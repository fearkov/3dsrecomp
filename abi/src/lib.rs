//! the contract between the code 3dsrecomp spits out and the programs running it
//! recomp.h is the C side, this is the Rust twin (a test keeps their layouts in sync), docs/interface.md has the details

use std::ffi::{c_char, c_void, CStr};
#[cfg(feature = "load")]
use std::path::Path;
use std::path::PathBuf;

/// recomp.h, the generated code includes it
pub const HEADER: &str = include_str!("../recomp.h");

/// interface version, code has to match it to run
pub const ABI: u32 = 8;

/// oldest version code can be made for and still run, v4 left every svc to the host's loop and never calls Host::svc
pub const OLDEST_ABI: u32 = 4;

/// codegen version, bumped when its code runs way better or does more
/// 2 checked itself vs memory, 3 did that way faster, 4 ran svcs w/o leaving the code
/// 5 divided on the host, 6 answers the clock and a mutex itself
/// older code still runs, rebuilding gets the goodies, hosts can nag about it
pub const GENERATION: u32 = 6;

/// why the code handed control back
pub const EXIT_NONE: u32 = 0;
pub const EXIT_SVC: u32 = 1;
pub const EXIT_BUDGET: u32 = 2;
pub const EXIT_UNWIND: u32 = 3;

/// runs the guest from r15, gives back where it went on return (the value written to pc) or STOPPED when the host takes over
/// hosts go by exit and the context, never by the return value, pre v6 code doesn't give one
pub type Code = unsafe extern "C" fn(*mut Context) -> u32;

/// what code returns when it stopped for the host
pub const STOPPED: u32 = u32::MAX;

/// how much C stack the code gets below where the host enters it
/// way more than 2048 guest calls, as deep as older versions went
pub const STACK: usize = 1 << 20;

/// where `3dsrecomp build` drops libs for hosts to find, one per title, in the system's app data dir
pub fn library_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    let dir = if cfg!(windows) {
        var("APPDATA")
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|home| home.join("Library/Application Support"))
    } else {
        var("XDG_DATA_HOME").or_else(|| var("HOME").map(|home| home.join(".local/share")))
    };
    dir.map(|dir| dir.join("3dsrecomp"))
}

/// a title's lib file name, its title id plus the system's extension (so, dll or dylib)
pub fn library_name(program_id: u64) -> String {
    format!("{program_id:016X}.{}", std::env::consts::DLL_EXTENSION)
}

/// the lib installed for a title, if any
pub fn installed(program_id: u64) -> Option<PathBuf> {
    let path = library_dir()?.join(library_name(program_id));
    path.is_file().then_some(path)
}

#[repr(C)]
pub struct Host {
    pub read8: unsafe extern "C" fn(*mut Context, u32) -> u8,
    pub read16: unsafe extern "C" fn(*mut Context, u32) -> u16,
    pub read32: unsafe extern "C" fn(*mut Context, u32) -> u32,
    pub write8: unsafe extern "C" fn(*mut Context, u32, u8),
    pub write16: unsafe extern "C" fn(*mut Context, u32, u16),
    pub write32: unsafe extern "C" fn(*mut Context, u32, u32),
    pub interpret: unsafe extern "C" fn(*mut Context, u32, u32),
    pub lookup: unsafe extern "C" fn(*mut Context, u32) -> Option<Code>,
    pub svc: unsafe extern "C" fn(*mut Context, u32),
}

#[repr(C)]
pub struct Context {
    pub r: [u32; 16],
    pub n: u8,
    pub z: u8,
    pub c: u8,
    pub v: u8,
    pub q: u8,
    pub thumb: u8,
    pub ge: u8,
    pub exclusive: u8,
    pub budget: i32,
    pub exit: u32,
    pub svc: u32,
    /// what pre v6 code counts calls in, 0 b4 each call
    pub depth: u32,
    pub exclusive_address: u32,
    pub tls: u32,
    pub read_pages: *const *mut u8,
    pub write_pages: *const *mut u8,
    pub vfp: *mut u32,
    pub fpscr: *mut u32,
    pub host: *const Host,
    pub user: *mut c_void,
    /// lowest addr the code's C stack may reach, see stack_limit
    pub stack_limit: usize,
    /// from v7 the code answers GetSystemTick itself, tick_end minus the budget, costing tick_cost of it
    /// only at tick_at (addr after the svc, bit 0 for Thumb) while budget > tick_floor
    /// counted in ticks, last one in tick_last, NO_TICKS sends them all thru Host::svc
    pub tick_end: u64,
    pub tick_last: u64,
    pub tick_floor: i32,
    pub tick_cost: i32,
    pub tick_at: u32,
    pub ticks: u32,
    /// from v8 the code also takes and drops the one mutex the host lends it
    /// WaitSynchronizationN on held alone at wait_at takes it once more, ReleaseMutex on held at release_at drops it once
    /// holding counts how many times the thread has it, all while budget > held_floor (NOTHING_HELD turns it off)
    /// each svc the code answers itself (ticks too) logs the addr after it in trail
    /// latest at (done minus 1) mod TRAIL, done counts them, its tick b4 the cost goes in tick_last
    pub wait_at: u32,
    pub release_at: u32,
    pub held: u32,
    pub holding: u32,
    pub held_floor: i32,
    pub done: u32,
    pub trail: [u32; TRAIL],
}

/// a tick_at where no code answers GetSystemTick
pub const NO_TICKS: u32 = 0;

/// a held_floor that makes the code answer no wait or release itself
pub const NOTHING_HELD: i32 = i32::MAX;

/// how many self answered svc addrs the code keeps
pub const TRAIL: usize = 64;

/// a stack_limit giving the code STACK bytes of C stack below the caller's frame, set it b4 each call
#[inline(always)]
pub fn stack_limit() -> usize {
    let here = 0u8;
    (std::ptr::addr_of!(here) as usize).saturating_sub(STACK)
}

#[repr(C)]
pub struct Entry {
    pub address: u32,
    pub code: Code,
}

/// a module's code, entries are offsets from its load addr
#[repr(C)]
pub struct Module {
    name: *const c_char,
    base: *mut u32,
    pub size: u32,
    count: u32,
    entries: *const Entry,
}

impl Module {
    pub fn name(&self) -> &str {
        // safe bc the generated table only holds string literals
        unsafe { CStr::from_ptr(self.name) }.to_str().unwrap_or_default()
    }

    pub fn entries(&self) -> &[Entry] {
        // safe bc the table lives as long as the code
        unsafe { std::slice::from_raw_parts(self.entries, self.count as usize) }
    }
}

/// a chunk of guest code (addrs or module offsets) plus its bytes' hash, a unit's pieces are in order w/o overlaps
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Piece {
    pub start: u32,
    pub end: u32,
    pub hash: u64,
}

/// a run of a unit's pieces, as indices
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Run {
    pub first: u32,
    pub end: u32,
}

/// a func's code, count runs from the unit's runs[first], plus where it starts
#[repr(C)]
pub struct Origin {
    pub first: u32,
    pub count: u32,
    pub start: u32,
}

/// code of the exe or a module, its funcs, the func each entry runs, and a per func flag the host sets when its code changed
#[repr(C)]
pub struct Origins {
    count: u32,
    piece_count: u32,
    pieces: *const Piece,
    functions: *const Origin,
    runs: *const Run,
    owners: *const u32,
    stale: *mut u8,
    starts: *mut u32,
}

/// an entry's owner when handwritten code runs it
pub const NO_ORIGIN: u32 = u32::MAX;

/// the start a stale func gets, nothing starts there
pub const NO_START: u32 = u32::MAX;

/// hash of the bytes a func came from, 64 bit FNV1a over its spans back to back
#[derive(Debug, Clone, Copy)]
pub struct CodeHash(u64);

impl Default for CodeHash {
    fn default() -> Self {
        CodeHash(0xCBF2_9CE4_8422_2325)
    }
}

impl CodeHash {
    pub fn add(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 ^ byte as u64).wrapping_mul(0x0100_0000_01B3);
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Origins {
    pub fn pieces(&self) -> &[Piece] {
        if self.pieces.is_null() {
            return &[];
        }
        // safe bc the generated table has piece_count pieces
        unsafe { std::slice::from_raw_parts(self.pieces, self.piece_count as usize) }
    }

    pub fn functions(&self) -> &[Origin] {
        if self.functions.is_null() {
            return &[];
        }
        // safe bc the generated table has count funcs
        unsafe { std::slice::from_raw_parts(self.functions, self.count as usize) }
    }

    pub fn runs(&self) -> &[Run] {
        let count = self.functions().iter().map(|f| (f.first + f.count) as usize).max().unwrap_or(0);
        if count == 0 {
            return &[];
        }
        // safe bc the funcs' runs are all in the table
        unsafe { std::slice::from_raw_parts(self.runs, count) }
    }

    /// is the func running entry i stale
    fn owner_is_stale(&self, entry: usize) -> bool {
        // safe bc every entry of the unit has an owner and every func a flag
        if self.owners.is_null() {
            return false;
        }
        unsafe {
            let owner = *self.owners.add(entry);
            owner != NO_ORIGIN && *self.stale.add(owner as usize) != 0
        }
    }
}

/// tables of code linked into the program instead of loaded from a lib, that's how `3dsrecomp port` programs run
#[derive(Debug, Clone, Copy)]
pub struct Linked {
    program_id: u64,
    abi: u32,
    entries: *const c_void,
    count: u32,
    modules: *const c_void,
    module_count: u32,
    /// codegen version and its recomp_origins (what the funcs came from), none if the program doesn't say
    generation: u32,
    origins: *const c_void,
}

impl Linked {
    /// # Safety
    ///
    /// the ptrs and counts must be the recomp_ symbols of code 3dsrecomp generated and linked into this program
    pub unsafe fn new(
        program_id: u64,
        abi: u32,
        entries: *const c_void,
        count: u32,
        modules: *const c_void,
        module_count: u32,
    ) -> Linked {
        Linked { program_id, abi, entries, count, modules, module_count, generation: 0, origins: std::ptr::null() }
    }

    /// same code plus what its funcs came from, so it gets checked against memory like a lib
    /// and a func a mod or another game version changed stops running
    ///
    /// # Safety
    ///
    /// generation and origins must be recomp_generation and recomp_origins of the same code
    pub unsafe fn with_origins(self, generation: u32, origins: *const c_void) -> Linked {
        Linked { generation, origins, ..self }
    }

    /// the title the code got recompiled from
    pub fn program_id(&self) -> u64 {
        self.program_id
    }
}

// safe bc the tables live as long as the program and are readonly
// except the module bases, which only the thread running the code touches
unsafe impl Send for Linked {}
unsafe impl Sync for Linked {}

/// code 3dsrecomp generated, from a lib or linked in
pub struct Library {
    entries: *const Entry,
    count: usize,
    modules: *const Module,
    module_count: usize,
    /// modules placed somewhere, as base, size and index
    placed: Vec<(u32, u32, usize)>,
    /// interface version the code was made for, see ABI
    abi: u32,
    /// codegen version that made the code, see GENERATION
    generation: u32,
    /// what the exe's funcs and then each module's came from, none for older generations
    origins: *const Origins,
    /// recomp_natives, says if the C lib funcs the code runs on the host do, null when there are none
    natives: *mut u8,
    /// the lib the tables live in, none when linked in
    #[cfg(feature = "load")]
    _library: Option<libloading::Library>,
}

// safe for the same reasons as Linked
unsafe impl Send for Library {}

impl Library {
    /// a lib `3dsrecomp build` made
    #[cfg(feature = "load")]
    pub fn open(path: &Path) -> Result<Library, String> {
        // safe bc 3dsrecomp built it and its symbols have recomp.h's types, the version check makes sure
        unsafe {
            let library = libloading::Library::new(path).map_err(|e| e.to_string())?;
            let symbol = |name: &[u8]| -> Result<*const c_void, String> {
                library.get::<*const c_void>(name).map(|s| *s).map_err(|e| e.to_string())
            };
            let linked = Linked {
                program_id: 0,
                abi: *(symbol(b"recomp_abi")? as *const u32),
                entries: symbol(b"recomp_entries")?,
                count: *(symbol(b"recomp_entry_count")? as *const u32),
                modules: symbol(b"recomp_modules")?,
                module_count: *(symbol(b"recomp_module_count")? as *const u32),
                generation: 0,
                origins: std::ptr::null(),
            };
            let mut code = Library::linked(&linked)?;
            // libs made b4 it said have none
            code.generation = symbol(b"recomp_generation").map_or(0, |generation| *(generation as *const u32));
            // generation 2 laid the table out differently, only tests ever used it
            if code.generation >= 3 {
                code.origins = symbol(b"recomp_origins").map_or(std::ptr::null(), |origins| origins as *const Origins);
            }
            code.natives = symbol(b"recomp_natives").map_or(std::ptr::null_mut(), |natives| natives as *mut u8);
            code._library = Some(library);
            Ok(code)
        }
    }

    /// the code linked into the program
    pub fn linked(linked: &Linked) -> Result<Library, String> {
        if !(OLDEST_ABI..=ABI).contains(&linked.abi) {
            return Err(format!("it was built for version {} of the interface, this is {ABI}", linked.abi));
        }
        Ok(Library {
            entries: linked.entries as *const Entry,
            count: linked.count as usize,
            modules: linked.modules as *const Module,
            module_count: linked.module_count as usize,
            placed: Vec::new(),
            abi: linked.abi,
            // linked code was made along w/ the program
            generation: GENERATION,
            // and gets checked against memory when the program says what it came from (gen 3 and up can), like a lib
            origins: if linked.generation >= 3 { linked.origins as *const Origins } else { std::ptr::null() },
            natives: std::ptr::null_mut(),
            #[cfg(feature = "load")]
            _library: None,
        })
    }

    /// interface version the code was made for, OLDEST_ABI to ABI, v4 code never calls Host::svc
    pub fn abi(&self) -> u32 {
        self.abi
    }

    /// switches the C lib funcs the code runs on the host (natives) back to the title's own code when off
    /// says if the code has any, they start on
    pub fn set_natives(&mut self, on: bool) -> bool {
        if self.natives.is_null() {
            return false;
        }
        // safe bc recomp_natives is the code's own byte, only the thread running it reads it
        unsafe { *self.natives = on as u8 };
        true
    }

    /// codegen version that made the code, 0 for libs older than that
    /// below GENERATION means a rebuild gives faster code
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn entries(&self) -> &[Entry] {
        // safe bc the table lives as long as the code
        unsafe { std::slice::from_raw_parts(self.entries, self.count) }
    }

    pub fn modules(&self) -> &[Module] {
        // safe for the same reason
        unsafe { std::slice::from_raw_parts(self.modules, self.module_count) }
    }

    /// how many funcs and modules there's code for
    pub fn describe(&self) -> String {
        format!("{} entry points, {} modules", self.count, self.module_count)
    }

    /// code that can run from address (bit 0 for Thumb) in the exe or a placed module
    /// none for a func whose code changed since it was made
    pub fn lookup(&self, address: u32) -> Option<Code> {
        let find = |entries: &[Entry], unit: usize, address: u32| {
            let i = entries.binary_search_by_key(&address, |entry| entry.address).ok()?;
            let stale = self.origins(unit).is_some_and(|origins| origins.owner_is_stale(i));
            (!stale).then_some(entries[i].code)
        };
        find(self.entries(), 0, address).or_else(|| {
            let &(base, _, index) = self.placed.iter().find(|&&(base, size, _)| address.wrapping_sub(base) < size)?;
            find(self.modules()[index].entries(), index + 1, address - base)
        })
    }

    /// what unit's funcs came from, 0 is the exe, i + 1 is module i, when the code says
    pub fn origins(&self, unit: usize) -> Option<&Origins> {
        if self.origins.is_null() || unit > self.module_count {
            return None;
        }
        // safe bc the code has a table for the exe and each module
        Some(unsafe { &*self.origins.add(unit) })
    }

    /// checks unit's funcs against memory (read fills it in from an addr, offsets plus base)
    /// funcs w/ changed bytes go stale and stop running, returns how many, each piece read and hashed once
    pub fn check(&mut self, unit: usize, base: u32, mut read: impl FnMut(u32, &mut [u8])) -> usize {
        let Some(origins) = self.origins(unit) else { return 0 };
        let pieces = origins.pieces();
        let (Some(first), Some(last)) = (pieces.first(), pieces.last()) else { return 0 };
        let mut code = vec![0; (last.end - first.start) as usize];
        read(base.wrapping_add(first.start), &mut code);
        // how many pieces b4 each one changed
        let mut changed_before = Vec::with_capacity(pieces.len() + 1);
        changed_before.push(0u32);
        for piece in pieces {
            let mut hash = CodeHash::default();
            hash.add(&code[(piece.start - first.start) as usize..(piece.end - first.start) as usize]);
            let changed = (hash.value() != piece.hash) as u32;
            changed_before.push(changed_before.last().unwrap() + changed);
        }
        let runs = origins.runs();
        let mut stale = 0;
        for (index, function) in origins.functions().iter().enumerate() {
            let runs = &runs[function.first as usize..(function.first + function.count) as usize];
            let changed = runs.iter().any(|run| changed_before[run.end as usize] > changed_before[run.first as usize]);
            // safe bc the flags and starts are the code's own, one each per func, only the running thread reads them
            unsafe {
                *origins.stale.add(index) = changed as u8;
                *origins.starts.add(index) = if changed { NO_START } else { function.start };
            }
            stale += changed as usize;
        }
        stale
    }

    /// marks unit's func starting at start stale as if its code changed, so the interpreter runs it
    /// for hosts that need to watch it step by step, start is a module offset like its pieces
    /// a later check undoes it, returns whether there was one
    pub fn interpret(&mut self, unit: usize, start: u32) -> bool {
        let Some(origins) = self.origins(unit) else { return false };
        let Some(index) = origins.functions().iter().position(|function| function.start == start) else { return false };
        // safe, same as check, a flag and a start per func
        unsafe {
            *origins.stale.add(index) = 1;
            *origins.starts.add(index) = NO_START;
        }
        true
    }

    /// marks every func of unit whose code covers address stale so the interpreter runs whatever reaches it
    /// for hosts that must stop there, code can belong to several funcs and each would run it
    /// address is a module offset, a later check undoes it like interpret, returns how many
    pub fn interpret_at(&mut self, unit: usize, address: u32) -> usize {
        let Some(origins) = self.origins(unit) else { return 0 };
        let pieces = origins.pieces();
        let runs = origins.runs();
        let mut marked = 0;
        for (index, function) in origins.functions().iter().enumerate() {
            let runs = &runs[function.first as usize..(function.first + function.count) as usize];
            let takes_in = runs.iter().any(|run| {
                pieces[run.first as usize..run.end as usize].iter().any(|piece| (piece.start..piece.end).contains(&address))
            });
            if takes_in {
                // safe, same as check, a flag and a start per func
                unsafe {
                    *origins.stale.add(index) = 1;
                    *origins.starts.add(index) = NO_START;
                }
                marked += 1;
            }
        }
        marked
    }

    /// the module called name
    pub fn module_index(&self, name: &str) -> Option<usize> {
        self.modules().iter().position(|module| module.name() == name)
    }

    /// tells module index's code where it got loaded, 0 when it goes away
    pub fn place(&mut self, index: usize, base: u32) {
        let module = &self.modules()[index];
        // safe bc base points at the module's var next to the code, which the code only reads on entry
        unsafe { *module.base = base };
        let size = module.size;
        self.placed.retain(|&(_, _, i)| i != index);
        if base != 0 {
            self.placed.push((base, size, index));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};
    use std::process::Command;

    /// prints the header's layout the way the lines below expect
    const LAYOUT: &str = r#"
#include <stddef.h>
#include <stdio.h>
#include "recomp.h"

#define SIZE(type) printf(#type " %zu\n", sizeof(type))
#define AT(type, field) printf(#type "." #field " %zu\n", offsetof(type, field))

int main(void) {
    SIZE(Context);
    AT(Context, r); AT(Context, n); AT(Context, z); AT(Context, c); AT(Context, v);
    AT(Context, q); AT(Context, thumb); AT(Context, ge); AT(Context, exclusive);
    AT(Context, budget); AT(Context, exit); AT(Context, svc); AT(Context, depth);
    AT(Context, exclusive_address); AT(Context, tls); AT(Context, read_pages);
    AT(Context, write_pages); AT(Context, vfp); AT(Context, fpscr); AT(Context, host);
    AT(Context, user); AT(Context, stack_limit); AT(Context, tick_end); AT(Context, tick_last);
    AT(Context, tick_floor); AT(Context, tick_cost); AT(Context, tick_at); AT(Context, ticks);
    AT(Context, wait_at); AT(Context, release_at); AT(Context, held); AT(Context, holding);
    AT(Context, held_floor); AT(Context, done); AT(Context, trail);
    SIZE(Host);
    AT(Host, read8); AT(Host, read16); AT(Host, read32); AT(Host, write8);
    AT(Host, write16); AT(Host, write32); AT(Host, interpret); AT(Host, lookup); AT(Host, svc);
    SIZE(Entry);
    AT(Entry, address); AT(Entry, code);
    SIZE(Module);
    AT(Module, name); AT(Module, base); AT(Module, size); AT(Module, count); AT(Module, entries);
    SIZE(Piece);
    AT(Piece, start); AT(Piece, end); AT(Piece, hash);
    SIZE(Run);
    AT(Run, first); AT(Run, end);
    SIZE(Origin);
    AT(Origin, first); AT(Origin, count); AT(Origin, start);
    SIZE(Origins);
    AT(Origins, count); AT(Origins, piece_count); AT(Origins, pieces); AT(Origins, functions); AT(Origins, runs);
    AT(Origins, owners); AT(Origins, stale); AT(Origins, starts);
    printf("NO_ORIGIN %u\nNO_START %u\n", NO_ORIGIN, NO_START);
    printf("RECOMP_ABI %d\nRECOMP_STOPPED %u\nRECOMP_TRAIL %d\n", RECOMP_ABI, RECOMP_STOPPED, RECOMP_TRAIL);
    printf("EXIT_NONE %d\nEXIT_SVC %d\nEXIT_BUDGET %d\nEXIT_UNWIND %d\n", EXIT_NONE, EXIT_SVC, EXIT_BUDGET, EXIT_UNWIND);
    return 0;
}
"#;

    macro_rules! at {
        ($lines:ident, $type:ident, $($field:ident),*) => {
            $lines.push(format!("{} {}", stringify!($type), size_of::<$type>()));
            $($lines.push(format!("{}.{} {}", stringify!($type), stringify!($field), offset_of!($type, $field)));)*
        };
    }

    /// a changed byte marks the funcs holding it and only those, each piece hashed once however many funcs share it
    #[test]
    fn a_changed_byte_marks_the_functions_holding_it() {
        let mut memory = vec![0u8; 0x40];
        for (i, byte) in memory.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let hash = |memory: &[u8], start: u32, end: u32| {
            let mut hash = CodeHash::default();
            hash.add(&memory[(start - 0x10) as usize..(end - 0x10) as usize]);
            hash.value()
        };
        let pieces = [(0x10, 0x20), (0x20, 0x28), (0x28, 0x30)]
            .map(|(start, end)| Piece { start, end, hash: hash(&memory, start, end) });
        // one func holds all the code, one the middle piece, one the last
        let runs = [Run { first: 0, end: 3 }, Run { first: 1, end: 2 }, Run { first: 2, end: 3 }];
        let functions = [Origin { first: 0, count: 1, start: 0x10 }, Origin { first: 1, count: 1, start: 0x20 }, Origin { first: 2, count: 1, start: 0x28 }];
        let owners = [0u32, 1, 2];
        let mut stale = [0u8; 3];
        let mut starts = [0x10u32, 0x20, 0x28];
        let origins = Origins {
            count: 3,
            piece_count: 3,
            pieces: pieces.as_ptr(),
            functions: functions.as_ptr(),
            runs: runs.as_ptr(),
            owners: owners.as_ptr(),
            stale: stale.as_mut_ptr(),
            starts: starts.as_mut_ptr(),
        };
        let mut library = Library {
            entries: std::ptr::null(),
            count: 0,
            modules: std::ptr::null(),
            module_count: 0,
            placed: Vec::new(),
            abi: ABI,
            generation: GENERATION,
            origins: &origins,
            natives: std::ptr::null_mut(),
            #[cfg(feature = "load")]
            _library: None,
        };
        let read = |memory: &[u8]| {
            let memory = memory.to_vec();
            move |address: u32, out: &mut [u8]| out.copy_from_slice(&memory[(address - 0x10) as usize..][..out.len()])
        };
        assert_eq!(library.check(0, 0, read(&memory)), 0);
        memory[0x2A - 0x10] ^= 1;
        assert_eq!(library.check(0, 0, read(&memory)), 2);
        assert_eq!(stale, [1, 0, 1]);
        assert_eq!(starts, [NO_START, 0x20, NO_START]);
        assert!(origins.owner_is_stale(0) && !origins.owner_is_stale(1));
    }

    /// a host has the interpreter run the func starting at an addr, or every func covering one, till a check undoes the marks
    #[test]
    fn a_host_marks_functions_for_the_interpreter() {
        let pieces = [(0x10, 0x20), (0x20, 0x28), (0x28, 0x30)].map(|(start, end)| Piece { start, end, hash: 0 });
        // one func holds all the code, one the middle piece, one the last
        let runs = [Run { first: 0, end: 3 }, Run { first: 1, end: 2 }, Run { first: 2, end: 3 }];
        let functions = [Origin { first: 0, count: 1, start: 0x10 }, Origin { first: 1, count: 1, start: 0x20 }, Origin { first: 2, count: 1, start: 0x28 }];
        let owners = [0u32, 1, 2];
        let mut stale = [0u8; 3];
        let mut starts = [0x10u32, 0x20, 0x28];
        let origins = Origins {
            count: 3,
            piece_count: 3,
            pieces: pieces.as_ptr(),
            functions: functions.as_ptr(),
            runs: runs.as_ptr(),
            owners: owners.as_ptr(),
            stale: stale.as_mut_ptr(),
            starts: starts.as_mut_ptr(),
        };
        let mut library = Library {
            entries: std::ptr::null(),
            count: 0,
            modules: std::ptr::null(),
            module_count: 0,
            placed: Vec::new(),
            abi: ABI,
            generation: GENERATION,
            origins: &origins,
            natives: std::ptr::null_mut(),
            #[cfg(feature = "load")]
            _library: None,
        };
        assert!(library.interpret(0, 0x20));
        assert!(!library.interpret(0, 0x24), "nothing starts there");
        assert_eq!((stale, starts), ([0, 1, 0], [0x10, NO_START, 0x28]));
        // the last piece belongs to the first func and the last one
        assert_eq!(library.interpret_at(0, 0x2A), 2);
        assert_eq!((stale, starts), ([1, 1, 1], [NO_START; 3]));
        // the code as made, every piece hashing to what it says
        let mut hashed = pieces;
        for piece in hashed.iter_mut() {
            let mut hash = CodeHash::default();
            hash.add(&vec![0; (piece.end - piece.start) as usize]);
            piece.hash = hash.value();
        }
        let origins = Origins { pieces: hashed.as_ptr(), ..origins };
        library.origins = &origins;
        assert_eq!(library.check(0, 0, |_, out| out.fill(0)), 0);
        assert_eq!((stale, starts), ([0; 3], [0x10, 0x20, 0x28]));
    }

    /// linked code gets checked vs memory when the program says what it came from
    /// not when it doesn't, or says it in a pre gen 3 layout
    #[test]
    fn linked_code_is_checked_when_it_says_what_it_was_made_from() {
        let memory: Vec<u8> = (0..0x10u8).collect();
        let mut hash = CodeHash::default();
        hash.add(&memory);
        let pieces = [Piece { start: 0, end: 0x10, hash: hash.value() }];
        let runs = [Run { first: 0, end: 1 }];
        let functions = [Origin { first: 0, count: 1, start: 0 }];
        let owners = [0u32];
        let mut stale = [0u8; 1];
        let mut starts = [0u32];
        let origins = Origins {
            count: 1,
            piece_count: 1,
            pieces: pieces.as_ptr(),
            functions: functions.as_ptr(),
            runs: runs.as_ptr(),
            owners: owners.as_ptr(),
            stale: stale.as_mut_ptr(),
            starts: starts.as_mut_ptr(),
        };
        // safe bc the tables are empty and origins outlive the code
        let plain = unsafe { Linked::new(1, ABI, std::ptr::null(), 0, std::ptr::null(), 0) };
        let given = unsafe { plain.with_origins(GENERATION, &origins as *const Origins as *const c_void) };
        let older = unsafe { plain.with_origins(2, &origins as *const Origins as *const c_void) };
        assert!(Library::linked(&plain).unwrap().origins(0).is_none());
        assert!(Library::linked(&older).unwrap().origins(0).is_none());
        let mut library = Library::linked(&given).unwrap();
        let mut changed = memory.clone();
        changed[3] ^= 1;
        assert_eq!(library.check(0, 0, |address, out| out.copy_from_slice(&memory[address as usize..][..out.len()])), 0);
        assert_eq!(library.check(0, 0, |address, out| out.copy_from_slice(&changed[address as usize..][..out.len()])), 1);
        assert_eq!(stale, [1]);
        assert_eq!(starts, [NO_START]);
    }

    /// code for older versions runs down to the oldest (which leaves every svc to the host's loop), any other version doesn't
    #[test]
    fn code_runs_down_to_the_oldest_version() {
        // safe bc the tables are empty
        let made = |abi| unsafe { Linked::new(1, abi, std::ptr::null(), 0, std::ptr::null(), 0) };
        assert!(Library::linked(&made(ABI)).is_ok());
        assert!(Library::linked(&made(OLDEST_ABI)).is_ok());
        assert!(Library::linked(&made(OLDEST_ABI - 1)).is_err());
        assert!(Library::linked(&made(ABI + 1)).is_err());
    }

    /// recomp.h and these structs describe the same memory, a C program built from the header reports it
    #[test]
    fn the_header_has_the_same_layout() {
        let dir = std::env::temp_dir().join(format!("recomp-abi-layout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("recomp.h"), HEADER).unwrap();
        std::fs::write(dir.join("layout.c"), LAYOUT).unwrap();
        // CC, else the first compiler around, which on windows is rarely cc
        let compilers = std::env::var("CC").map_or_else(|_| vec!["cc".to_owned(), "gcc".to_owned(), "clang".to_owned()], |cc| vec![cc]);
        let math: &[&str] = if cfg!(unix) { &["-lm"] } else { &[] };
        let built = compilers.iter().any(|compiler| {
            Command::new(compiler)
                .args(["-w", "-o", "layout", "layout.c"])
                .args(math)
                .current_dir(&dir)
                .status()
                .is_ok_and(|status| status.success())
        });
        if !built {
            eprintln!("no C compiler to build the header with, its layout went unchecked");
            return;
        }
        let output = Command::new(dir.join("layout")).output().unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let header: Vec<String> = String::from_utf8(output.stdout).unwrap().lines().map(str::to_owned).collect();

        let mut lines = Vec::new();
        at!(lines, Context, r, n, z, c, v, q, thumb, ge, exclusive, budget, exit, svc, depth, exclusive_address, tls,
            read_pages, write_pages, vfp, fpscr, host, user, stack_limit, tick_end, tick_last, tick_floor, tick_cost, tick_at, ticks,
            wait_at, release_at, held, holding, held_floor, done, trail);
        at!(lines, Host, read8, read16, read32, write8, write16, write32, interpret, lookup, svc);
        at!(lines, Entry, address, code);
        at!(lines, Module, name, base, size, count, entries);
        at!(lines, Piece, start, end, hash);
        at!(lines, Run, first, end);
        at!(lines, Origin, first, count, start);
        at!(lines, Origins, count, piece_count, pieces, functions, runs, owners, stale, starts);
        lines.push(format!("NO_ORIGIN {NO_ORIGIN}"));
        lines.push(format!("NO_START {NO_START}"));
        lines.push(format!("RECOMP_ABI {ABI}"));
        lines.push(format!("RECOMP_STOPPED {STOPPED}"));
        lines.push(format!("RECOMP_TRAIL {TRAIL}"));
        for (name, value) in
            [("EXIT_NONE", EXIT_NONE), ("EXIT_SVC", EXIT_SVC), ("EXIT_BUDGET", EXIT_BUDGET), ("EXIT_UNWIND", EXIT_UNWIND)]
        {
            lines.push(format!("{name} {value}"));
        }
        assert_eq!(header, lines);
    }
}
