//! the interface between the code 3dsrecomp generates and the programs that
//! run it. recomp.h is the C side and this is the same thing in Rust, which
//! a test holds to the header's layout. docs/interface.md describes it.

use std::ffi::{c_char, c_void, CStr};
#[cfg(feature = "load")]
use std::path::Path;
use std::path::PathBuf;

/// recomp.h, which the generated code includes.
pub const HEADER: &str = include_str!("../recomp.h");

/// the interface version, which code has to match to be run.
pub const ABI: u32 = 4;

/// the code generator's version, raised when the code it makes runs much
/// better or does more than before, which checking itself against memory did
/// at 2, and doing that much faster at 3. code of an older one still runs, and building it again brings the
/// improvements, which a host can suggest.
pub const GENERATION: u32 = 3;

/// why the code gave control back.
pub const EXIT_NONE: u32 = 0;
pub const EXIT_SVC: u32 = 1;
pub const EXIT_BUDGET: u32 = 2;
pub const EXIT_UNWIND: u32 = 3;

pub type Code = unsafe extern "C" fn(*mut Context);

/// where 3dsrecomp build installs libraries for hosts to find, one per
/// title, in the system's place for a program's data.
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

/// the file a title's library goes by, named after its title id, with the
/// system's extension for them, so, dll or dylib.
pub fn library_name(program_id: u64) -> String {
    format!("{program_id:016X}.{}", std::env::consts::DLL_EXTENSION)
}

/// the library installed for a title, if there is one.
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
    pub depth: u32,
    pub exclusive_address: u32,
    pub tls: u32,
    pub read_pages: *const *mut u8,
    pub write_pages: *const *mut u8,
    pub vfp: *mut u32,
    pub fpscr: *mut u32,
    pub host: *const Host,
    pub user: *mut c_void,
}

#[repr(C)]
pub struct Entry {
    pub address: u32,
    pub code: Code,
}

/// a module's code, whose entries are offsets from where it gets loaded.
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
        // SAFETY: the generated table holds string literals
        unsafe { CStr::from_ptr(self.name) }.to_str().unwrap_or_default()
    }

    pub fn entries(&self) -> &[Entry] {
        // SAFETY: the table lives as long as the code does
        unsafe { std::slice::from_raw_parts(self.entries, self.count as usize) }
    }
}

/// a piece of guest code, as addresses or offsets in a module, and the hash
/// of its bytes. a unit's pieces are in order and never overlap.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Piece {
    pub start: u32,
    pub end: u32,
    pub hash: u64,
}

/// a run of a unit's pieces, as indices.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Run {
    pub first: u32,
    pub end: u32,
}

/// a function's code, count runs from the unit's runs[first], and where it
/// starts.
#[repr(C)]
pub struct Origin {
    pub first: u32,
    pub count: u32,
    pub start: u32,
}

/// the code of the executable or a module, its functions, the function
/// each entry runs, and a flag per function the host sets when its code
/// changed.
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

/// an entry's owner when code written by hand runs it.
pub const NO_ORIGIN: u32 = u32::MAX;

/// the start a stale function gets, which nothing starts at.
pub const NO_START: u32 = u32::MAX;

/// the hash of the bytes a function was made from, 64-bit FNV-1a over its
/// spans one after another.
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
        // SAFETY: the generated table has piece_count pieces
        unsafe { std::slice::from_raw_parts(self.pieces, self.piece_count as usize) }
    }

    pub fn functions(&self) -> &[Origin] {
        if self.functions.is_null() {
            return &[];
        }
        // SAFETY: the generated table has count functions
        unsafe { std::slice::from_raw_parts(self.functions, self.count as usize) }
    }

    pub fn runs(&self) -> &[Run] {
        let count = self.functions().iter().map(|f| (f.first + f.count) as usize).max().unwrap_or(0);
        if count == 0 {
            return &[];
        }
        // SAFETY: the functions' runs are all in the table
        unsafe { std::slice::from_raw_parts(self.runs, count) }
    }

    /// whether the function that runs entry i is stale.
    fn owner_is_stale(&self, entry: usize) -> bool {
        // SAFETY: there is an owner for each of the unit's entries, and a
        // flag for each function
        if self.owners.is_null() {
            return false;
        }
        unsafe {
            let owner = *self.owners.add(entry);
            owner != NO_ORIGIN && *self.stale.add(owner as usize) != 0
        }
    }
}

/// the tables of code linked into the program itself rather than loaded
/// from a library, which is how a program 3dsrecomp port made runs.
#[derive(Debug, Clone, Copy)]
pub struct Linked {
    program_id: u64,
    abi: u32,
    entries: *const c_void,
    count: u32,
    modules: *const c_void,
    module_count: u32,
}

impl Linked {
    /// # Safety
    ///
    /// the pointers and counts have to be the recomp_ symbols of code that
    /// 3dsrecomp generated, linked into this program.
    pub unsafe fn new(
        program_id: u64,
        abi: u32,
        entries: *const c_void,
        count: u32,
        modules: *const c_void,
        module_count: u32,
    ) -> Linked {
        Linked { program_id, abi, entries, count, modules, module_count }
    }

    /// the title the code was recompiled from.
    pub fn program_id(&self) -> u64 {
        self.program_id
    }
}

// SAFETY: the tables live as long as the program and are read only, apart
// from the module bases, which only the thread running the code touches.
unsafe impl Send for Linked {}
unsafe impl Sync for Linked {}

/// code 3dsrecomp generated, from a library or linked in.
pub struct Library {
    entries: *const Entry,
    count: usize,
    modules: *const Module,
    module_count: usize,
    /// the modules placed somewhere, as base, size and index.
    placed: Vec<(u32, u32, usize)>,
    /// the code generator's version that made the code, see GENERATION.
    generation: u32,
    /// what the executable's functions and then each module's were made
    /// from, none for code of the generations before.
    origins: *const Origins,
    /// the library the tables are in, none when they are linked in.
    #[cfg(feature = "load")]
    _library: Option<libloading::Library>,
}

// SAFETY: as for Linked
unsafe impl Send for Library {}

impl Library {
    /// a library 3dsrecomp build made.
    #[cfg(feature = "load")]
    pub fn open(path: &Path) -> Result<Library, String> {
        // SAFETY: a library 3dsrecomp built, whose symbols have the types
        // recomp.h gives them, which the version check makes sure of
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
            };
            let mut code = Library::linked(&linked)?;
            // libraries made before it said have none
            code.generation = symbol(b"recomp_generation").map_or(0, |generation| *(generation as *const u32));
            // generation 2 laid the table out differently, nothing was made
            // with it but tests
            if code.generation >= 3 {
                code.origins = symbol(b"recomp_origins").map_or(std::ptr::null(), |origins| origins as *const Origins);
            }
            code._library = Some(library);
            Ok(code)
        }
    }

    /// the code linked into the program.
    pub fn linked(linked: &Linked) -> Result<Library, String> {
        if linked.abi != ABI {
            return Err(format!("it was built for version {} of the interface, this is {ABI}", linked.abi));
        }
        Ok(Library {
            entries: linked.entries as *const Entry,
            count: linked.count as usize,
            modules: linked.modules as *const Module,
            module_count: linked.module_count as usize,
            placed: Vec::new(),
            // code linked in was made along with the program
            generation: GENERATION,
            // and is not checked against what the program has in memory
            origins: std::ptr::null(),
            #[cfg(feature = "load")]
            _library: None,
        })
    }

    /// the version of the code generator that made the code, 0 for a
    /// library made before libraries said. lower than GENERATION means
    /// building it again gives faster code.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn entries(&self) -> &[Entry] {
        // SAFETY: the table lives as long as the code does
        unsafe { std::slice::from_raw_parts(self.entries, self.count) }
    }

    pub fn modules(&self) -> &[Module] {
        // SAFETY: as above
        unsafe { std::slice::from_raw_parts(self.modules, self.module_count) }
    }

    /// how many functions and modules there is code for.
    pub fn describe(&self) -> String {
        format!("{} entry points, {} modules", self.count, self.module_count)
    }

    /// the code that can run from address, bit 0 set for Thumb, in the
    /// executable or in a module that is placed. none for a function whose
    /// code changed since it was made.
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

    /// what the functions of unit were made from, the executable's for 0
    /// and module i's for i + 1, when the code says.
    pub fn origins(&self, unit: usize) -> Option<&Origins> {
        if self.origins.is_null() || unit > self.module_count {
            return None;
        }
        // SAFETY: the code has a table for the executable and each module
        Some(unsafe { &*self.origins.add(unit) })
    }

    /// checks the functions of unit against the code in memory, which read
    /// fills in from an address, the unit's offsets added to base. those
    /// whose bytes changed are marked stale and run no more, and how many
    /// there are comes back. each piece of code is read and hashed once.
    pub fn check(&mut self, unit: usize, base: u32, mut read: impl FnMut(u32, &mut [u8])) -> usize {
        let Some(origins) = self.origins(unit) else { return 0 };
        let pieces = origins.pieces();
        let (Some(first), Some(last)) = (pieces.first(), pieces.last()) else { return 0 };
        let mut code = vec![0; (last.end - first.start) as usize];
        read(base.wrapping_add(first.start), &mut code);
        // how many of the pieces before each one changed
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
            // SAFETY: the flags and starts are the code's own, one of each
            // per function, which only the thread running it reads
            unsafe {
                *origins.stale.add(index) = changed as u8;
                *origins.starts.add(index) = if changed { NO_START } else { function.start };
            }
            stale += changed as usize;
        }
        stale
    }

    /// the module called name.
    pub fn module_index(&self, name: &str) -> Option<usize> {
        self.modules().iter().position(|module| module.name() == name)
    }

    /// tells the code of module index where it was loaded, zero when it goes
    /// away.
    pub fn place(&mut self, index: usize, base: u32) {
        let module = &self.modules()[index];
        // SAFETY: base points at the module's variable beside the code, which
        // the code only reads on entry
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

    /// prints the header's layout, the way the lines below expect it.
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
    AT(Context, user);
    SIZE(Host);
    AT(Host, read8); AT(Host, read16); AT(Host, read32); AT(Host, write8);
    AT(Host, write16); AT(Host, write32); AT(Host, interpret); AT(Host, lookup);
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
    printf("RECOMP_ABI %d\n", RECOMP_ABI);
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

    /// a changed byte marks the functions whose code holds it, and only
    /// those, each piece hashed once whichever functions share it.
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
        // one function holds all the code, one the middle piece, one the last
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
            generation: GENERATION,
            origins: &origins,
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

    /// recomp.h and the structs here describe the same memory, which a C
    /// program built from the header reports on.
    #[test]
    fn the_header_has_the_same_layout() {
        let dir = std::env::temp_dir().join(format!("recomp-abi-layout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("recomp.h"), HEADER).unwrap();
        std::fs::write(dir.join("layout.c"), LAYOUT).unwrap();
        // CC, else the first compiler there is, which on Windows is rarely cc
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
            read_pages, write_pages, vfp, fpscr, host, user);
        at!(lines, Host, read8, read16, read32, write8, write16, write32, interpret, lookup);
        at!(lines, Entry, address, code);
        at!(lines, Module, name, base, size, count, entries);
        at!(lines, Piece, start, end, hash);
        at!(lines, Run, first, end);
        at!(lines, Origin, first, count, start);
        at!(lines, Origins, count, piece_count, pieces, functions, runs, owners, stale, starts);
        lines.push(format!("NO_ORIGIN {NO_ORIGIN}"));
        lines.push(format!("NO_START {NO_START}"));
        lines.push(format!("RECOMP_ABI {ABI}"));
        for (name, value) in
            [("EXIT_NONE", EXIT_NONE), ("EXIT_SVC", EXIT_SVC), ("EXIT_BUDGET", EXIT_BUDGET), ("EXIT_UNWIND", EXIT_UNWIND)]
        {
            lines.push(format!("{name} {value}"));
        }
        assert_eq!(header, lines);
    }
}
