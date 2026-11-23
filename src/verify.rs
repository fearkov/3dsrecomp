//! checking recompiled code against the interpreter. both run a function
//! from the same made up state over their own copy of the title's memory,
//! and anything that differs afterwards is a bug in one of them.

use std::ffi::c_void;
use std::ptr::null_mut;

use zakuro_cpu::{Bus, Cpu, Exit};

use crate::abi::{self, Code, Context, Host, Library};

const PAGE_SIZE: usize = 0x1000;
/// the return address functions are called with, which nothing maps.
const RETURN: u32 = 0xFFFF_FFF0;
const STACK_TOP: u32 = 0x1000_0000;
const STACK_SIZE: u32 = 0x4_0000;
const HEAP: u32 = 0x0800_0000;
const HEAP_SIZE: u32 = 0x4_0000;
const TLS: u32 = 0x1FF8_2000;
/// instructions a run may take before it counts as stuck.
const LIMIT: i32 = 200_000;

/// where the harness loads the module it checks.
pub const MODULE_BASE: u32 = 0x0A00_0000;
/// what a module's imports lead to, a function returning zero.
pub const IMPORT_STUB: u32 = 0x0B00_0000;

#[derive(Clone)]
pub struct Region {
    pub base: u32,
    pub bytes: Vec<u8>,
    pub writable: bool,
}

/// the guest's 4 GiB in the host's, plus the 64 KiB past them recomp.h
/// asks for, which the recompiled code reaches at base plus the address.
/// what the title has is committed and the rest only reserved. an access
/// there faults, and the handler commits the page, zeroed and writable,
/// counts the fault and lets the code go on, the way the interpreter reads
/// 0 and counts one. copy_from puts the pages back.
struct Space {
    base: *mut u8,
    touched: Vec<usize>,
    faults: u64,
}

const SPACE_SIZE: usize = (1 << 32) + 0x1_0000;

/// the spaces the fault handler looks in, as addresses of their boxes.
static SPACES: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// whether a fault at host address is in a space, whose page it then makes
/// accessible. called by the handler, on the thread that faulted.
fn fault_at(address: usize) -> bool {
    let Ok(spaces) = SPACES.lock() else { return false };
    for &space in spaces.iter() {
        // SAFETY: a registered space lives until its Memory drops, which
        // unregisters it first
        let space = unsafe { &mut *(space as *mut Space) };
        let offset = address.wrapping_sub(space.base as usize);
        if offset < SPACE_SIZE {
            let page = offset & !(PAGE_SIZE - 1);
            // SAFETY: a page of the reservation
            unsafe { os::open(space.base.add(page), PAGE_SIZE) };
            space.touched.push(page);
            space.faults += 1;
            return true;
        }
    }
    false
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_DECOMMIT: u32 = 0x4000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_NOACCESS: u32 = 1;
    const PAGE_READONLY: u32 = 2;
    const PAGE_READWRITE: u32 = 4;

    #[repr(C)]
    struct ExceptionRecord {
        code: u32,
        flags: u32,
        record: *mut ExceptionRecord,
        address: *mut c_void,
        parameters: u32,
        information: [usize; 15],
    }

    #[repr(C)]
    struct ExceptionPointers {
        record: *mut ExceptionRecord,
        context: *mut c_void,
    }

    extern "system" {
        fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
        fn VirtualProtect(address: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut c_void;
    }

    unsafe extern "system" fn handler(pointers: *mut ExceptionPointers) -> i32 {
        // SAFETY: the system hands over a valid record
        let record = unsafe { &*(*pointers).record };
        // an access violation, its address the second parameter
        if record.code == 0xC000_0005 && record.parameters >= 2 && super::fault_at(record.information[1]) {
            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }
        0 // EXCEPTION_CONTINUE_SEARCH
    }

    pub fn reserve(size: usize) -> *mut u8 {
        static HANDLER: std::sync::Once = std::sync::Once::new();
        // SAFETY: plain system calls
        HANDLER.call_once(|| unsafe {
            AddVectoredExceptionHandler(1, handler);
        });
        let base = unsafe { VirtualAlloc(std::ptr::null_mut(), size, MEM_RESERVE, PAGE_NOACCESS) } as *mut u8;
        assert!(!base.is_null(), "cannot reserve the guest's address space");
        base
    }

    /// # Safety
    /// the pages have to be the reservation's
    pub unsafe fn open(at: *mut u8, size: usize) {
        unsafe {
            VirtualAlloc(at.cast(), size, MEM_COMMIT, PAGE_READWRITE);
            VirtualProtect(at.cast(), size, PAGE_READWRITE, &mut 0);
        }
    }

    /// # Safety
    /// as open, and committed
    pub unsafe fn read_only(at: *mut u8, size: usize) {
        unsafe { VirtualProtect(at.cast(), size, PAGE_READONLY, &mut 0) };
    }

    /// # Safety
    /// as open
    pub unsafe fn close(at: *mut u8, size: usize) {
        unsafe { VirtualFree(at.cast(), size, MEM_DECOMMIT) };
    }

    /// # Safety
    /// a reservation nothing uses any more
    pub unsafe fn release(base: *mut u8, _size: usize) {
        unsafe { VirtualFree(base.cast(), 0, MEM_RELEASE) };
    }
}

#[cfg(unix)]
mod os {
    unsafe extern "C" fn handler(_signal: i32, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
        // SAFETY: the system hands over a valid siginfo
        let address = unsafe { (*info).si_addr() } as usize;
        if !super::fault_at(address) {
            // not ours: the default action, once the access runs again
            unsafe {
                libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                libc::signal(libc::SIGBUS, libc::SIG_DFL);
            }
        }
    }

    pub fn reserve(size: usize) -> *mut u8 {
        static HANDLER: std::sync::Once = std::sync::Once::new();
        // SAFETY: plain system calls
        HANDLER.call_once(|| unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut());
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
        });
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        let base = unsafe { libc::mmap(std::ptr::null_mut(), size, libc::PROT_NONE, flags, -1, 0) };
        assert!(base != libc::MAP_FAILED, "cannot reserve the guest's address space");
        base as *mut u8
    }

    /// # Safety
    /// the pages have to be the reservation's
    pub unsafe fn open(at: *mut u8, size: usize) {
        unsafe { libc::mprotect(at.cast(), size, libc::PROT_READ | libc::PROT_WRITE) };
    }

    /// # Safety
    /// as open
    pub unsafe fn read_only(at: *mut u8, size: usize) {
        unsafe { libc::mprotect(at.cast(), size, libc::PROT_READ) };
    }

    /// # Safety
    /// as open
    pub unsafe fn close(at: *mut u8, size: usize) {
        unsafe {
            libc::madvise(at.cast(), size, libc::MADV_DONTNEED);
            libc::mprotect(at.cast(), size, libc::PROT_NONE);
        }
    }

    /// # Safety
    /// a reservation nothing uses any more
    pub unsafe fn release(base: *mut u8, size: usize) {
        unsafe { libc::munmap(base.cast(), size) };
    }
}

/// a region's place in the space.
struct Area {
    base: u32,
    size: usize,
    writable: bool,
}

pub struct Memory {
    areas: Vec<Area>,
    space: Box<Space>,
    read_pages: Vec<*mut u8>,
    write_pages: Vec<*mut u8>,
    faults: u64,
}

impl Memory {
    pub fn new(regions: Vec<Region>) -> Memory {
        let base = os::reserve(SPACE_SIZE);
        let mut space = Box::new(Space { base, touched: Vec::new(), faults: 0 });
        SPACES.lock().unwrap().push(&mut *space as *mut Space as usize);
        let mut read_pages = vec![null_mut(); 1 << 20];
        let mut write_pages = vec![null_mut(); 1 << 20];
        let mut areas = Vec::new();
        for region in regions {
            let size = region.bytes.len().next_multiple_of(PAGE_SIZE);
            // SAFETY: the region's pages, in the reservation
            unsafe {
                let at = base.add(region.base as usize);
                os::open(at, size);
                std::ptr::copy_nonoverlapping(region.bytes.as_ptr(), at, region.bytes.len());
                if !region.writable {
                    os::read_only(at, size);
                }
                for offset in (0..size).step_by(PAGE_SIZE) {
                    let index = (region.base as usize + offset) >> 12;
                    read_pages[index] = at.add(offset);
                    if region.writable {
                        write_pages[index] = at.add(offset);
                    }
                }
            }
            areas.push(Area { base: region.base, size, writable: region.writable });
        }
        Memory { areas, space, read_pages, write_pages, faults: 0 }
    }

    fn bytes(&self, area: &Area) -> &[u8] {
        // SAFETY: an area is committed, at least readable, for as long as
        // the space
        unsafe { std::slice::from_raw_parts(self.space.base.add(area.base as usize), area.size) }
    }

    fn duplicate(&self) -> Memory {
        let regions = self
            .areas
            .iter()
            .map(|a| Region { base: a.base, bytes: self.bytes(a).to_vec(), writable: a.writable })
            .collect();
        Memory::new(regions)
    }

    /// the faults of both ways the run went, the interpreter's and the
    /// recompiled code's.
    fn faults(&self) -> u64 {
        self.faults + self.space.faults
    }

    fn copy_from(&mut self, other: &Memory) {
        let base = self.space.base;
        // the pages the code faulted on, back as they were
        for page in std::mem::take(&mut self.space.touched) {
            let area = self.areas.iter().find(|a| (a.base as usize..a.base as usize + a.size).contains(&page));
            // SAFETY: pages of the reservation
            unsafe {
                match area {
                    // a read-only page the code wrote, with the title's bytes again
                    Some(area) if !area.writable => {
                        std::ptr::copy_nonoverlapping(other.space.base.add(page), base.add(page), PAGE_SIZE);
                        os::read_only(base.add(page), PAGE_SIZE);
                    }
                    Some(_) => {}
                    None => os::close(base.add(page), PAGE_SIZE),
                }
            }
        }
        for area in self.areas.iter().filter(|a| a.writable) {
            let at = area.base as usize;
            // SAFETY: the same area, writable, in both spaces
            unsafe { std::ptr::copy_nonoverlapping(other.space.base.add(at), base.add(at), area.size) };
        }
        self.faults = 0;
        self.space.faults = 0;
    }

    /// the first address whose byte differs between two copies, where two
    /// NaNs count as the same whatever their bits.
    fn first_difference(&self, other: &Memory) -> Option<u32> {
        self.areas.iter().zip(&other.areas).filter(|(area, _)| area.writable).find_map(|(area, other_area)| {
            let (a, b) = (self.bytes(area), other.bytes(other_area));
            let mut i = 0;
            while i < a.len() {
                if a[i] == b[i] {
                    i += 1;
                    continue;
                }
                let word = i & !3;
                let double = i & !7;
                if nans(a, b, double, 8) {
                    i = double + 8;
                } else if nans(a, b, word, 4) {
                    i = word + 4;
                } else {
                    return Some(area.base + i as u32);
                }
            }
            None
        })
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        let space = &mut *self.space as *mut Space as usize;
        SPACES.lock().unwrap().retain(|&s| s != space);
        // SAFETY: nothing reaches the space any more
        unsafe { os::release(self.space.base, SPACE_SIZE) };
    }
}

/// whether the float of size bytes at offset is a NaN in both a and b.
fn nans(a: &[u8], b: &[u8], offset: usize, size: usize) -> bool {
    let nan = |bytes: &[u8]| match *bytes.get(offset..offset + size).unwrap_or_default() {
        [_, _, _, _] => f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()).is_nan(),
        [_, _, _, _, _, _, _, _] => f64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()).is_nan(),
        _ => false,
    };
    nan(a) && nan(b)
}

/// whether two sets of VFP registers hold the same values, where two NaNs
/// count as the same. the compilers on each side are free to pick which NaN
/// comes out of an operation, and so is the hardware.
fn same_vfp(a: &[u32; 32], b: &[u32; 32]) -> bool {
    let single = |bits: u32| f32::from_bits(bits).is_nan();
    let double = |r: &[u32; 32], d: usize| f64::from_bits((r[2 * d + 1] as u64) << 32 | r[2 * d] as u64).is_nan();
    (0..16).all(|d| {
        (double(a, d) && double(b, d)) || (2 * d..2 * d + 2).all(|s| a[s] == b[s] || (single(a[s]) && single(b[s])))
    })
}

impl Bus for Memory {
    fn read8(&mut self, address: u32) -> u8 {
        let page = self.read_pages[(address >> 12) as usize];
        if page.is_null() {
            self.faults += 1;
            return 0;
        }
        // SAFETY: a mapped page is PAGE_SIZE bytes of a region's buffer
        unsafe { *page.add((address & 0xFFF) as usize) }
    }

    fn read16(&mut self, address: u32) -> u16 {
        u16::from_le_bytes([self.read8(address), self.read8(address.wrapping_add(1))])
    }

    fn read32(&mut self, address: u32) -> u32 {
        u32::from_le_bytes(std::array::from_fn(|i| self.read8(address.wrapping_add(i as u32))))
    }

    fn write8(&mut self, address: u32, value: u8) {
        let page = self.write_pages[(address >> 12) as usize];
        if page.is_null() {
            self.faults += 1;
            return;
        }
        // SAFETY: as in read8
        unsafe { *page.add((address & 0xFFF) as usize) = value }
    }

    fn write16(&mut self, address: u32, value: u16) {
        for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.write8(address.wrapping_add(i as u32), byte);
        }
    }

    fn write32(&mut self, address: u32, value: u32) {
        for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.write8(address.wrapping_add(i as u32), byte);
        }
    }
}

/// one side of a comparison.
struct Run {
    memory: Memory,
    cpu: Cpu,
    library: *const Library,
    /// what the interpreter stopped with inside a callback.
    pending: Option<Exit>,
    /// instructions the interpreter ran on the recompiled side, alone or
    /// for the code.
    interpreted: u64,
    fallbacks: u64,
    /// whether svcs change nothing and the run goes on after them, the way
    /// it does with a host that runs them in place, rather than ending.
    through: bool,
    /// the svcs it went on through.
    svcs: u64,
}

#[derive(Debug, PartialEq)]
enum Stop {
    Returned,
    Svc(u32),
    Limit,
    Other(String),
}

fn stop(exit: Exit) -> Stop {
    match exit {
        Exit::Supervisor(number) => Stop::Svc(number),
        other => Stop::Other(format!("{other:?}")),
    }
}

/// whether a run goes on after what the interpreter stopped with, an svc
/// it goes on through, counting it.
fn goes_through(run: &mut Run, exit: &Exit) -> bool {
    let through = run.through && matches!(exit, Exit::Supervisor(_));
    run.svcs += through as u64;
    through
}

/// the run a callback belongs to.
///
/// # Safety
///
/// ctx must be a context set up by recompiled, whose user field points at
/// a live Run nothing else is using.
unsafe fn run_of<'a>(ctx: *mut Context) -> &'a mut Run {
    unsafe { &mut *((*ctx).user as *mut Run) }
}

unsafe extern "C" fn interpret(ctx: *mut Context, address: u32, _opcode: u32) {
    unsafe {
        let run = run_of(ctx);
        let ctx = &mut *ctx;
        load(ctx, &mut run.cpu);
        run.cpu.regs[15] = address;
        let exit = run.cpu.step(&mut run.memory);
        store(&run.cpu, ctx);
        run.fallbacks += 1;
        let step = if ctx.thumb != 0 { 2 } else { 4 };
        if exit.is_some() || ctx.r[15] != address.wrapping_add(step) {
            run.pending = exit;
            ctx.exit = abi::EXIT_UNWIND;
        }
    }
}

unsafe extern "C" fn lookup(ctx: *mut Context, address: u32) -> Option<Code> {
    unsafe { (*run_of(ctx).library).lookup(address) }
}

/// an svc, which the code goes on after when the run goes on through them,
/// and which ends the run otherwise, as the interpreter's.
unsafe extern "C" fn svc(ctx: *mut Context, number: u32) {
    unsafe {
        let run = run_of(ctx);
        if run.through {
            run.svcs += 1;
        } else {
            (*ctx).svc = number;
            (*ctx).exit = abi::EXIT_SVC;
        }
    }
}

static HOST: Host = Host { interpret, lookup, svc };

fn load(ctx: &Context, cpu: &mut Cpu) {
    cpu.regs = ctx.r;
    cpu.cpsr.n = ctx.n != 0;
    cpu.cpsr.z = ctx.z != 0;
    cpu.cpsr.c = ctx.c != 0;
    cpu.cpsr.v = ctx.v != 0;
    cpu.cpsr.q = ctx.q != 0;
    cpu.cpsr.ge = ctx.ge;
    cpu.cpsr.thumb = ctx.thumb != 0;
    cpu.exclusive_addr = (ctx.exclusive != 0).then_some(ctx.exclusive_address);
}

fn store(cpu: &Cpu, ctx: &mut Context) {
    ctx.r = cpu.regs;
    ctx.n = cpu.cpsr.n as u8;
    ctx.z = cpu.cpsr.z as u8;
    ctx.c = cpu.cpsr.c as u8;
    ctx.v = cpu.cpsr.v as u8;
    ctx.q = cpu.cpsr.q as u8;
    ctx.ge = cpu.cpsr.ge;
    ctx.thumb = cpu.cpsr.thumb as u8;
    ctx.exclusive = cpu.exclusive_addr.is_some() as u8;
    ctx.exclusive_address = cpu.exclusive_addr.unwrap_or(0);
    ctx.tls = cpu.cp15.thread_id_ro;
}

fn interpreted(run: &mut Run) -> Stop {
    for _ in 0..LIMIT {
        if run.cpu.regs[15] == RETURN && !run.cpu.cpsr.thumb {
            return Stop::Returned;
        }
        if let Some(exit) = run.cpu.step(&mut run.memory) {
            if !goes_through(run, &exit) {
                return stop(exit);
            }
        }
    }
    Stop::Limit
}

/// runs the recompiled code the way a host would, falling back to the
/// interpreter wherever there is none. slice is the budget each run of the
/// code gets, out of LIMIT in all. a short one makes the code stop at block
/// starts and go on from there, which is what a host does at the end of a
/// timeslice, and when a block does not fit, one instruction goes through
/// the interpreter instead, as in Zakuro. budget holds what is left after.
///
/// # Safety
///
/// run and ctx have to stay valid and unaliased for the whole run, the
/// callbacks reach run through ctx.
unsafe fn recompiled(run: *mut Run, ctx: *mut Context, slice: i32) -> Stop {
    unsafe {
        let mut left = LIMIT;
        let stop = loop {
            if (*ctx).r[15] == RETURN && (*ctx).thumb == 0 {
                break Stop::Returned;
            }
            if left <= 0 {
                break Stop::Limit;
            }
            if let Some(code) = (*(*run).library).lookup((*ctx).r[15] | (*ctx).thumb as u32) {
                let budget = slice.min(left);
                (*ctx).budget = budget;
                (*ctx).exit = abi::EXIT_NONE;
                (*ctx).depth = 0;
                code(ctx);
                let spent = budget - (*ctx).budget;
                left -= spent;
                if let Some(exit) = (*run).pending.take() {
                    break stop(exit);
                }
                match (*ctx).exit {
                    abi::EXIT_SVC => break Stop::Svc((*ctx).svc),
                    // the block did not fit, the interpreter takes a step
                    abi::EXIT_BUDGET if spent == 0 => {}
                    _ => continue,
                }
            }
            let run = &mut *run;
            let ctx = &mut *ctx;
            load(ctx, &mut run.cpu);
            let exit = run.cpu.step(&mut run.memory);
            store(&run.cpu, ctx);
            left -= 1;
            run.interpreted += 1;
            if let Some(exit) = exit {
                if !goes_through(run, &exit) {
                    break stop(exit);
                }
            }
        };
        (*ctx).budget = left;
        stop
    }
}

/// xorshift, enough to make up states.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as u32
    }

    fn heap_pointer(&mut self) -> u32 {
        (HEAP + self.next() % (HEAP_SIZE - 0x1000)) & !3
    }
}

fn differences(a: &Run, b: &Run, ctx: &Context) -> Vec<String> {
    let mut found = Vec::new();
    let nan = |bits: u32| f32::from_bits(bits).is_nan();
    for i in 0..16 {
        // a NaN moved out of a VFP register
        if a.cpu.regs[i] != ctx.r[i] && !(nan(a.cpu.regs[i]) && nan(ctx.r[i])) {
            found.push(format!("r{i} {:08X} against {:08X}", a.cpu.regs[i], ctx.r[i]));
        }
    }
    let flags = [
        ("n", a.cpu.cpsr.n, ctx.n),
        ("z", a.cpu.cpsr.z, ctx.z),
        ("c", a.cpu.cpsr.c, ctx.c),
        ("v", a.cpu.cpsr.v, ctx.v),
        ("q", a.cpu.cpsr.q, ctx.q),
        ("thumb", a.cpu.cpsr.thumb, ctx.thumb),
    ];
    for (name, expected, got) in flags {
        if expected as u8 != got {
            found.push(format!("{name} {} against {got}", expected as u8));
        }
    }
    let monitor = (ctx.exclusive != 0).then_some(ctx.exclusive_address);
    if a.cpu.exclusive_addr != monitor {
        found.push(format!("exclusive monitor {:X?} against {monitor:X?}", a.cpu.exclusive_addr));
    }
    if a.cpu.cpsr.ge != ctx.ge {
        found.push(format!("ge {:X} against {:X}", a.cpu.cpsr.ge, ctx.ge));
    }
    if !same_vfp(&a.cpu.vfp.regs, &b.cpu.vfp.regs) || a.cpu.vfp.fpscr != b.cpu.vfp.fpscr {
        found.push("vfp state".to_owned());
    }
    if let Some(address) = a.memory.first_difference(&b.memory) {
        found.push(format!("memory at {address:08X}"));
    }
    // the interpreter counts each access, the recompiled code each page it
    // first touches, so only whether either faulted can compare
    if (a.memory.faults() > 0) != (b.memory.faults() > 0) {
        found.push(format!("{} faults against {}", a.memory.faults(), b.memory.faults()));
    }
    found
}

/// the title's memory, its segments where it expects them plus a stack, a
/// heap and thread local storage full of made up data.
pub fn regions(text: (u32, &[u8]), rodata: (u32, &[u8]), data: (u32, &[u8]), bss: u32) -> Vec<Region> {
    let mut random = Random(0x9E37_79B9_7F4A_7C15);
    let mut heap = vec![0u8; HEAP_SIZE as usize];
    for word in heap.chunks_mut(4) {
        let value = if random.next().is_multiple_of(4) { random.heap_pointer() } else { random.next() };
        word.copy_from_slice(&value.to_le_bytes());
    }
    let mut data_bytes = data.1.to_vec();
    data_bytes.resize(data_bytes.len() + bss as usize, 0);
    vec![
        Region { base: text.0, bytes: text.1.to_vec(), writable: false },
        Region { base: rodata.0, bytes: rodata.1.to_vec(), writable: false },
        Region { base: data.0, bytes: data_bytes, writable: true },
        Region { base: HEAP, bytes: heap, writable: true },
        Region { base: STACK_TOP - STACK_SIZE, bytes: vec![0; STACK_SIZE as usize], writable: true },
        Region { base: TLS, bytes: vec![0; PAGE_SIZE], writable: true },
        // mov r0, 0 and bx lr
        Region { base: IMPORT_STUB, bytes: [0xE3A0_0000u32, 0xE12F_FF1E].iter().flat_map(|w| w.to_le_bytes()).collect(), writable: false },
    ]
}

#[derive(Default)]
pub struct Report {
    /// instructions run as recompiled code, through the fallback and in
    /// the interpreter alone.
    pub native: u64,
    pub fallbacks: u64,
    pub interpreted: u64,
    pub tested: usize,
    pub returned: usize,
    pub svc: usize,
    /// svcs that runs went on through and still matched.
    pub through: u64,
    pub stuck: usize,
    pub other: usize,
    pub mismatched: usize,
}

impl Report {
    pub fn add(&mut self, other: &Report) {
        self.native += other.native;
        self.fallbacks += other.fallbacks;
        self.interpreted += other.interpreted;
        self.tested += other.tested;
        self.returned += other.returned;
        self.svc += other.svc;
        self.through += other.through;
        self.stuck += other.stuck;
        self.other += other.other;
        self.mismatched += other.mismatched;
    }
}

/// the context the recompiled side of run works on, its registers left for
/// store to fill in. run has to stay where it is while the code runs.
fn context(run: &mut Run) -> Context {
    Context {
        r: [0; 16],
        n: 0,
        z: 0,
        c: 0,
        v: 0,
        q: 0,
        thumb: 0,
        ge: 0,
        exclusive: 0,
        budget: 0,
        exit: 0,
        svc: 0,
        depth: 0,
        exclusive_address: 0,
        tls: 0,
        fastmem: run.memory.space.base,
        vfp: run.cpu.vfp.regs.as_mut_ptr(),
        fpscr: &mut run.cpu.vfp.fpscr,
        host: &HOST,
        user: run as *mut Run as *mut c_void,
    }
}

/// runs each function both ways, printing the first few mismatches. the
/// functions are entries with bit 0 set for Thumb.
pub fn verify(name: &str, pristine: &Memory, library: &Library, functions: &[u32]) -> Report {
    let fresh = || Run {
        memory: pristine.duplicate(),
        cpu: Cpu::new(),
        library,
        pending: None,
        interpreted: 0,
        fallbacks: 0,
        through: false,
        svcs: 0,
    };
    let mut a = fresh();
    let mut b = fresh();
    let mut report = Report::default();

    for &function in functions {
        a.memory.copy_from(pristine);
        b.memory.copy_from(pristine);
        let mut random = Random(0x5DEE_CE66_D000_0000 ^ function as u64);
        let mut cpu = Cpu::new();
        for register in 0..13 {
            cpu.regs[register] = match random.next() % 4 {
                0 | 1 => random.heap_pointer(),
                2 => random.next() % 256,
                _ => random.next(),
            };
        }
        cpu.regs[13] = STACK_TOP - 0x1000;
        cpu.regs[14] = RETURN;
        cpu.regs[15] = function & !1;
        cpu.cpsr.thumb = function & 1 != 0;
        let flags = random.next();
        cpu.cpsr.n = flags & 1 != 0;
        cpu.cpsr.z = flags & 2 != 0;
        cpu.cpsr.c = flags & 4 != 0;
        cpu.cpsr.v = flags & 8 != 0;
        for register in 0..32 {
            cpu.vfp.regs[register] = ((random.next() % 20_000) as f32 / 100.0 - 100.0).to_bits();
        }
        // half the runs start on short vectors of some length and stride,
        // with flush to zero on or off
        if random.next().is_multiple_of(2) {
            let stride = if random.next().is_multiple_of(2) { 3 << 20 } else { 0 };
            let flush = if random.next().is_multiple_of(2) { 1 << 24 } else { 0 };
            cpu.vfp.fpscr = (random.next() % 8) << 16 | stride | flush;
        }
        cpu.cp15.thread_id_ro = TLS;
        a.cpu = cpu.clone();
        b.cpu = cpu.clone();

        let mut ctx = context(&mut b);
        store(&cpu, &mut ctx);

        // half the functions go on through their svcs, the other half end
        // at the first one, as all of them do in code made for version 4 of
        // the interface, which has no svc callback. the coin is a product's
        // top bit, which xorshift's coin for the slices below, a sum of the
        // address's bits, says nothing about
        let through = library.abi() > 4 && (function as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 63 == 1;
        for run in [&mut a, &mut b] {
            run.through = through;
            run.svcs = 0;
        }
        let expected = interpreted(&mut a);
        b.interpreted = 0;
        b.fallbacks = 0;
        // half the functions run in short slices, stopping for the budget at
        // block starts and going on from there
        let mut slicing = Random(0x2545_F491_4F6C_DD1D ^ function as u64);
        let slice = if slicing.next().is_multiple_of(2) { LIMIT } else { 1 + (slicing.next() % 48) as i32 };
        // SAFETY: b and ctx live through the run and nothing else touches them
        let got = unsafe { recompiled(&mut b, &mut ctx, slice) };
        report.tested += 1;
        let spent = (LIMIT - ctx.budget) as u64;
        report.native += spent.saturating_sub(b.interpreted + b.fallbacks);
        report.fallbacks += b.fallbacks;
        report.interpreted += b.interpreted;
        if functions.len() == 1 {
            // a single function gets the whole story
            println!("  {name} {function:08X}, interpreter stopped with {expected:?}, recompiled with {got:?}");
            println!(
                "  recompiled side, {} native, {} fallbacks, {} interpreted alone",
                spent.saturating_sub(b.interpreted + b.fallbacks),
                b.fallbacks,
                b.interpreted
            );
            println!("  interpreter {:08X?}", a.cpu.regs);
            println!("  recompiled  {:08X?}", ctx.r);
            for i in 0..32 {
                if a.cpu.vfp.regs[i] != b.cpu.vfp.regs[i] {
                    let (x, y) = (a.cpu.vfp.regs[i], b.cpu.vfp.regs[i]);
                    println!("  s{i} {x:08X} ({}) against {y:08X} ({})", f32::from_bits(x), f32::from_bits(y));
                }
            }
            println!("  fpscr {:08X} against {:08X}", a.cpu.vfp.fpscr, b.cpu.vfp.fpscr);
        }
        if expected == Stop::Limit || got == Stop::Limit {
            report.stuck += 1;
            continue;
        }
        let mut found = differences(&a, &b, &ctx);
        if a.svcs != b.svcs {
            found.insert(0, format!("went through {} svcs against {}", a.svcs, b.svcs));
        }
        if expected != got {
            found.insert(0, format!("stopped with {expected:?} against {got:?}"));
        }
        if !found.is_empty() {
            report.mismatched += 1;
            if report.mismatched <= 20 {
                println!("  {name} {function:08X}  {}", found.join(", "));
            }
            continue;
        }
        report.through += a.svcs;
        match expected {
            Stop::Returned => report.returned += 1,
            Stop::Svc(_) => report.svc += 1,
            _ => report.other += 1,
        }
    }
    report
}

/// a division's case, the bits of its quotient, whether a sign was set, and
/// whether n and d had high words.
type Case = (u32, bool, bool, bool);

/// what the title's code charged in a case, the least, the most, the sum and
/// how many times.
type Charged = (u64, u64, u64, i32);

/// how the natives fared against the title's own code for them.
#[derive(Default)]
pub struct NativesReport {
    pub tested: usize,
    pub mismatched: usize,
    /// divisions the natives charged the budget for as the title's code
    /// does, out of how many, and the most a native was off by.
    pub charged_alike: usize,
    pub charged: usize,
    pub most_off: i32,
}

/// numbers to divide, n and d, of every size up to bits and both signs when
/// signed, so that the library's code goes every way it can, and the cases
/// at the edges, a divisor of zero and of one, and the quotient that
/// overflows.
fn dividends(random: &mut Random, bits: u32, signed: bool) -> Vec<(u64, u64)> {
    let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let mut sized = |size: u32| {
        let value = (random.next() as u64) << 32 | random.next() as u64;
        if size == 0 { 0 } else { (value | 1 << (size - 1)) & (u64::MAX >> (64 - size)) }
    };
    let mut cases = Vec::new();
    for n_bits in 0..=bits {
        for d_bits in 1..=bits {
            cases.push((sized(n_bits), sized(d_bits)));
        }
    }
    let top = 1u64 << (bits - 1);
    cases.extend([(12345, 0), (0, 7), (7, 1), (top, mask), (mask, 1), (mask, mask), (top, 3)]);
    if signed {
        let flipped: Vec<(u64, u64)> = cases.iter().map(|&(n, d)| (n.wrapping_neg() & mask, d)).collect();
        let both: Vec<(u64, u64)> = cases.iter().map(|&(n, d)| (n.wrapping_neg() & mask, d.wrapping_neg() & mask)).collect();
        let divisor: Vec<(u64, u64)> = cases.iter().map(|&(n, d)| (n, d.wrapping_neg() & mask)).collect();
        cases.extend(flipped);
        cases.extend(both);
        cases.extend(divisor);
    }
    cases
}

/// runs each native the library has, and the title's own code for it in the
/// interpreter, on the numbers dividends makes. the quotient and remainder
/// have to agree, and every register a call keeps. it also runs the title's
/// code recompiled, the natives off, and prints what that charges the
/// budget against what the natives do, by the bits of the quotient.
pub fn natives(pristine: &Memory, library: &mut Library, natives: &[crate::natives::Native]) -> NativesReport {
    use crate::natives::Kind;
    use std::collections::BTreeMap;
    let library: *mut Library = library;
    let fresh = || Run {
        memory: pristine.duplicate(),
        cpu: Cpu::new(),
        library,
        pending: None,
        interpreted: 0,
        fallbacks: 0,
        through: false,
        svcs: 0,
    };
    let mut report = NativesReport::default();
    // the divisions only touch the stack, so the runs go on from where the
    // last left memory
    let mut expected = fresh();
    let mut got = fresh();
    for native in natives {
        let (bits, signed, results) = match native.kind {
            Kind::Uidivmod => (32, false, 2),
            Kind::Idivmod => (32, true, 2),
            Kind::Uldivmod => (64, false, 4),
            Kind::Ldivmod => (64, true, 4),
        };
        let mut random = Random(0x5DEE_CE66_D000_0000 ^ native.address as u64);
        // what each side charged, by the bits of the quotient and whether a
        // sign or a high word was in it
        let mut charges: BTreeMap<Case, Charged> = BTreeMap::new();
        for (n, d) in dividends(&mut random, bits, signed) {
            let mut cpu = Cpu::new();
            for register in 4..13 {
                cpu.regs[register] = random.next();
            }
            let (n_low, n_high, d_low, d_high) = (n as u32, (n >> 32) as u32, d as u32, (d >> 32) as u32);
            if bits == 32 {
                cpu.regs[0] = n_low;
                cpu.regs[1] = d_low;
            } else {
                cpu.regs[..4].copy_from_slice(&[n_low, n_high, d_low, d_high]);
            }
            cpu.regs[13] = STACK_TOP - 0x1000;
            cpu.regs[14] = RETURN;
            cpu.regs[15] = native.address;
            cpu.cp15.thread_id_ro = TLS;
            // what the library's code leaves below sp is compared too, from
            // nothing
            let stack = STACK_TOP - 0x1000 - 32;
            for at in (stack..stack + 32).step_by(4) {
                expected.memory.write32(at, 0);
            }
            expected.cpu = cpu.clone();
            let stopped = interpreted(&mut expected);
            let mut spent = [0i32; 2];
            for (side, natives_on) in [false, true].into_iter().enumerate() {
                // SAFETY: nothing runs the library's code meanwhile
                unsafe { (*library).set_natives(natives_on) };
                for at in (stack..stack + 32).step_by(4) {
                    got.memory.write32(at, 0);
                }
                got.cpu = cpu.clone();
                let mut ctx = context(&mut got);
                store(&cpu, &mut ctx);
                // SAFETY: got and ctx live through the run and nothing else
                // touches them
                let stop = unsafe { recompiled(&mut got, &mut ctx, LIMIT) };
                spent[side] = LIMIT - ctx.budget;
                report.tested += 1;
                let mut found = Vec::new();
                if stop != stopped {
                    found.push(format!("stopped with {stopped:?} against {stop:?}"));
                }
                for register in (0..results).chain(4..12).chain([13, 15]) {
                    if expected.cpu.regs[register] != ctx.r[register] {
                        found.push(format!("r{register} {:08X} against {:08X}", expected.cpu.regs[register], ctx.r[register]));
                    }
                }
                for at in (stack..stack + 32).step_by(4) {
                    let (want, have) = (expected.memory.read32(at), got.memory.read32(at));
                    if want != have {
                        found.push(format!("[{at:08X}] {want:08X} against {have:08X}"));
                    }
                }
                if !found.is_empty() {
                    report.mismatched += 1;
                    if report.mismatched <= 20 {
                        let side = if natives_on { "native" } else { "recompiled" };
                        println!("  {:?} at {:08X}, {n:X} / {d:X}, {side}: {}", native.kind, native.address, found.join(", "));
                    }
                }
            }
            if d == 0 {
                continue;
            }
            let negative = signed && ((n >> (bits - 1)) & 1 == 1 || (d >> (bits - 1)) & 1 == 1);
            let magnitude = |value: u64| if negative && (value >> (bits - 1)) & 1 == 1 { value.wrapping_neg() & (u64::MAX >> (64 - bits)) } else { value };
            let (un, ud) = if signed { (magnitude(n), magnitude(d)) } else { (n, d) };
            // the 64-bit divisions go by how much longer n is than d, the
            // 32-bit ones by the bits of the quotient
            let quotient_bits = if bits == 64 {
                (64 + ud.leading_zeros()).saturating_sub(un.leading_zeros())
            } else if un / ud == 0 {
                0
            } else {
                64 - (un / ud).leading_zeros()
            };
            let key = (quotient_bits, negative, un >> 32 != 0, ud >> 32 != 0);
            let entry = charges.entry(key).or_insert((u64::MAX, 0, 0, 0));
            let original = spent[0] as u64;
            *entry = (entry.0.min(original), entry.1.max(original), entry.2 + original, entry.3 + 1);
            report.charged += 1;
            report.charged_alike += (spent[1] == spent[0]) as usize;
            report.most_off = report.most_off.max((spent[1] - spent[0]).abs());
        }
        println!("  {:?} at {:08X}, what the title's code charges by quotient bits, sign, high n, high d:", native.kind, native.address);
        for ((quotient_bits, negative, high_n, high_d), (min, max, sum, count)) in &charges {
            println!(
                "    {quotient_bits:2} {} {} {}  {min:4} to {max:4}, mean {:.1}",
                *negative as u8,
                *high_n as u8,
                *high_d as u8,
                *sum as f64 / *count as f64
            );
        }
    }
    // SAFETY: as above
    unsafe { (*library).set_natives(true) };
    report
}
