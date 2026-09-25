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

pub struct Memory {
    regions: Vec<Region>,
    read_pages: Vec<*mut u8>,
    write_pages: Vec<*mut u8>,
    faults: u64,
}

impl Memory {
    pub fn new(mut regions: Vec<Region>) -> Memory {
        let mut read_pages = vec![null_mut(); 1 << 20];
        let mut write_pages = vec![null_mut(); 1 << 20];
        for region in &mut regions {
            region.bytes.resize(region.bytes.len().next_multiple_of(PAGE_SIZE), 0);
            for (i, page) in region.bytes.chunks_mut(PAGE_SIZE).enumerate() {
                let index = (region.base as usize >> 12) + i;
                read_pages[index] = page.as_mut_ptr();
                if region.writable {
                    write_pages[index] = page.as_mut_ptr();
                }
            }
        }
        Memory { regions, read_pages, write_pages, faults: 0 }
    }

    fn duplicate(&self) -> Memory {
        let regions = self
            .regions
            .iter()
            .map(|r| Region { base: r.base, bytes: r.bytes.clone(), writable: r.writable })
            .collect();
        Memory::new(regions)
    }

    fn copy_from(&mut self, other: &Memory) {
        for (region, source) in self.regions.iter_mut().zip(&other.regions) {
            if region.writable {
                region.bytes.copy_from_slice(&source.bytes);
            }
        }
        self.faults = 0;
    }

    /// the first address whose byte differs between two copies.
    /// the first address whose byte differs between two copies, where two
    /// NaNs count as the same whatever their bits.
    fn first_difference(&self, other: &Memory) -> Option<u32> {
        self.regions.iter().zip(&other.regions).filter(|(region, _)| region.writable).find_map(|(a, b)| {
            let mut i = 0;
            while i < a.bytes.len() {
                if a.bytes[i] == b.bytes[i] {
                    i += 1;
                    continue;
                }
                let word = i & !3;
                let double = i & !7;
                if nans(&a.bytes, &b.bytes, double, 8) {
                    i = double + 8;
                } else if nans(&a.bytes, &b.bytes, word, 4) {
                    i = word + 4;
                } else {
                    return Some(a.base + i as u32);
                }
            }
            None
        })
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

/// the run a callback belongs to.
///
/// # Safety
///
/// ctx must be a context set up by recompiled, whose user field points at
/// a live Run nothing else is using.
unsafe fn run_of<'a>(ctx: *mut Context) -> &'a mut Run {
    unsafe { &mut *((*ctx).user as *mut Run) }
}

unsafe extern "C" fn read8(ctx: *mut Context, address: u32) -> u8 {
    unsafe { run_of(ctx).memory.read8(address) }
}

unsafe extern "C" fn read16(ctx: *mut Context, address: u32) -> u16 {
    unsafe { run_of(ctx).memory.read16(address) }
}

unsafe extern "C" fn read32(ctx: *mut Context, address: u32) -> u32 {
    unsafe { run_of(ctx).memory.read32(address) }
}

unsafe extern "C" fn write8(ctx: *mut Context, address: u32, value: u8) {
    unsafe { run_of(ctx).memory.write8(address, value) }
}

unsafe extern "C" fn write16(ctx: *mut Context, address: u32, value: u16) {
    unsafe { run_of(ctx).memory.write16(address, value) }
}

unsafe extern "C" fn write32(ctx: *mut Context, address: u32, value: u32) {
    unsafe { run_of(ctx).memory.write32(address, value) }
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
            ctx.exit = 3;
        }
    }
}

unsafe extern "C" fn lookup(ctx: *mut Context, address: u32) -> Option<Code> {
    unsafe { (*run_of(ctx).library).lookup(address) }
}

static HOST: Host = Host { read8, read16, read32, write8, write16, write32, interpret, lookup };

fn load(ctx: &Context, cpu: &mut Cpu) {
    cpu.regs = ctx.r;
    cpu.cpsr.n = ctx.n != 0;
    cpu.cpsr.z = ctx.z != 0;
    cpu.cpsr.c = ctx.c != 0;
    cpu.cpsr.v = ctx.v != 0;
    cpu.cpsr.q = ctx.q != 0;
    cpu.cpsr.ge = ctx.ge;
    cpu.cpsr.thumb = ctx.thumb != 0;
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
}

fn interpreted(run: &mut Run) -> Stop {
    for _ in 0..LIMIT {
        if run.cpu.regs[15] == RETURN && !run.cpu.cpsr.thumb {
            return Stop::Returned;
        }
        if let Some(exit) = run.cpu.step(&mut run.memory) {
            return stop(exit);
        }
    }
    Stop::Limit
}

/// runs the recompiled code the way a host would, falling back to the
/// interpreter wherever there is none.
///
/// # Safety
///
/// run and ctx have to stay valid and unaliased for the whole run, the
/// callbacks reach run through ctx.
unsafe fn recompiled(run: *mut Run, ctx: *mut Context) -> Stop {
    unsafe {
        (*ctx).budget = LIMIT;
        loop {
            if (*ctx).r[15] == RETURN && (*ctx).thumb == 0 {
                return Stop::Returned;
            }
            if (*ctx).budget <= 0 {
                return Stop::Limit;
            }
            match (*(*run).library).lookup((*ctx).r[15] | (*ctx).thumb as u32) {
                Some(code) => {
                    (*ctx).exit = 0;
                    (*ctx).depth = 0;
                    code(ctx);
                    if let Some(exit) = (*run).pending.take() {
                        return stop(exit);
                    }
                    match (*ctx).exit {
                        abi::EXIT_SVC => return Stop::Svc((*ctx).svc),
                        abi::EXIT_BUDGET => return Stop::Limit,
                        _ => {}
                    }
                }
                None => {
                    let run = &mut *run;
                    let ctx = &mut *ctx;
                    load(ctx, &mut run.cpu);
                    let exit = run.cpu.step(&mut run.memory);
                    store(&run.cpu, ctx);
                    ctx.budget -= 1;
                    run.interpreted += 1;
                    if let Some(exit) = exit {
                        return stop(exit);
                    }
                }
            }
        }
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
    if a.cpu.cpsr.ge != ctx.ge {
        found.push(format!("ge {:X} against {:X}", a.cpu.cpsr.ge, ctx.ge));
    }
    if !same_vfp(&a.cpu.vfp.regs, &b.cpu.vfp.regs) || a.cpu.vfp.fpscr != b.cpu.vfp.fpscr {
        found.push("vfp state".to_owned());
    }
    if let Some(address) = a.memory.first_difference(&b.memory) {
        found.push(format!("memory at {address:08X}"));
    }
    if a.memory.faults != b.memory.faults {
        found.push(format!("{} faults against {}", a.memory.faults, b.memory.faults));
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
        self.stuck += other.stuck;
        self.other += other.other;
        self.mismatched += other.mismatched;
    }
}

/// runs each function both ways, printing the first few mismatches. the
/// functions are entries with bit 0 set for Thumb.
pub fn verify(name: &str, pristine: &Memory, library: &Library, functions: &[u32]) -> Report {
    let fresh =
        || Run { memory: pristine.duplicate(), cpu: Cpu::new(), library, pending: None, interpreted: 0, fallbacks: 0 };
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
        cpu.cp15.thread_id_ro = TLS;
        a.cpu = cpu.clone();
        b.cpu = cpu.clone();

        let mut ctx = Context {
            r: [0; 16],
            n: 0,
            z: 0,
            c: 0,
            v: 0,
            q: 0,
            thumb: 0,
            ge: 0,
            pad: 0,
            budget: 0,
            exit: 0,
            svc: 0,
            depth: 0,
            read_pages: b.memory.read_pages.as_ptr(),
            write_pages: b.memory.write_pages.as_ptr(),
            vfp: b.cpu.vfp.regs.as_mut_ptr(),
            fpscr: &mut b.cpu.vfp.fpscr,
            host: &HOST,
            user: &mut b as *mut Run as *mut c_void,
        };
        store(&cpu, &mut ctx);

        let expected = interpreted(&mut a);
        b.interpreted = 0;
        b.fallbacks = 0;
        // SAFETY: b and ctx live through the run and nothing else touches them
        let got = unsafe { recompiled(&mut b, &mut ctx) };
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
        match expected {
            Stop::Returned => report.returned += 1,
            Stop::Svc(_) => report.svc += 1,
            _ => report.other += 1,
        }
    }
    report
}
