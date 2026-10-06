//! compiling the generated C, a compiler per core as long as the memory
//! holds them, into a shared library a host loads or a static one a program
//! links in.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// floating point has to round exactly the way the interpreter does, so
/// nothing may be fused into a multiply-add.
const FLAGS: &[&str] = &["-O2", "-ffp-contract=off", "-fno-math-errno", "-w"];
/// what only matters for ELF and Mach-O, and that compilers for Windows
/// refuse or ignore.
const UNIX_FLAGS: &[&str] = &["-fPIC", "-fvisibility=hidden"];

/// gcc collects its garbage far less often on a machine with a lot of
/// memory, and with that a file of generated code took 7.8 GB at its peak
/// instead of 4.8.
const GCC_FLAGS: &[&str] = &["--param", "ggc-min-expand=20", "--param", "ggc-min-heapsize=65536"];

/// about how many bytes a compiler takes at its peak for each byte of
/// generated C it compiles, gcc 16 keeping a whole file of functions in
/// memory took around 450 for one of 2.9 MB.
const MEMORY_PER_BYTE: u64 = 600;

/// what to leave of the memory there is for everything else.
const RESERVE: u64 = 1 << 30;

/// what progress hears after each file, how many are done and of how
/// many, answering whether to go on.
pub type Progress<'a> = &'a (dyn Fn(usize, usize) -> bool + Sync);

/// whether a program runs, asked for its version.
fn runs(program: &str) -> bool {
    Command::new(program).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// the first of the tools that runs, or the one named in variable.
fn tool(variable: &str, tools: &[&str]) -> String {
    std::env::var(variable)
        .ok()
        .filter(|name| !name.is_empty())
        .or_else(|| tools.iter().find(|tool| runs(tool)).map(|tool| tool.to_string()))
        .unwrap_or_else(|| tools[0].to_owned())
}

/// whether compiler is gcc, whose options for its garbage the others refuse.
fn is_gcc(compiler: &str) -> bool {
    let output = Command::new(compiler).arg("--version").output();
    output.is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("Free Software Foundation"))
}

/// the memory the system has to spare, MemAvailable on Linux and the free
/// physical memory on Windows, or none when it can't tell.
fn spare_memory() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = info.lines().find(|line| line.starts_with("MemAvailable:"))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kib * 1024)
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct MemoryStatus {
            length: u32,
            load: u32,
            total_physical: u64,
            available_physical: u64,
            total_page_file: u64,
            available_page_file: u64,
            total_virtual: u64,
            available_virtual: u64,
            available_extended_virtual: u64,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GlobalMemoryStatusEx(status: *mut MemoryStatus) -> i32;
        }
        // SAFETY: the struct is MEMORYSTATUSEX, with its length filled in
        unsafe {
            let mut status: MemoryStatus = std::mem::zeroed();
            status.length = std::mem::size_of::<MemoryStatus>() as u32;
            (GlobalMemoryStatusEx(&mut status) != 0).then_some(status.available_physical)
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    None
}

/// the C compiler, from CC or else the first there is. on Windows MinGW's
/// gcc comes first, it links a DLL with nothing else installed.
fn compiler() -> String {
    let compilers: &[&str] = if cfg!(windows) { &["gcc", "clang", "cc"] } else { &["cc", "gcc", "clang"] };
    tool("CC", compilers)
}

/// whether there is a C compiler to build with.
pub fn check() -> Result<(), String> {
    let compiler = compiler();
    if runs(&compiler) {
        return Ok(());
    }
    let suggestion = if cfg!(windows) {
        "install MinGW-w64's gcc, from MSYS2 or WinLibs, or LLVM's clang"
    } else {
        "install one such as gcc or clang"
    };
    Err(format!("there is no C compiler ({compiler}), {suggestion}, or name it in CC"))
}

/// compiles sources, file names inside dir, and links them into library,
/// telling progress how many of them are done after each one.
pub fn compile(dir: &Path, sources: &[String], library: &Path, progress: Progress) -> Result<(), String> {
    shared(&objects(dir, sources, progress)?, library)
}

/// compiles sources, file names inside dir, each into an object beside it,
/// stopping when progress says so. a compiler starts once the memory there
/// is to spare holds what it is likely to take, and there is always one
/// running, so a machine with little memory builds slower instead of
/// running out of it.
pub fn objects(dir: &Path, sources: &[String], progress: Progress) -> Result<Vec<PathBuf>, String> {
    let compiler = compiler();
    let gcc = is_gcc(&compiler);
    let jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    let budget = spare_memory().map(|spare| spare.saturating_sub(RESERVE));
    let needs: Vec<u64> =
        sources.iter().map(|source| std::fs::metadata(dir.join(source)).map_or(0, |m| m.len()) * MEMORY_PER_BYTE).collect();
    // the biggest first, so that none of them starts last and holds the
    // others up
    let mut order: Vec<usize> = (0..sources.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(needs[i]));

    // the next of order to start, and the memory and compilers in use
    let state = Mutex::new((0usize, 0u64, 0usize));
    let freed = Condvar::new();
    let done = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let failures = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| loop {
                let index = {
                    let mut state = state.lock().unwrap();
                    loop {
                        let (next, using, running) = *state;
                        if stopped.load(Ordering::Relaxed) || next == order.len() {
                            break None;
                        }
                        let index = order[next];
                        if running == 0 || budget.is_none_or(|budget| using + needs[index] <= budget) {
                            *state = (next + 1, using + needs[index], running + 1);
                            break Some(index);
                        }
                        state = freed.wait(state).unwrap();
                    }
                };
                let Some(index) = index else { break };
                let source = &sources[index];
                let path = dir.join(source);
                let status = Command::new(&compiler)
                    .args(FLAGS)
                    .args(if gcc { GCC_FLAGS } else { &[] })
                    .args(if cfg!(windows) { &[][..] } else { UNIX_FLAGS })
                    .arg("-I")
                    .arg(dir)
                    .arg("-c")
                    .arg(&path)
                    .arg("-o")
                    .arg(path.with_extension("o"))
                    .status();
                if !status.is_ok_and(|s| s.success()) {
                    failures.lock().unwrap().push(source.clone());
                }
                if !progress(done.fetch_add(1, Ordering::Relaxed) + 1, sources.len()) {
                    stopped.store(true, Ordering::Relaxed);
                }
                let mut state = state.lock().unwrap();
                state.1 -= needs[index];
                state.2 -= 1;
                freed.notify_all();
            });
        }
    });
    if stopped.into_inner() {
        return Err("stopped".to_owned());
    }
    let failures = failures.into_inner().unwrap();
    if !failures.is_empty() {
        return Err(format!("{} failed to compile, {}", failures.len(), failures.join(" ")));
    }
    Ok(sources.iter().map(|source| dir.join(source).with_extension("o")).collect())
}

/// links objects into a shared library. on Windows gcc's runtime goes in
/// with it, so the DLL needs no other DLL beside it.
pub fn shared(objects: &[PathBuf], library: &Path) -> Result<(), String> {
    let compiler = compiler();
    let mut command = Command::new(&compiler);
    if cfg!(windows) && compiler.contains("gcc") {
        command.arg("-static-libgcc");
    }
    let status = command.arg("-shared").arg("-o").arg(library).args(objects).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err("linking failed".to_owned()),
    }
}

/// puts objects into a static library.
pub fn archive(objects: &[PathBuf], library: &Path) -> Result<(), String> {
    // ar adds to what is there, which could hold objects no longer built
    if library.exists() {
        std::fs::remove_file(library).map_err(|e| format!("could not replace {}, {e}", library.display()))?;
    }
    let ar = tool("AR", &["ar", "llvm-ar"]);
    let status = Command::new(&ar).arg("rcs").arg(library).args(objects).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err("archiving failed".to_owned()),
    }
}
