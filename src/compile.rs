//! compiling the generated C, a compiler per core as long as the memory
//! holds them, into a shared library a host loads or a static one a program
//! links in.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
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

/// a C compiler: a program, and the arguments that go before the rest,
/// none for gcc, cc for zig, whose compiler is zig cc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiler {
    pub program: PathBuf,
    pub leading: Vec<String>,
}

impl Compiler {
    pub fn new(program: impl Into<PathBuf>, leading: &[&str]) -> Compiler {
        Compiler { program: program.into(), leading: leading.iter().map(|arg| arg.to_string()).collect() }
    }

    /// the compiler CC names, or else the first of the usual ones that runs.
    /// on Windows MinGW's gcc comes first, it links a DLL with nothing else
    /// installed.
    pub fn find() -> Option<Compiler> {
        if let Some(named) = std::env::var("CC").ok().filter(|named| !named.trim().is_empty()) {
            return Some(Compiler::named(&named));
        }
        let compilers: &[&str] = if cfg!(windows) { &["gcc", "clang", "cc"] } else { &["cc", "gcc", "clang"] };
        compilers.iter().map(|name| Compiler::new(name, &[])).find(Compiler::runs)
    }

    /// what CC holds: a program, or a program and the arguments that go
    /// first, separated by spaces, like zig cc.
    fn named(value: &str) -> Compiler {
        if Path::new(value).exists() {
            return Compiler::new(value, &[]);
        }
        let mut words = value.split_whitespace();
        let program = words.next().unwrap_or(value);
        Compiler { program: program.into(), leading: words.map(str::to_owned).collect() }
    }

    /// whether it runs, asked for its version.
    pub fn runs(&self) -> bool {
        self.command().arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    }

    /// a command that runs it, its leading arguments given.
    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.leading);
        command
    }

    /// whether it is gcc, whose options for its garbage the others refuse.
    fn is_gcc(&self) -> bool {
        let output = self.command().arg("--version").output();
        output.is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("Free Software Foundation"))
    }

    /// how it is called, for messages.
    pub fn describe(&self) -> String {
        std::iter::once(self.program.display().to_string()).chain(self.leading.iter().cloned()).collect::<Vec<_>>().join(" ")
    }
}

/// makes command run below normal priority, so that a game being played
/// keeps the processor while it compiles.
#[cfg(unix)]
fn lower(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setpriority is safe to call between fork and exec
    unsafe {
        command.pre_exec(|| {
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
            Ok(())
        });
    }
}

#[cfg(windows)]
fn lower(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
    command.creation_flags(BELOW_NORMAL_PRIORITY_CLASS);
}

#[cfg(not(any(unix, windows)))]
fn lower(_: &mut Command) {}

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

/// the compiler to build with, the one given or else the one find() picks,
/// when it runs.
pub fn check(given: Option<&Compiler>) -> Result<Compiler, String> {
    let compiler = given.cloned().or_else(Compiler::find);
    if let Some(compiler) = compiler.as_ref().filter(|compiler| compiler.runs()) {
        return Ok(compiler.clone());
    }
    let name = compiler.map(|compiler| compiler.describe()).unwrap_or_else(|| if cfg!(windows) { "gcc" } else { "cc" }.to_owned());
    let suggestion = if cfg!(windows) {
        "install MinGW-w64's gcc, from MSYS2 or WinLibs, or LLVM's clang"
    } else {
        "install one such as gcc or clang"
    };
    Err(format!("there is no C compiler ({name}), {suggestion}, or name it in CC"))
}

/// compiles sources, file names inside dir, and links them into library,
/// telling progress how many of them are done after each one. in the
/// background the compilers run below normal priority and leave a core.
pub fn compile(
    compiler: &Compiler,
    dir: &Path,
    sources: &[String],
    library: &Path,
    progress: Progress,
    background: bool,
) -> Result<(), String> {
    shared(compiler, &objects(compiler, dir, sources, progress, background)?, library)
}

/// compiles sources, file names inside dir, each into an object beside it,
/// stopping when progress says so. a compiler starts once the memory there
/// is to spare holds what it is likely to take, and there is always one
/// running, so a machine with little memory builds slower instead of
/// running out of it.
pub fn objects(
    compiler: &Compiler,
    dir: &Path,
    sources: &[String],
    progress: Progress,
    background: bool,
) -> Result<Vec<PathBuf>, String> {
    let gcc = compiler.is_gcc();
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
    let jobs = if background { cores.saturating_sub(1).max(1) } else { cores };
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
                let mut command = compiler.command();
                if background {
                    lower(&mut command);
                }
                let status = command
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
pub fn shared(compiler: &Compiler, objects: &[PathBuf], library: &Path) -> Result<(), String> {
    let mut command = compiler.command();
    if cfg!(windows) && compiler.is_gcc() {
        command.arg("-static-libgcc");
    }
    let library = std::path::absolute(library).map_err(|e| format!("linking failed, {e}"))?;
    let objects = from_folder(&mut command, objects);
    finished(command.arg("-shared").arg("-o").arg(library).args(objects).status(), "linking")
}

/// has command run in the folder objects are all in and gives their names
/// from there, their whole paths when they are not in one. a command line
/// on Windows holds 32767 characters, which the whole paths of the 600
/// objects of Monster Hunter 3 Ultimate or Pokémon Sun pass.
fn from_folder(command: &mut Command, objects: &[PathBuf]) -> Vec<PathBuf> {
    let folder = objects.first().and_then(|object| object.parent()).filter(|folder| !folder.as_os_str().is_empty());
    match folder.filter(|folder| objects.iter().all(|object| object.parent() == Some(*folder))) {
        Some(folder) => {
            command.current_dir(folder);
            objects.iter().map(|object| object.file_name().map_or_else(|| object.clone(), PathBuf::from)).collect()
        }
        None => objects.to_vec(),
    }
}

/// what a tool's run came to, an error saying why when it failed.
fn finished(status: std::io::Result<ExitStatus>, what: &str) -> Result<(), String> {
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{what} failed, {status}")),
        Err(error) => Err(format!("{what} failed, {error}")),
    }
}

/// puts objects into a static library.
pub fn archive(objects: &[PathBuf], library: &Path) -> Result<(), String> {
    // ar adds to what is there, which could hold objects no longer built
    if library.exists() {
        std::fs::remove_file(library).map_err(|e| format!("could not replace {}, {e}", library.display()))?;
    }
    let ar = std::env::var("AR")
        .ok()
        .filter(|name| !name.is_empty())
        .or_else(|| ["ar", "llvm-ar"].into_iter().find(|tool| Compiler::new(tool, &[]).runs()).map(str::to_owned))
        .unwrap_or_else(|| "ar".to_owned());
    let library = std::path::absolute(library).map_err(|e| format!("archiving failed, {e}"))?;
    let mut command = Command::new(&ar);
    let objects = from_folder(&mut command, objects);
    finished(command.arg("rcs").arg(library).args(objects).status(), "archiving")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cc_names_a_program_and_what_goes_before_the_rest() {
        assert_eq!(Compiler::named("zig cc"), Compiler::new("zig", &["cc"]));
        assert_eq!(Compiler::named("gcc"), Compiler::new("gcc", &[]));
        // a program that is there stays whole, spaces and all
        let dir = std::env::temp_dir().join(format!("3dsrecomp cc {}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("my cc");
        std::fs::write(&program, b"").unwrap();
        assert_eq!(Compiler::named(program.to_str().unwrap()), Compiler::new(&program, &[]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// a big game's objects link however long their paths are, on Windows
    /// too, where a command line holds 32767 characters.
    #[test]
    fn objects_link_however_long_their_paths_are() {
        let Some(compiler) = Compiler::find() else { return };
        let folder = format!("3dsrecomp {}{}", "a folder with a long name ".repeat(3), std::process::id());
        let dir = std::env::temp_dir().join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        let sources: Vec<String> = (0..400).map(|i| format!("code{i:03}.c")).collect();
        for (i, source) in sources.iter().enumerate() {
            std::fs::write(dir.join(source), format!("int f{i}(void) {{ return {i}; }}\n")).unwrap();
        }
        let length: usize = sources.iter().map(|source| dir.join(source).with_extension("o").as_os_str().len() + 1).sum();
        assert!(length > 32_767, "the whole paths would not fit on a command line on Windows");
        let library = dir.join(if cfg!(windows) { "many.dll" } else { "libmany.so" });
        compile(&compiler, &dir, &sources, &library, &|_, _| true, false).unwrap();
        assert!(library.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_compiler_that_does_not_run_is_turned_down() {
        let error = check(Some(&Compiler::new("/nowhere/cc", &[]))).unwrap_err();
        assert!(error.starts_with("there is no C compiler (/nowhere/cc)"), "{error}");
    }
}
