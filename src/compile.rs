//! compiling the generated C into a shared library, one compiler per core.

use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// floating point has to round exactly the way the interpreter does, so
/// nothing may be fused into a multiply-add.
const FLAGS: &[&str] = &["-O2", "-fPIC", "-fvisibility=hidden", "-ffp-contract=off", "-fno-math-errno", "-w"];

/// compiles sources, file names inside dir, and links them into library.
pub fn compile(dir: &Path, sources: &[String], library: &Path) -> Result<(), String> {
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                while let Some(source) = sources.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let path = dir.join(source);
                    let status = Command::new(&compiler)
                        .args(FLAGS)
                        .arg("-c")
                        .arg(&path)
                        .arg("-o")
                        .arg(path.with_extension("o"))
                        .status();
                    if !status.is_ok_and(|s| s.success()) {
                        failures.lock().unwrap().push(source.clone());
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    if !failures.is_empty() {
        return Err(format!("{} failed to compile, {}", failures.len(), failures.join(" ")));
    }

    let objects = sources.iter().map(|source| dir.join(source).with_extension("o"));
    let status = Command::new(&compiler).arg("-shared").arg("-o").arg(library).args(objects).status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err("linking failed".to_owned()),
    }
}
