//! recompiling a title from end to end, writing the C, compiling it and
//! installing the library, for the command line and for programs that run
//! it themselves and follow it through its events.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::discover::{self, Analysis, Mode, Program, Source};
use crate::overrides::{self, Override};
use crate::rom::Title;
use crate::{abi, codegen, compile, Mods};

/// what happens along the way.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// the C is written.
    Generated { files: usize, bytes: usize, overrides: usize },
    /// something worth knowing that does not stop it.
    Note(String),
    Compiled { done: usize, total: usize },
    /// the library is linked.
    Built { library: PathBuf, took: Duration },
    Installed(PathBuf),
}

/// what a build is to do.
#[derive(Default)]
pub struct Options<'a> {
    /// where to work, the cache when none, and then the library gets
    /// installed where hosts find it.
    pub dir: Option<&'a Path>,
    /// C files of functions written by hand, see docs/overrides.md.
    pub overrides: Option<&'a Path>,
    /// set from elsewhere to stop it.
    pub cancel: Option<&'a AtomicBool>,
    /// the code and modules a mod changes, recompiled in place of the
    /// title's own.
    pub mods: Mods<'a>,
    /// the C compiler, the one CC names or the first there is when none.
    pub compiler: Option<compile::Compiler>,
    /// compile below normal priority and leave a core, for a game being
    /// played meanwhile.
    pub background: bool,
}

/// the title's code written as C.
pub struct Generated {
    pub title: Title,
    pub dir: PathBuf,
    /// the files to compile, names inside dir.
    pub sources: Vec<String>,
}

/// writes the title at rom as C in the dir pick chooses, the overrides with
/// it, and what the mods change in place of the title's own code and files.
pub fn generate(
    rom: &Path,
    pick: impl FnOnce(&Title) -> PathBuf,
    overrides: Option<&Path>,
    mods: Mods,
    events: &(dyn Fn(Event) + Sync),
) -> Result<Generated, String> {
    let title = Title::load(rom).map_err(|error| format!("could not load {}, {error}", rom.display()))?;
    let mut programs = crate::programs(&title, mods).map_err(|error| format!("could not read the code, {error}"))?;
    let dir = pick(&title);
    let files = match overrides {
        Some(path) => overrides::load(path)?,
        None => Vec::new(),
    };
    let replaced: Vec<Override> = files.iter().flat_map(|file| file.overrides.iter().cloned()).collect();
    // whatever an override replaces has to be generated too, for it to call
    for item in &replaced {
        let name = item.module.as_deref().unwrap_or("executable");
        let Some((_, program)) = programs.iter_mut().find(|(program, _)| program == name) else {
            return Err(format!("the title has no module called {name}"));
        };
        program.seeds.insert(0, (item.address, Source::Override));
    }

    let mut analyses: Vec<Analysis> = programs.iter().map(|(_, program)| discover::analyze(program)).collect();
    let functions = apply_hints(&title, &mut programs, &mut analyses);
    if functions > 0 {
        events(Event::Note(format!("{functions} of the places Zakuro interpreted start new functions")));
    }
    for item in &replaced {
        let index = programs.iter().position(|(name, _)| Some(name.as_str()) == item.module.as_deref()).unwrap_or(0);
        let thumb = item.address & 1 != 0;
        let found = analyses[index]
            .functions
            .values()
            .any(|f| (f.mode == Mode::Thumb) == thumb && f.labels.contains(&(item.address & !1)));
        if !found {
            events(Event::Note(format!(
                "no code at 0x{:08X} for {} to replace, so it cannot call the original",
                item.address, item.name
            )));
        }
    }
    let units: Vec<codegen::Unit> = programs
        .iter()
        .zip(&analyses)
        .enumerate()
        .map(|(i, ((name, program), analysis))| codegen::Unit { module: (i > 0).then_some(name.as_str()), program, analysis })
        .collect();
    let generated = codegen::generate(&units, &replaced);

    let write = |path: &Path, contents: &[u8]| {
        std::fs::write(path, contents).map_err(|error| format!("could not write {}, {error}", path.display()))
    };
    let folder = if files.is_empty() { dir.clone() } else { dir.join("hand") };
    std::fs::create_dir_all(&folder).map_err(|error| format!("could not create {}, {error}", folder.display()))?;
    for (name, contents) in &generated {
        write(&dir.join(name), contents.as_bytes())?;
    }
    let mut sources: Vec<String> = generated.iter().map(|(name, _)| name.clone()).filter(|name| name.ends_with(".c")).collect();
    for file in &files {
        let name = format!("hand/{}", file.path.file_name().unwrap_or_default().to_string_lossy());
        write(&dir.join(&name), file.source.as_bytes())?;
        sources.push(name);
    }
    let bytes = generated.iter().map(|(_, contents)| contents.len()).sum();
    events(Event::Generated { files: generated.len(), bytes, overrides: replaced.len() });
    Ok(Generated { title, dir, sources })
}

/// recompiles the title at rom into a library and returns where it ended
/// up, installed when the options name no dir.
pub fn build(rom: &Path, options: &Options, events: &(dyn Fn(Event) + Sync)) -> Result<PathBuf, String> {
    let compiler = compile::check(options.compiler.as_ref())?;
    let stopped = || options.cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed));
    let pick = |title: &Title| options.dir.map(Path::to_owned).unwrap_or_else(|| cache_dir(title.program_id()));
    let generated = generate(rom, pick, options.overrides, options.mods, events)?;
    if stopped() {
        return Err("stopped".to_owned());
    }
    let program_id = generated.title.program_id();
    let library = generated.dir.join(abi::library_name(program_id));
    let start = Instant::now();
    let progress = |done, total| {
        events(Event::Compiled { done, total });
        !stopped()
    };
    compile::compile(&compiler, &generated.dir, &generated.sources, &library, &progress, options.background)?;
    events(Event::Built { library: library.clone(), took: start.elapsed() });
    if options.dir.is_some() {
        return Ok(library);
    }
    let installed = install(&library, program_id)?;
    events(Event::Installed(installed.clone()));
    Ok(installed)
}

/// takes in where the emulator had to interpret the title's last library,
/// which only ever ran code. the places outside the functions found already
/// start functions, found by analyzing the executable again, and says how
/// many. a place inside one adds nothing, discovery already makes a label of
/// every way the code goes in, branch targets and the returns from calls and
/// svcs, while Zakuro used to note where it finished a block the budget did
/// not cover, which as labels split the hot loops into single instructions.
pub fn apply_hints(title: &Title, programs: &mut [(String, Program)], analyses: &mut [Analysis]) -> usize {
    let Some(index) = programs.iter().position(|(name, _)| name == "executable") else { return 0 };
    let program = &mut programs[index].1;
    let text = program.text.base..program.text.end();
    // this player's and everyone's who ran the same code
    let mut hinted = hints(title.program_id());
    hinted.extend(bundled(title.program_id(), code_hash(program)));
    hinted.retain(|&address| text.contains(&(address & !1)));
    hinted.sort_unstable();
    hinted.dedup();
    if hinted.is_empty() {
        return 0;
    }
    let outside = new_functions(&analyses[index], &hinted);
    if !outside.is_empty() {
        program.seeds.extend(outside.iter().map(|&address| (address, Source::Hint)));
        analyses[index] = discover::analyze(program);
    }
    outside.len()
}

/// the hinted places none of the functions the analysis found holds, which
/// start functions of their own, odd for Thumb.
pub fn new_functions(analysis: &Analysis, hinted: &[u32]) -> Vec<u32> {
    let mut owned = std::collections::HashSet::new();
    for function in analysis.functions.values() {
        let thumb = (function.mode == Mode::Thumb) as u32;
        owned.extend(function.instructions.iter().map(|&address| address | thumb));
    }
    hinted.iter().copied().filter(|address| !owned.contains(address)).collect()
}

/// the addresses Zakuro wrote down next to a title's library, those it ran
/// in its interpreter for want of code, odd for Thumb.
pub fn hints(program_id: u64) -> Vec<u32> {
    let Some(dir) = abi::library_dir() else { return Vec::new() };
    let path = dir.join(abi::library_name(program_id)).with_extension("hints");
    std::fs::read_to_string(path).map(|text| read_hints(&text)).unwrap_or_default()
}

/// the addresses in a file of hints.
pub fn read_hints(text: &str) -> Vec<u32> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| u32::from_str_radix(line.trim_start_matches("0x"), 16).ok())
        .collect()
}

/// where players' runs went into code the analysis does not find, gathered
/// from their hints, by game and by the code they are for.
const BUNDLED: &str = include_str!("../hints.txt");

/// a hash of the code of a title's executable, FNV-1a over its bytes, so
/// the hints of one revision or update of a game stay out of another's.
pub fn code_hash(program: &Program) -> u64 {
    program.text.bytes.iter().fold(0xCBF2_9CE4_8422_2325, |hash, &byte| (hash ^ byte as u64).wrapping_mul(0x0100_0000_01B3))
}

/// the hints the list has for a title's code.
pub fn bundled(program_id: u64, hash: u64) -> Vec<u32> {
    section(BUNDLED, program_id, hash)
}

/// the addresses under a list's header for a title's code.
fn section(list: &str, program_id: u64, hash: u64) -> Vec<u32> {
    let mut taking = false;
    let mut found = Vec::new();
    for line in list.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        if let Some(header) = line.strip_prefix('=') {
            let mut fields = header.split_whitespace().map(|field| u64::from_str_radix(field, 16).ok());
            taking = fields.next().flatten() == Some(program_id) && fields.next().flatten() == Some(hash);
        } else if taking {
            found.extend(u32::from_str_radix(line.trim_start_matches("0x"), 16).ok());
        }
    }
    found
}

/// where build works on a title whose library it installs.
pub fn cache_dir(program_id: u64) -> PathBuf {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    let base = if cfg!(windows) {
        var("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|home| home.join("Library/Caches"))
    } else {
        var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|home| home.join(".cache")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("3dsrecomp").join(format!("{program_id:016X}"))
}

/// copies the library to where hosts look for it, under another name first
/// so that a host running the old one keeps it.
pub fn install(library: &Path, program_id: u64) -> Result<PathBuf, String> {
    let dir = abi::library_dir().ok_or("there is no place to install the library")?;
    let target = dir.join(abi::library_name(program_id));
    let partial = target.with_extension(format!("{}.new", std::env::consts::DLL_EXTENSION));
    std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::copy(library, &partial))
        .and_then(|_| step_aside(&target))
        .and_then(|()| std::fs::rename(&partial, &target))
        .map_err(|error| format!("could not install {}, {error}", target.display()))?;
    Ok(target)
}

/// moves the library at target out of the way, when there is one. Windows
/// refuses to replace a library a game being played has loaded, but lets it
/// be renamed, and the game keeps running it until it loads the new one.
/// those moved away earlier go when nothing holds them any more.
fn step_aside(target: &Path) -> std::io::Result<()> {
    if !cfg!(windows) || !target.exists() {
        return Ok(());
    }
    let aside = |n: u32| target.with_extension(format!("{}.old{n}", std::env::consts::DLL_EXTENSION));
    for n in 0..16 {
        // still loaded, or not there
        let _ = std::fs::remove_file(aside(n));
    }
    let free = (0..16).map(aside).find(|path| !path.exists()).unwrap_or_else(|| aside(16));
    std::fs::rename(target, free)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a game's hints in the list go to the code they were gathered on, a
    /// revision or update of it with other code gets none of them.
    #[test]
    fn the_list_gives_hints_to_the_code_they_are_for() {
        let list = "# a note\n= 0004000000033500 00000000000000AB\n00100000\n00100011\n\n= 0004000000033500 00000000000000AC\n00200000\n";
        assert_eq!(section(list, 0x0004_0000_0003_3500, 0xAB), [0x0010_0000, 0x0010_0011]);
        assert_eq!(section(list, 0x0004_0000_0003_3500, 0xAC), [0x0020_0000]);
        assert!(section(list, 0x0004_0000_0003_3600, 0xAB).is_empty());
        assert!(section(list, 0x0004_0000_0003_3500, 0xAD).is_empty());
    }

    #[test]
    fn every_line_of_the_list_reads() {
        for line in BUNDLED.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
            match line.strip_prefix('=') {
                Some(header) => {
                    let fields: Vec<&str> = header.split_whitespace().collect();
                    assert!(fields.len() >= 2, "{line}");
                    assert!(u64::from_str_radix(fields[0], 16).is_ok() && u64::from_str_radix(fields[1], 16).is_ok(), "{line}");
                }
                None => assert!(u32::from_str_radix(line, 16).is_ok(), "{line}"),
            }
        }
    }
    use crate::cro::tests::named;
    use crate::rom::tests::rom;

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// a piece of code as the tables write it, with the hash of its bytes.
    fn piece(start: u32, end: u32, bytes: &[u8]) -> String {
        let mut hash = abi::CodeHash::default();
        hash.add(bytes);
        format!("{{0x{start:08X}u, 0x{end:08X}u, 0x{:016X}ull}},", hash.value())
    }

    /// the code made with a mod's code and modules says it was made from
    /// them, so a host running the mod finds none of it stale.
    #[test]
    fn generating_with_mods_makes_code_of_what_they_change() {
        let (own, modded) = ([0xE3A0_0000, 0xE12F_FF1E], [0xE3A0_0001, 0xE12F_FF1E]);
        let path = rom("generate-mods", &bytes(&own), &[("cro/Battle.cro", &named("Battle", &own))]);
        let dir = std::env::temp_dir().join(format!("3dsrecomp-generate-mods-{}", std::process::id()));
        let (code, module) = (bytes(&modded), named("Battle", &modded));
        let romfs = |path: &str| (path == "cro/Battle.cro").then(|| module.clone());
        let tables = |mods: Mods| {
            generate(&path, |_| dir.clone(), None, mods, &|_| {}).unwrap();
            std::fs::read_to_string(dir.join("entries.c")).unwrap()
        };

        let tables_modded = tables(Mods { code: Some(&code), romfs: Some(&romfs), ..Mods::default() });
        // the executable's function and the module's, a piece each
        assert!(tables_modded.contains(&piece(0x0010_0000, 0x0010_0008, &code)), "{tables_modded}");
        assert!(tables_modded.contains(&piece(0x200, 0x208, &code)), "{tables_modded}");
        let plain = tables(Mods::default());
        assert!(plain.contains(&piece(0x0010_0000, 0x0010_0008, &bytes(&own))), "{plain}");
        assert!(plain.contains(&piece(0x200, 0x208, &bytes(&own))), "{plain}");

        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
