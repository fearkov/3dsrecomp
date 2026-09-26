//! 3dsrecomp, a static recompiler for 3DS titles built on the Zakuro runtime.
//!
//! analyze reports how much of a title's code a generic pass can discover
//! on its own, build turns what it found into C and compiles it into a
//! library the emulator can load.

mod abi;
mod arm;
mod codegen;
mod compile;
mod cro;
mod discover;
mod image;
mod thumb;
mod verify;

use std::path::Path;
use std::process::exit;

use discover::{Analysis, Byte, Mode, Program, Source};
use zakuro_fs::Title;
use zakuro_fs::romfs::{DirEntry, FileEntry, RomFs};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["analyze", rom] => analyze(rom),
        ["build", rom, dir] => build(rom, Path::new(dir)),
        ["verify", rom, library] => check(rom, Path::new(library), 500),
        ["verify", rom, library, count] => check(rom, Path::new(library), count.parse().unwrap_or(500)),
        _ => {
            eprintln!("usage, 3dsrecomp analyze <rom>, build <rom> <dir> or verify <rom> <library> [count]");
            exit(2);
        }
    }
}

/// the title and its programs, the executable first and then its modules.
fn load(path: &str) -> (Title, Vec<(String, Program)>) {
    let title = Title::load(path).unwrap_or_else(|error| {
        eprintln!("could not load {path}, {error}");
        exit(1);
    });
    let image = image::Image::from_title(&title).unwrap_or_else(|error| {
        eprintln!("could not read the code, {error}");
        exit(1);
    });
    let files = module_files(&title);
    let crs = static_module(&title);
    let exports = crs.as_ref().map(|module| module.code_exports()).unwrap_or_default();
    let imported_from_executable = crs.as_ref().map(|module| imported(&files, module)).unwrap_or_default();
    let mut programs = vec![("executable".to_owned(), image.into_program(&exports, &imported_from_executable))];
    programs.extend(
        files
            .iter()
            .filter_map(|(module, bytes)| Some((module.name.clone(), module.program(bytes, &imported(&files, module))?))),
    );
    (title, programs)
}

/// the code addresses in module that other modules take from it without a
/// name, which nothing else may lead to.
fn imported(files: &[(cro::Module, Vec<u8>)], module: &cro::Module) -> Vec<u32> {
    files
        .iter()
        .flat_map(|(other, _)| &other.anonymous_imports)
        .filter(|(name, _)| *name == module.name)
        .filter_map(|&(_, tag)| module.code_address(tag))
        .collect()
}

fn build(path: &str, dir: &Path) {
    let (title, programs) = load(path);
    let analyses: Vec<Analysis> = programs.iter().map(|(_, program)| discover::analyze(program)).collect();
    let units: Vec<codegen::Unit> = programs
        .iter()
        .zip(&analyses)
        .enumerate()
        .map(|(i, ((name, program), analysis))| codegen::Unit {
            module: (i > 0).then_some(name.as_str()),
            program,
            analysis,
        })
        .collect();
    let files = codegen::generate(&units);

    if let Err(error) = std::fs::create_dir_all(dir) {
        eprintln!("could not create {}, {error}", dir.display());
        exit(1);
    }
    for (name, contents) in &files {
        if let Err(error) = std::fs::write(dir.join(name), contents) {
            eprintln!("could not write {name}, {error}");
            exit(1);
        }
    }
    let size: usize = files.iter().map(|(_, contents)| contents.len()).sum();
    println!("wrote {} files, {} MiB of C", files.len(), size >> 20);

    let sources: Vec<String> = files.iter().map(|(name, _)| name.clone()).filter(|name| name.ends_with(".c")).collect();
    let library = dir.join(format!("{:016X}.so", title.program_id()));
    let start = std::time::Instant::now();
    if let Err(error) = compile::compile(dir, &sources, &library) {
        eprintln!("{error}");
        exit(1);
    }
    println!("built {} in {:.1?}", library.display(), start.elapsed());
}

/// runs up to count of the recompiled functions of each program against
/// the interpreter, the modules one at a time, each loaded at the same place.
fn check(path: &str, library: &Path, count: usize) {
    let (title, programs) = load(path);
    let library = abi::Library::open(library).unwrap_or_else(|error| {
        eprintln!("could not open {}, {error}", library.display());
        exit(1);
    });
    let image = image::Image::from_title(&title).unwrap_or_else(|error| {
        eprintln!("could not read the code, {error}");
        exit(1);
    });
    let regions = verify::regions(
        (image.text.base, &image.text.bytes),
        (image.rodata.base, &image.rodata.bytes),
        (image.data.base, &image.data.bytes),
        title.exheader.bss_size,
    );
    let start = std::time::Instant::now();

    let executable = verify::verify(
        "executable",
        &verify::Memory::new(regions.clone()),
        &library,
        &sample(&discover::analyze(&programs[0].1), 0, count),
    );
    print_report("executable", &executable);

    let mut modules = verify::Report::default();
    let files = module_files(&title);
    for (module, bytes) in &files {
        let Some(index) = library.modules().iter().position(|m| m.name() == module.name) else { continue };
        let Some(program) = module.program(bytes, &imported(&files, module)) else { continue };
        let mut memory = regions.clone();
        memory.push(verify::Region {
            base: verify::MODULE_BASE,
            bytes: module.image(bytes, verify::MODULE_BASE, verify::IMPORT_STUB),
            writable: true,
        });
        library.place(index, verify::MODULE_BASE);
        let report = verify::verify(
            &module.name,
            &verify::Memory::new(memory),
            &library,
            &sample(&discover::analyze(&program), verify::MODULE_BASE, count),
        );
        library.place(index, 0);
        modules.add(&report);
    }
    print_report("modules", &modules);
    println!("took {:.1?}", start.elapsed());
}

/// up to count of the functions that became C, spread over the program, as
/// addresses at base with bit 0 set for Thumb.
fn sample(analysis: &Analysis, base: u32, count: usize) -> Vec<u32> {
    let functions: Vec<u32> = analysis
        .functions
        .iter()
        .filter(|&(&entry, f)| codegen::recompiles(entry, f))
        .map(|(&entry, f)| (base + entry) | (f.mode == Mode::Thumb) as u32)
        .collect();
    // VERIFY_ONLY=address checks that one function alone
    if let Some(only) = std::env::var("VERIFY_ONLY").ok().and_then(|v| u32::from_str_radix(&v, 16).ok()) {
        return functions.into_iter().filter(|&f| f == only).collect();
    }
    let step = (functions.len() / count.max(1)).max(1);
    functions.into_iter().step_by(step).take(count).collect()
}

fn print_report(name: &str, report: &verify::Report) {
    println!(
        "{name:<11} {} functions, {} returned, {} reached an svc, {} stuck, {} stopped otherwise, {} mismatched",
        report.tested, report.returned, report.svc, report.stuck, report.other, report.mismatched
    );
    println!(
        "{:<11} instructions {} recompiled, {} through the fallback, {} interpreted alone",
        "", report.native, report.fallbacks, report.interpreted
    );
}

fn analyze(path: &str) {
    let (title, programs) = load(path);
    let module_count = programs.len() - 1;
    let start = std::time::Instant::now();
    let analyses: Vec<Analysis> = programs.iter().map(|(_, program)| discover::analyze(program)).collect();
    let elapsed = start.elapsed();

    println!("title       {}, {} modules", title.exheader.title, module_count);
    println!();
    println!("                  KiB  functions   code  literals  unreached  indirect  switches    svc  dead ends");
    let executable = Totals::of(&analyses[0]);
    let modules = analyses[1..].iter().map(Totals::of).fold(Totals::default(), Totals::add);
    executable.print("executable");
    modules.print("modules");
    executable.add(modules).print("all");
    println!();

    let functions = || analyses.iter().flat_map(|analysis| analysis.functions.values());
    let from = |source: Source| functions().filter(|f| f.source == source).count();
    println!(
        "found by    {} calls, {} pointers, {} relocations, {} exports, {} imports, {} entry",
        from(Source::Call),
        from(Source::Pointer),
        from(Source::Relocation),
        from(Source::Export),
        from(Source::Import),
        from(Source::Entry)
    );
    let thumb = functions().filter(|f| f.mode == Mode::Thumb).count();
    let instructions: usize = functions().map(|f| f.instructions.len()).sum();
    println!("thumb       {thumb} functions");
    println!("decoded     {instructions} instructions, shared code once per function");
    println!("analysis    {elapsed:.2?}");
    println!();

    println!("largest unreached runs");
    let mut gaps: Vec<_> = programs
        .iter()
        .zip(&analyses)
        .flat_map(|((name, program), analysis)| {
            analysis.largest_gaps(program.text.base, 8).into_iter().map(move |(start, length)| (name, start, length))
        })
        .collect();
    gaps.sort_by_key(|gap| std::cmp::Reverse(gap.2));
    for (name, start, length) in gaps.into_iter().take(10) {
        println!("  {name:<28} 0x{start:08X}  {length} bytes");
    }
}

/// the numbers the report shows for a program, or for several added up.
#[derive(Default, Clone, Copy)]
struct Totals {
    text: usize,
    functions: usize,
    code: usize,
    literal: usize,
    indirect: usize,
    switches: usize,
    svc: usize,
    dead_ends: usize,
}

impl Totals {
    fn of(analysis: &Analysis) -> Totals {
        Totals {
            text: analysis.map.len(),
            functions: analysis.functions.len(),
            code: analysis.count(Byte::Code),
            literal: analysis.count(Byte::Literal),
            indirect: analysis.indirect_sites,
            switches: analysis.jump_tables,
            svc: analysis.svc_sites,
            dead_ends: analysis.dead_ends,
        }
    }

    fn add(self, other: Totals) -> Totals {
        Totals {
            text: self.text + other.text,
            functions: self.functions + other.functions,
            code: self.code + other.code,
            literal: self.literal + other.literal,
            indirect: self.indirect + other.indirect,
            switches: self.switches + other.switches,
            svc: self.svc + other.svc,
            dead_ends: self.dead_ends + other.dead_ends,
        }
    }

    fn print(&self, name: &str) {
        let percent = |bytes: usize| bytes as f64 * 100.0 / self.text.max(1) as f64;
        let unreached = self.text - self.code - self.literal;
        println!(
            "{name:<12} {:>9} {:>10} {:>5.1}% {:>8.1}% {:>9.1}% {:>9} {:>9} {:>6} {:>10}",
            self.text / 1024,
            self.functions,
            percent(self.code),
            percent(self.literal),
            percent(unreached),
            self.indirect,
            self.switches,
            self.svc,
            self.dead_ends
        );
    }
}

/// the main executable's module description, the static.crs every title
/// carries in its RomFS.
fn static_module(title: &Title) -> Option<cro::Module> {
    let romfs = title.romfs.as_ref()?;
    let file = romfs.lookup("static.crs").ok()?;
    cro::parse(title.read_romfs(&file, 0, file.data_size as usize)?)
}

/// every CRO module in the RomFS with its file.
fn module_files(title: &Title) -> Vec<(cro::Module, Vec<u8>)> {
    let Some(romfs) = &title.romfs else { return Vec::new() };
    let mut files = Vec::new();
    if let Ok(root) = romfs.root() {
        find_modules(romfs, &root, &mut files);
    }
    files
        .into_iter()
        .filter_map(|file| {
            let bytes = title.read_romfs(&file, 0, file.data_size as usize)?;
            Some((cro::parse(bytes)?, bytes.to_vec()))
        })
        .collect()
}

fn find_modules(romfs: &RomFs, dir: &DirEntry, files: &mut Vec<FileEntry>) {
    for (_, file) in romfs.files(dir) {
        if file.name.to_ascii_lowercase().ends_with(".cro") {
            files.push(file);
        }
    }
    for (_, subdir) in romfs.subdirs(dir) {
        find_modules(romfs, &subdir, files);
    }
}
