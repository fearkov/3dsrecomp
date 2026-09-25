//! 3dsrecomp, a static recompiler for 3DS titles built on the Zakuro runtime.
//!
//! for now it only analyzes, finding how much of a title's code a generic
//! pass can discover on its own.

mod arm;
mod cro;
mod discover;
mod image;
mod thumb;

use discover::{Analysis, Byte, Mode, Program, Source};
use zakuro_fs::Title;
use zakuro_fs::romfs::{DirEntry, FileEntry, RomFs};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(command), Some(path)) = (args.next(), args.next()) else {
        eprintln!("usage, 3dsrecomp analyze <rom>");
        std::process::exit(2);
    };
    if command != "analyze" {
        eprintln!("unknown command {command}");
        std::process::exit(2);
    }

    let title = match Title::load(&path) {
        Ok(title) => title,
        Err(error) => {
            eprintln!("could not load {path}, {error}");
            std::process::exit(1);
        }
    };
    let image = match image::Image::from_title(&title) {
        Ok(image) => image,
        Err(error) => {
            eprintln!("could not read the code, {error}");
            std::process::exit(1);
        }
    };

    let exports = static_module(&title).map(|module| module.code_exports()).unwrap_or_default();
    let mut programs = vec![("executable".to_owned(), image.into_program(&exports))];
    let modules = modules(&title);
    let module_count = modules.len();
    programs.extend(modules);

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
        "found by    {} calls, {} pointers, {} relocations, {} exports, {} entry",
        from(Source::Call),
        from(Source::Pointer),
        from(Source::Relocation),
        from(Source::Export),
        from(Source::Entry)
    );
    let thumb = functions().filter(|f| f.mode == Mode::Thumb).count();
    let instructions: usize = functions().map(|f| f.instructions).sum();
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

/// every CRO module in the RomFS, by file name.
fn modules(title: &Title) -> Vec<(String, Program)> {
    let Some(romfs) = &title.romfs else { return Vec::new() };
    let mut files = Vec::new();
    if let Ok(root) = romfs.root() {
        find_modules(romfs, &root, &mut files);
    }
    files
        .into_iter()
        .filter_map(|file| {
            let bytes = title.read_romfs(&file, 0, file.data_size as usize)?;
            let program = cro::parse(bytes)?.program(bytes)?;
            Some((file.name, program))
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
