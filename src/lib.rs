//! 3dsrecomp as a library, for tools that find a 3DS title's code or
//! recompile it themselves.
//!
//! rom reads the title, discover finds its functions, codegen writes them as
//! C against recomp.h and compile builds that into a shared library. abi,
//! with the host feature, loads such a library from Rust.
//!
//! ```no_run
//! let title = recomp3ds::rom::Title::load("game.3ds")?;
//! for (name, program) in recomp3ds::programs(&title)? {
//!     let analysis = recomp3ds::discover::analyze(&program);
//!     println!("{name}, {} functions", analysis.functions.len());
//! }
//! # Ok::<(), recomp3ds::rom::Error>(())
//! ```

#[cfg(feature = "host")]
pub mod abi;
mod arm;
pub mod codegen;
pub mod compile;
pub mod cro;
pub mod discover;
pub mod image;
pub mod rom;
mod thumb;
#[cfg(feature = "verify")]
pub mod verify;

use discover::Program;
use rom::{DirEntry, Error, FileEntry, RomFs, Title};

/// the title's programs, the executable first and then its modules, each
/// named and ready for discovery.
pub fn programs(title: &Title) -> Result<Vec<(String, Program)>, Error> {
    let image = image::Image::from_title(title)?;
    let files = module_files(title);
    let crs = static_module(title);
    let exports = crs.as_ref().map(|module| module.code_exports()).unwrap_or_default();
    let imported_from_executable = crs.as_ref().map(|module| imported(&files, crs.as_ref(), module)).unwrap_or_default();
    let mut programs = vec![("executable".to_owned(), image.into_program(&exports, &imported_from_executable))];
    programs.extend(files.iter().filter_map(|(module, bytes)| {
        Some((module.name.clone(), module.program(bytes, &imported(&files, crs.as_ref(), module))?))
    }));
    Ok(programs)
}

/// the code addresses in module that the other modules, and the executable
/// through its crs, take from it without a name, which nothing else may lead
/// to.
pub fn imported(files: &[(cro::Module, Vec<u8>)], crs: Option<&cro::Module>, module: &cro::Module) -> Vec<u32> {
    files
        .iter()
        .map(|(other, _)| other)
        .chain(crs)
        .flat_map(|other| &other.anonymous_imports)
        .filter(|(name, _)| *name == module.name)
        .filter_map(|&(_, tag)| module.code_address(tag))
        .collect()
}

/// the main executable's module description, the static.crs every title
/// carries in its RomFS.
pub fn static_module(title: &Title) -> Option<cro::Module> {
    let romfs = title.romfs.as_ref()?;
    let file = romfs.lookup("static.crs").ok()?;
    cro::parse(&title.read_romfs(&file, 0, file.data_size as usize)?)
}

/// every CRO module in the RomFS with its file.
pub fn module_files(title: &Title) -> Vec<(cro::Module, Vec<u8>)> {
    let Some(romfs) = &title.romfs else { return Vec::new() };
    let mut files = Vec::new();
    if let Ok(root) = romfs.root() {
        find_modules(romfs, &root, &mut files);
    }
    files
        .into_iter()
        .filter_map(|file| {
            let bytes = title.read_romfs(&file, 0, file.data_size as usize)?;
            Some((cro::parse(&bytes)?, bytes))
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
