//! 3dsrecomp as a library, for tools that find a 3DS title's code or
//! recompile it themselves.
//!
//! rom reads the title, discover finds its functions, codegen writes them as
//! C against recomp.h, with any overrides in place of the functions they
//! replace, and compile builds that into a shared or a static library. port
//! makes a program of a title out of the static one. abi is the interface
//! the code runs against, which loads the shared one from Rust with the
//! host feature. what a mod changes, code and files read in place of the
//! title's own, goes in a Mods.
//!
//! ```no_run
//! let title = recomp3ds::rom::Title::load("game.3ds")?;
//! for (name, program) in recomp3ds::programs(&title, recomp3ds::Mods::default())? {
//!     let analysis = recomp3ds::discover::analyze(&program);
//!     println!("{name}, {} functions", analysis.functions.len());
//! }
//! # Ok::<(), recomp3ds::rom::Error>(())
//! ```

pub use recomp_abi as abi;
mod arm;
pub mod build;
pub mod codegen;
pub mod compile;
pub mod cro;
pub mod discover;
pub mod image;
pub mod overrides;
pub mod port;
pub mod rom;
mod thumb;
#[cfg(feature = "verify")]
pub mod verify;

use discover::Program;
use rom::{DirEntry, Error, FileEntry, RomFs, Title};

/// what a mod changes in a title, read in place of the title's own code and
/// files. the default changes nothing.
#[derive(Clone, Copy, Default)]
pub struct Mods<'a> {
    /// the executable's code, decompressed, its segments one after another
    /// the way the title's own has them, or the way exheader says.
    pub code: Option<&'a [u8]>,
    /// the extended header the mod gives in place of the title's, at least
    /// its first 0x400 bytes, which says where the segments of code lie
    /// when the mod's code moves them.
    pub exheader: Option<&'a [u8]>,
    /// the RomFS files the mod replaces. the modules and static.crs are
    /// read through it, by their paths from the RomFS's root, / separated
    /// and spelled the way the title has them, like static.crs or
    /// cro/Battle.cro.
    pub romfs: Option<Files<'a>>,
}

/// the bytes that replace the RomFS file at a path, None to keep the
/// title's.
pub type Files<'a> = &'a (dyn Fn(&str) -> Option<Vec<u8>> + Sync);

impl Mods<'_> {
    /// the RomFS file at path, the bytes given in its place or else the
    /// title's.
    fn read(&self, title: &Title, path: &str, file: &FileEntry) -> Option<Vec<u8>> {
        self.romfs.and_then(|romfs| romfs(path)).or_else(|| title.read_romfs(file, 0, file.data_size as usize))
    }
}

/// the title's programs, the executable first and then its modules, each
/// named and ready for discovery, made from what mods change in place of
/// the title's own.
pub fn programs(title: &Title, mods: Mods) -> Result<Vec<(String, Program)>, Error> {
    let image = match mods.code {
        Some(code) => {
            let exheader = mods.exheader.filter(|ex| ex.len() >= 0x400).map(rom::ExHeader::read);
            image::Image::from_code(exheader.as_ref().unwrap_or(&title.exheader), code)
        }
        None => image::Image::from_title(title)?,
    };
    let files = module_files(title, mods);
    let crs = static_module(title, mods);
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
/// carries in its RomFS, or the one a mod gives in its place.
pub fn static_module(title: &Title, mods: Mods) -> Option<cro::Module> {
    let romfs = title.romfs.as_ref()?;
    let file = romfs.lookup("static.crs").ok()?;
    cro::parse(&mods.read(title, "static.crs", &file)?)
}

/// every CRO module in the RomFS with its file, the one a mod gives in its
/// place when it gives one.
pub fn module_files(title: &Title, mods: Mods) -> Vec<(cro::Module, Vec<u8>)> {
    let Some(romfs) = &title.romfs else { return Vec::new() };
    let mut files = Vec::new();
    if let Ok(root) = romfs.root() {
        find_modules(romfs, &root, "", &mut files);
    }
    files
        .into_iter()
        .filter_map(|(path, file)| {
            let bytes = mods.read(title, &path, &file)?;
            Some((cro::parse(&bytes)?, bytes))
        })
        .collect()
}

/// the CRO files in dir and in the folders in it, with their paths, path
/// being dir's.
fn find_modules(romfs: &RomFs, dir: &DirEntry, path: &str, files: &mut Vec<(String, FileEntry)>) {
    for (_, file) in romfs.files(dir) {
        if file.name.to_ascii_lowercase().ends_with(".cro") {
            files.push((join(path, &file.name), file));
        }
    }
    for (_, subdir) in romfs.subdirs(dir) {
        find_modules(romfs, &subdir, &join(path, &subdir.name), files);
    }
}

/// the path of name in the folder at path. paths skip the nameless
/// folders, the root and the one some titles keep everything in.
fn join(path: &str, name: &str) -> String {
    if path.is_empty() || name.is_empty() {
        format!("{path}{name}")
    } else {
        format!("{path}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cro::tests::named;
    use crate::rom::tests::rom;

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn the_executable_is_made_of_the_code_a_mod_gives() {
        let (own, modded) = (bytes(&[0xE3A0_0000, 0xE12F_FF1E]), bytes(&[0xE3A0_0001, 0xE12F_FF1E]));
        let path = rom("code-mod", &own, &[]);
        let title = Title::load(&path).unwrap();
        let text = |mods: Mods| programs(&title, mods).unwrap()[0].1.text.bytes.clone();
        assert_eq!(text(Mods::default()), own);
        assert_eq!(text(Mods { code: Some(&modded), ..Mods::default() }), modded);
        drop(title);
        std::fs::remove_file(path).unwrap();
    }

    /// a mod that makes the code longer gives an exheader saying so, and
    /// its text is all of it, where the title's own exheader would cut it.
    #[test]
    fn a_mods_exheader_says_how_much_of_its_code_is_text() {
        let own = bytes(&[0xE3A0_0000, 0xE12F_FF1E]);
        let longer = bytes(&[0xE3A0_0000, 0xE12F_FF1E, 0xE12F_FF1E]);
        let path = rom("exheader-mod", &own, &[]);
        let title = Title::load(&path).unwrap();
        let mut exheader = vec![0; 0x400];
        exheader[0x10..0x1C].copy_from_slice(&[0x0010_0000u32, 1, 12].map(u32::to_le_bytes).concat());
        let text = |mods: Mods| programs(&title, mods).unwrap()[0].1.text.bytes.clone();
        assert_eq!(text(Mods { code: Some(&longer), ..Mods::default() }), own);
        assert_eq!(text(Mods { code: Some(&longer), exheader: Some(&exheader), ..Mods::default() }), longer);
        drop(title);
        std::fs::remove_file(path).unwrap();
    }

    /// the modules and the static module a mod replaces come from it, asked
    /// for by their paths, and the rest from the title.
    #[test]
    fn the_modules_a_mod_replaces_come_from_it() {
        let (own, modded) = ([0xE3A0_0000, 0xE12F_FF1E], [0xE3A0_0001, 0xE12F_FF1E]);
        let files: [(&str, &[u8]); 3] = [
            ("static.crs", &named("|static|", &[])),
            ("cro/Battle.cro", &named("Battle", &own)),
            ("cro/Field.cro", &named("Field", &[0xE12F_FF1E])),
        ];
        let path = rom("module-mod", &bytes(&own), &files);
        let title = Title::load(&path).unwrap();
        let (battle, crs) = (named("Battle", &modded), named("|modded|", &[]));
        let asked = std::sync::Mutex::new(Vec::new());
        let romfs = |path: &str| {
            asked.lock().unwrap().push(path.to_owned());
            match path {
                "cro/Battle.cro" => Some(battle.clone()),
                "static.crs" => Some(crs.clone()),
                _ => None,
            }
        };
        let text = |mods: Mods, module: &str| {
            let programs = programs(&title, mods).unwrap();
            programs.into_iter().find(|(name, _)| name == module).unwrap().1.text.bytes
        };
        let mods = Mods { romfs: Some(&romfs), ..Mods::default() };
        assert_eq!(text(mods, "Battle"), bytes(&modded));
        assert_eq!(text(mods, "Field"), bytes(&[0xE12F_FF1E]));
        assert_eq!(static_module(&title, mods).unwrap().name, "|modded|");
        assert_eq!(text(Mods::default(), "Battle"), bytes(&own));
        assert_eq!(static_module(&title, Mods::default()).unwrap().name, "|static|");
        let asked = asked.into_inner().unwrap();
        for path in ["static.crs", "cro/Battle.cro", "cro/Field.cro"] {
            assert!(asked.iter().any(|asked| asked == path), "{path} in {asked:?}");
        }
        drop(title);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn paths_leave_out_the_nameless_folders() {
        assert_eq!(join("", ""), "");
        assert_eq!(join("", "cro"), "cro");
        assert_eq!(join("cro", ""), "cro");
        assert_eq!(join("cro", "Battle.cro"), "cro/Battle.cro");
    }
}
