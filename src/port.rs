//! a title made into a program of its own, its recompiled code linked in
//! and Zakuro running everything around it.

use std::path::Path;

const ZAKURO: &str = "https://github.com/fearkov/zakuro";

const MANIFEST: &str = r#"# {title}, recompiled by 3dsrecomp port

[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
zakuro = {zakuro}

# a project of its own, whatever directory it sits in
[workspace]
"#;

const BUILD: &str = r#"use std::env::var;

fn main() {
    let dir = var("CARGO_MANIFEST_DIR").unwrap();
    let family = var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let env = var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    println!("cargo:rerun-if-changed=code/librecomp.a");
    if env == "msvc" {
        // MSVC's linker looks for recomp.lib, the same archive by its name
        let out = var("OUT_DIR").unwrap();
        std::fs::copy(format!("{dir}/code/librecomp.a"), format!("{out}/recomp.lib")).unwrap();
        println!("cargo:rustc-link-search=native={out}");
    } else {
        println!("cargo:rustc-link-search=native={dir}/code");
    }
    println!("cargo:rustc-link-lib=static=recomp");
    if family == "unix" {
        println!("cargo:rustc-link-lib=m");
    }
    // the code runs on the main thread, whose stack is 8 MiB on Linux and
    // 1 MiB on Windows unless it asks for more
    if family == "windows" {
        let stack = 8 << 20;
        match env.as_str() {
            "msvc" => println!("cargo:rustc-link-arg-bins=/STACK:{stack}"),
            _ => println!("cargo:rustc-link-arg-bins=-Wl,--stack,{stack}"),
        }
    }
}
"#;

const MAIN: &str = r#"//! {title}, recompiled ahead of time by 3dsrecomp and run by Zakuro. it
//! still reads the game for everything but the code, so it takes the path
//! to a copy of it the way Zakuro does.

use std::ffi::c_void;
use std::ptr::addr_of;

extern "C" {
    static recomp_abi: u32;
    static recomp_generation: u32;
    static recomp_entry_count: u32;
    static recomp_entries: u8;
    static recomp_module_count: u32;
    static recomp_modules: u8;
    static recomp_origins: u8;
}

fn main() {
    // SAFETY: the tables 3dsrecomp wrote beside the code build.rs links in
    let code = unsafe {
        zakuro::Linked::new(
            0x{program_id},
            recomp_abi,
            addr_of!(recomp_entries) as *const c_void,
            recomp_entry_count,
            addr_of!(recomp_modules) as *const c_void,
            recomp_module_count,
        )
        // so that functions a mod or an update changed run in the interpreter
        .with_origins(recomp_generation, addr_of!(recomp_origins) as *const c_void)
    };
    zakuro::run(Some(code));
}
"#;

/// a name Cargo takes for the program, from the title's.
pub fn package_name(title: &str) -> String {
    let name: String = title
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let name = name.trim_matches('-');
    if name.is_empty() { "title".to_owned() } else { name.to_owned() }
}

/// writes a Cargo project at dir whose program runs the title, with the code
/// build left in dir/code/librecomp.a. zakuro is a checkout to build against
/// instead of the one on GitHub.
pub fn write_project(dir: &Path, name: &str, title: &str, program_id: u64, zakuro: Option<&Path>) -> Result<(), String> {
    let dependency = match zakuro {
        Some(path) => {
            let path = std::fs::canonicalize(path).map_err(|e| format!("could not find {}, {e}", path.display()))?;
            let krate = if path.join("crates/zakuro/Cargo.toml").exists() { path.join("crates/zakuro") } else { path };
            format!("{{ path = \"{}\" }}", krate.display())
        }
        None => format!("{{ git = \"{ZAKURO}\" }}"),
    };
    let manifest = MANIFEST.replace("{title}", title).replace("{name}", name).replace("{zakuro}", &dependency);
    let main = MAIN.replace("{title}", title).replace("{program_id}", &format!("{program_id:016X}"));
    let write = |path: &Path, contents: &str| {
        std::fs::write(path, contents).map_err(|e| format!("could not write {}, {e}", path.display()))
    };
    std::fs::create_dir_all(dir.join("src")).map_err(|e| format!("could not create {}, {e}", dir.display()))?;
    write(&dir.join("Cargo.toml"), &manifest)?;
    write(&dir.join("build.rs"), BUILD)?;
    write(&dir.join("src/main.rs"), &main)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_become_package_names() {
        assert_eq!(package_name("sango-2"), "sango-2");
        assert_eq!(package_name("My Game!"), "my-game");
        assert_eq!(package_name("***"), "title");
    }
}
