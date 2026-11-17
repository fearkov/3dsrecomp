//! handwritten funcs that run instead of the generated ones, found in C files by the RECOMP_OVERRIDE marks recomp.h gives them

use std::path::{Path, PathBuf};

/// one handwritten func
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// module whose func it replaces, none for the exe
    pub module: Option<String>,
    /// what it replaces, an addr or module offset, odd for Thumb
    pub address: u32,
    /// the C func as the mark names it
    pub name: String,
    /// the name the replaced generated func goes by for it
    pub original: String,
}

/// a C file of overrides
pub struct File {
    pub path: PathBuf,
    pub source: String,
    pub overrides: Vec<Override>,
}

/// the C files at path, a file or a dir of them
pub fn load(path: &Path) -> Result<Vec<File>, String> {
    let paths = if path.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("could not read {}, {e}", path.display()))?;
        let mut paths: Vec<PathBuf> =
            entries.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "c")).collect();
        paths.sort();
        paths
    } else {
        vec![path.to_owned()]
    };
    paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).map_err(|e| format!("could not read {}, {e}", path.display()))?;
            let overrides = parse(&source).map_err(|e| format!("{}, {e}", path.display()))?;
            Ok(File { path, source, overrides })
        })
        .collect()
}

/// the overrides a C source marks
pub fn parse(source: &str) -> Result<Vec<Override>, String> {
    let code = strip_comments(source);
    let mut overrides = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("RECOMP_OVERRIDE") {
        let before = rest[..at].chars().next_back();
        rest = &rest[at + "RECOMP_OVERRIDE".len()..];
        if before.is_some_and(is_identifier) {
            continue;
        }
        let (in_module, after) = match rest.strip_prefix("_IN") {
            Some(after) => (true, after),
            None => (false, rest),
        };
        let Some(after) = after.trim_start().strip_prefix('(') else { continue };
        let Some(end) = after.find(')') else { return Err("a RECOMP_OVERRIDE is not closed".to_owned()) };
        let arguments: Vec<&str> = after[..end].split(',').map(str::trim).collect();
        rest = &after[end..];
        let item = match (in_module, arguments.as_slice()) {
            (false, [literal]) => Override {
                module: None,
                address: number(literal)?,
                name: format!("override_{literal}"),
                original: format!("original_{literal}"),
            },
            (true, [module, literal]) => {
                if module.is_empty() || !module.chars().all(is_identifier) {
                    return Err(format!("{module} is not a module name"));
                }
                Override {
                    module: Some((*module).to_owned()),
                    address: number(literal)?,
                    name: format!("override_{module}_{literal}"),
                    original: format!("original_{module}_{literal}"),
                }
            }
            (true, _) => return Err("RECOMP_OVERRIDE_IN takes a module and an offset".to_owned()),
            (false, _) => return Err("RECOMP_OVERRIDE takes an address".to_owned()),
        };
        if overrides.iter().any(|o: &Override| o.module == item.module && o.address == item.address) {
            return Err(format!("0x{:08X} is overridden twice", item.address));
        }
        overrides.push(item);
    }
    Ok(overrides)
}

fn is_identifier(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// a literal as C writes it, also has to fit in a name
fn number(literal: &str) -> Result<u32, String> {
    let parsed = match literal.strip_prefix("0x").or_else(|| literal.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => literal.parse(),
    };
    match parsed {
        Ok(value) if literal.chars().all(is_identifier) => Ok(value),
        _ => Err(format!("{literal} is not an address")),
    }
}

/// the source w/ comments and string insides blanked out
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if last == '*' && c == '/' {
                        break;
                    }
                    last = c;
                }
                out.push(' ');
            }
            '"' | '\'' => {
                out.push(c);
                while let Some(inner) = chars.next() {
                    if inner == '\\' {
                        chars.next();
                        out.push_str("  ");
                    } else if inner == c {
                        out.push(c);
                        break;
                    } else {
                        out.push(' ');
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_found_outside_comments() {
        let source = r#"
            #include "overrides.h"
            /* RECOMP_OVERRIDE(0x1000) is only an example */
            // RECOMP_OVERRIDE(0x2000) too
            const char *text = "RECOMP_OVERRIDE(0x3000)";
            RECOMP_OVERRIDE(0x0012A4F1) {
                RETURN_TO(ctx->r[14]);
            }
            RECOMP_OVERRIDE_IN(DllField, 0x40) {
                CALL(RECOMP_ORIGINAL_IN(DllField, 0x40));
            }
        "#;
        let overrides = parse(source).unwrap();
        assert_eq!(
            overrides,
            [
                Override {
                    module: None,
                    address: 0x0012_A4F1,
                    name: "override_0x0012A4F1".to_owned(),
                    original: "original_0x0012A4F1".to_owned(),
                },
                Override {
                    module: Some("DllField".to_owned()),
                    address: 0x40,
                    name: "override_DllField_0x40".to_owned(),
                    original: "original_DllField_0x40".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn bad_marks_are_reported() {
        assert!(parse("RECOMP_OVERRIDE(main) {}").is_err());
        assert!(parse("RECOMP_OVERRIDE(0x10) {} RECOMP_OVERRIDE(16) {}").is_err());
        assert!(parse("RECOMP_OVERRIDE_IN(0x10) {}").is_err());
    }
}
