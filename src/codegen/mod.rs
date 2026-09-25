//! turning the functions discovery found into C.
//!
//! every function becomes a C function that can be entered at any of its
//! labels. guest calls are C calls, and anything the code cannot follow on
//! its own, an svc, an unknown target, a full budget, returns all the way
//! out to the host, which picks up again from r15.

mod arm;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::discover::{Analysis, Function, Mode, Program};

pub const HEADER: &str = include_str!("recomp.h");

/// what the lowering of one instruction may refer to.
pub struct Scope<'a> {
    /// the labels of the function being written.
    pub labels: &'a BTreeSet<u32>,
    /// the functions written as C, by entry.
    pub functions: &'a BTreeSet<u32>,
}

/// instructions per source file, so the files compile in parallel.
const FILE_SIZE: usize = 20_000;

const PRELUDE: &str = "#include \"recomp.h\"\n#include \"functions.h\"\n\n";

/// whether a function becomes C. Thumb is left to the interpreter for now,
/// and so is any entry that turned out not to be code.
pub fn recompiles(entry: u32, function: &Function) -> bool {
    function.mode == Mode::Arm && function.labels.contains(&entry)
}

/// the C sources for a program, as file names and contents.
pub fn generate(program: &Program, analysis: &Analysis) -> Vec<(String, String)> {
    let functions: BTreeMap<u32, &Function> =
        analysis.functions.iter().filter(|&(&entry, f)| recompiles(entry, f)).map(|(&entry, f)| (entry, f)).collect();
    let names: BTreeSet<u32> = functions.keys().copied().collect();

    let mut files = vec![("recomp.h".to_owned(), HEADER.to_owned())];
    let mut prototypes = String::new();
    for address in &names {
        writeln!(prototypes, "void f_{address:08X}(Context *ctx);").unwrap();
    }
    files.push(("functions.h".to_owned(), prototypes));

    let mut source = String::new();
    let mut size = 0;
    let mut count = 0;
    for (&address, function) in &functions {
        if source.is_empty() {
            source.push_str(PRELUDE);
        }
        write_function(&mut source, program, &names, address, function);
        size += function.instructions.len();
        if size >= FILE_SIZE {
            files.push((format!("code{count:03}.c"), std::mem::take(&mut source)));
            size = 0;
            count += 1;
        }
    }
    if !source.is_empty() {
        files.push((format!("code{count:03}.c"), source));
    }

    // every label the host can resume at, preferring the function that
    // starts there
    let mut entries: BTreeMap<u32, u32> = BTreeMap::new();
    for (&address, function) in &functions {
        for &label in &function.labels {
            let owner = entries.entry(label).or_insert(address);
            if label == address {
                *owner = address;
            }
        }
    }
    let mut table = String::from(PRELUDE);
    writeln!(table, "RECOMP_EXPORT const uint32_t recomp_abi = RECOMP_ABI;").unwrap();
    writeln!(table, "RECOMP_EXPORT const uint32_t recomp_entry_count = {};", entries.len()).unwrap();
    writeln!(table, "RECOMP_EXPORT const Entry recomp_entries[] = {{").unwrap();
    for (label, owner) in entries {
        writeln!(table, "    {{0x{label:08X}u, f_{owner:08X}}},").unwrap();
    }
    table.push_str("};\n");
    files.push(("entries.c".to_owned(), table));
    files
}

fn write_function(out: &mut String, program: &Program, names: &BTreeSet<u32>, entry: u32, function: &Function) {
    let scope = Scope { labels: &function.labels, functions: names };
    writeln!(out, "void f_{entry:08X}(Context *ctx) {{").unwrap();
    writeln!(out, "    uint32_t target = ctx->r[15];").unwrap();
    writeln!(out, "    if (LIKELY(target == 0x{entry:08X}u && !ctx->thumb)) goto L_{entry:08X};").unwrap();
    writeln!(out, "dispatch:").unwrap();
    writeln!(out, "    if (!ctx->thumb) switch (target) {{").unwrap();
    for label in &function.labels {
        writeln!(out, "    case 0x{label:08X}u: goto L_{label:08X};").unwrap();
    }
    writeln!(out, "    }}").unwrap();
    // somewhere else, the host knows where
    writeln!(out, "    ctx->r[15] = target;").unwrap();
    writeln!(out, "    CALL(recomp_call);").unwrap();
    writeln!(out, "    return;").unwrap();

    let instructions = &function.instructions;
    for (i, &address) in instructions.iter().enumerate() {
        if function.labels.contains(&address) {
            let run = instructions[i + 1..].iter().take_while(|a| !function.labels.contains(a)).count() + 1;
            writeln!(out, "L_{address:08X}:").unwrap();
            writeln!(out, "    BUDGET(0x{address:08X}u, {run});").unwrap();
        }
        let op = program.text.read32(address).unwrap_or(0);
        writeln!(out, "    /* {address:08X} {op:08X} */").unwrap();
        let continues = arm::lower(out, &scope, address, op);
        let next = address + 4;
        if continues && instructions.get(i + 1) != Some(&next) {
            writeln!(out, "    target = 0x{next:08X}u; goto dispatch;").unwrap();
        }
    }
    writeln!(out, "}}\n").unwrap();
}
