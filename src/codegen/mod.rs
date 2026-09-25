//! turning the functions discovery found into C.
//!
//! every function becomes a C function that can be entered at any of its
//! labels. guest calls are C calls, and anything the code cannot follow on
//! its own, an svc, an unknown target, a full budget, returns all the way
//! out to the host, which picks up again from r15.

mod arm;
mod thumb;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::discover::{Analysis, Function, Mode, Program};

pub const HEADER: &str = include_str!("recomp.h");

/// what the lowering of one instruction may refer to.
pub struct Scope<'a> {
    /// the labels of the function being written.
    pub labels: &'a BTreeSet<u32>,
    /// the functions written as C, by entry, bit 0 set for Thumb.
    pub functions: &'a BTreeSet<u32>,
}

impl Scope<'_> {
    /// the C name of the function at target, if it was written.
    fn function(&self, target: u32, thumb: bool) -> Option<String> {
        self.functions.contains(&(target | thumb as u32)).then(|| name(target, thumb))
    }
}

fn name(entry: u32, thumb: bool) -> String {
    format!("{}_{entry:08X}", if thumb { 't' } else { 'f' })
}

macro_rules! emit {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).unwrap()
    };
}

/// a call, with link the return address as lr holds it, bit 0 set when
/// the caller is Thumb.
fn call(out: &mut String, scope: &Scope, link: u32, target: u32, thumb: bool) -> bool {
    let caller_thumb = link & 1 != 0;
    emit!(out, "    ctx->r[14] = 0x{link:08X}u; ctx->r[15] = 0x{target:08X}u;");
    if thumb != caller_thumb {
        emit!(out, "    ctx->thumb = {};", thumb as u8);
    }
    match scope.function(target, thumb) {
        Some(name) => emit!(out, "    CALL({name});"),
        None => emit!(out, "    CALL(recomp_call);"),
    }
    let check = if caller_thumb { "RETURNED_T" } else { "RETURNED" };
    emit!(out, "    {check}(0x{:08X}u);", link & !1);
    true
}

/// a branch without link, to a label of this function if it is one.
fn jump(out: &mut String, scope: &Scope, target: u32, thumb: bool) -> bool {
    if scope.labels.contains(&target) {
        emit!(out, "    goto L_{target:08X};");
    } else if let Some(name) = scope.function(target, thumb) {
        // a tail call
        emit!(out, "    ctx->r[15] = 0x{target:08X}u; CALL({name}); return;");
    } else {
        emit!(out, "    target = 0x{target:08X}u; goto dispatch;");
    }
    false
}

/// instructions per source file, so the files compile in parallel.
const FILE_SIZE: usize = 20_000;

const PRELUDE: &str = "#include \"recomp.h\"\n#include \"functions.h\"\n\n";

/// whether a function becomes C, which it does unless its entry turned
/// out not to be code.
pub fn recompiles(entry: u32, function: &Function) -> bool {
    function.labels.contains(&entry)
}

/// an address as the host looks it up, bit 0 set for Thumb.
fn key(address: u32, mode: Mode) -> u32 {
    address | (mode == Mode::Thumb) as u32
}

/// the C sources for a program, as file names and contents.
pub fn generate(program: &Program, analysis: &Analysis) -> Vec<(String, String)> {
    let functions: BTreeMap<u32, &Function> =
        analysis.functions.iter().filter(|&(&entry, f)| recompiles(entry, f)).map(|(&entry, f)| (entry, f)).collect();
    let names: BTreeSet<u32> = functions.iter().map(|(&entry, f)| key(entry, f.mode)).collect();

    let mut files = vec![("recomp.h".to_owned(), HEADER.to_owned())];
    let mut prototypes = String::new();
    for (&entry, function) in &functions {
        writeln!(prototypes, "void {}(Context *ctx);", name(entry, function.mode == Mode::Thumb)).unwrap();
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
    let mut entries: BTreeMap<u32, String> = BTreeMap::new();
    for (&address, function) in &functions {
        let owner = name(address, function.mode == Mode::Thumb);
        for &label in &function.labels {
            let slot = entries.entry(key(label, function.mode)).or_insert_with(|| owner.clone());
            if label == address {
                slot.clone_from(&owner);
            }
        }
    }
    let mut table = String::from(PRELUDE);
    writeln!(table, "RECOMP_EXPORT const uint32_t recomp_abi = RECOMP_ABI;").unwrap();
    writeln!(table, "RECOMP_EXPORT const uint32_t recomp_entry_count = {};", entries.len()).unwrap();
    writeln!(table, "RECOMP_EXPORT const Entry recomp_entries[] = {{").unwrap();
    for (label, owner) in entries {
        writeln!(table, "    {{0x{label:08X}u, {owner}}},").unwrap();
    }
    table.push_str("};\n");
    files.push(("entries.c".to_owned(), table));
    files
}

fn write_function(out: &mut String, program: &Program, names: &BTreeSet<u32>, entry: u32, function: &Function) {
    let scope = Scope { labels: &function.labels, functions: names };
    let thumb = function.mode == Mode::Thumb;
    let state = if thumb { "ctx->thumb" } else { "!ctx->thumb" };
    emit!(out, "void {}(Context *ctx) {{", name(entry, thumb));
    emit!(out, "    uint32_t target = ctx->r[15];");
    emit!(out, "    if (LIKELY(target == 0x{entry:08X}u && {state})) goto L_{entry:08X};");
    emit!(out, "dispatch:");
    emit!(out, "    if ({state}) switch (target) {{");
    for label in &function.labels {
        emit!(out, "    case 0x{label:08X}u: goto L_{label:08X};");
    }
    emit!(out, "    }}");
    // somewhere else, the host knows where
    emit!(out, "    ctx->r[15] = target;");
    emit!(out, "    CALL(recomp_call);");
    emit!(out, "    return;");

    let instructions = &function.instructions;
    for (i, &address) in instructions.iter().enumerate() {
        if function.labels.contains(&address) {
            let run = instructions[i + 1..].iter().take_while(|a| !function.labels.contains(a)).count() + 1;
            emit!(out, "L_{address:08X}:");
            emit!(out, "    BUDGET(0x{address:08X}u, {run});");
        }
        let (continues, size) = if thumb {
            let op = program.text.read16(address).unwrap_or(0) as u32;
            let second = program.text.read16(address + 2).unwrap_or(0) as u32;
            let size = crate::thumb::decode(op as u16, Some(second as u16), address).1;
            emit!(out, "    /* {address:08X} {op:04X} */");
            (thumb::lower(out, &scope, address, op, second), size)
        } else {
            let op = program.text.read32(address).unwrap_or(0);
            emit!(out, "    /* {address:08X} {op:08X} */");
            (arm::lower(out, &scope, address, op), 4)
        };
        let next = address + size;
        if continues && instructions.get(i + 1) != Some(&next) {
            emit!(out, "    target = 0x{next:08X}u; goto dispatch;");
        }
    }
    emit!(out, "}}\n");
}
