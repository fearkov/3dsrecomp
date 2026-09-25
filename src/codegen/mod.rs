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
    /// the C function that runs each function, by entry with bit 0 set
    /// for Thumb.
    pub functions: &'a BTreeMap<u32, String>,
    /// what the names of the functions start with, which keeps modules apart.
    pub prefix: &'a str,
    /// whether the code moves, so that addresses are offsets from where the
    /// host loaded it.
    pub relative: bool,
}

impl Scope<'_> {
    /// an address as C.
    fn at(&self, address: u32) -> String {
        if self.relative { format!("(module_base + 0x{address:X}u)") } else { format!("0x{address:08X}u") }
    }

    /// the C function that runs the function at target, if there is one.
    fn function(&self, target: u32, thumb: bool) -> Option<String> {
        self.functions.get(&(target | thumb as u32)).cloned()
    }
}

fn name(prefix: &str, entry: u32, thumb: bool) -> String {
    format!("{prefix}{}_{entry:08X}", if thumb { 't' } else { 'f' })
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
    let lr = if caller_thumb { format!("{} | 1", scope.at(link & !1)) } else { scope.at(link) };
    emit!(out, "    ctx->r[14] = {lr}; ctx->r[15] = {};", scope.at(target));
    if thumb != caller_thumb {
        emit!(out, "    ctx->thumb = {};", thumb as u8);
    }
    match scope.function(target, thumb) {
        Some(name) => emit!(out, "    CALL({name});"),
        None => emit!(out, "    CALL(recomp_call);"),
    }
    let check = if caller_thumb { "RETURNED_T" } else { "RETURNED" };
    emit!(out, "    {check}({});", scope.at(link & !1));
    true
}

/// a branch without link, to a label of this function if it is one.
fn jump(out: &mut String, scope: &Scope, target: u32, thumb: bool) -> bool {
    if scope.labels.contains(&target) {
        emit!(out, "    goto L_{target:08X};");
    } else if let Some(name) = scope.function(target, thumb) {
        // a tail call
        emit!(out, "    ctx->r[15] = {}; CALL({name}); return;", scope.at(target));
    } else {
        emit!(out, "    target = {}; goto dispatch;", scope.at(target));
    }
    false
}

/// instructions per source file, so the files compile in parallel.
const FILE_SIZE: usize = 20_000;

/// whether a function becomes C, which it does unless its entry turned
/// out not to be code.
pub fn recompiles(entry: u32, function: &Function) -> bool {
    function.labels.contains(&entry)
}

/// an address as the host looks it up, bit 0 set for Thumb.
fn key(address: u32, mode: Mode) -> u32 {
    address | (mode == Mode::Thumb) as u32
}

/// the functions whose code another function already has, each with the
/// entry of the function that runs it. a jump table's cases and the target
/// of a tail call turn up both ways, as functions of their own and inside
/// the function that reaches them.
fn containers(functions: &BTreeMap<u32, &Function>) -> BTreeMap<u32, u32> {
    let mut owners: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (&entry, function) in functions {
        for &label in &function.labels {
            owners.entry(label).or_default().push(entry);
        }
    }
    // a function only moves into a bigger one, so the links cannot loop
    let rank = |entry: u32| (functions[&entry].instructions.len(), std::cmp::Reverse(entry));
    let mut parent = BTreeMap::new();
    for (&entry, function) in functions {
        let contains = |other: u32| {
            let code = &functions[&other].instructions;
            function.instructions.iter().all(|address| code.binary_search(address).is_ok())
        };
        let best = owners[&entry]
            .iter()
            .copied()
            .filter(|&other| functions[&other].mode == function.mode && rank(other) > rank(entry))
            .filter(|&other| contains(other))
            .max_by_key(|&other| rank(other));
        if let Some(best) = best {
            parent.insert(entry, best);
        }
    }
    parent
        .keys()
        .map(|&entry| {
            let mut container = parent[&entry];
            while let Some(&next) = parent.get(&container) {
                container = next;
            }
            (entry, container)
        })
        .collect()
}

/// a program to write as C, the executable or one of its modules.
pub struct Unit<'a> {
    /// the module's name, None for the executable, whose code does not move.
    pub module: Option<&'a str>,
    pub program: &'a Program,
    pub analysis: &'a Analysis,
}

/// the C sources for the units, the executable first, as file names and
/// contents.
pub fn generate(units: &[Unit]) -> Vec<(String, String)> {
    let mut files = vec![("recomp.h".to_owned(), HEADER.to_owned())];
    let mut sources: Vec<String> = Vec::new();
    let mut source = String::new();
    // the headers the file being written includes
    let mut included = BTreeSet::new();
    let mut size = 0;
    let mut tables = String::from("#include \"recomp.h\"\n");
    let mut modules = String::new();

    for (index, unit) in units.iter().enumerate() {
        let prefix = if unit.module.is_some() { format!("m{index:03}_") } else { String::new() };
        let header = format!("{}functions.h", prefix);
        let mut functions: BTreeMap<u32, &Function> =
            unit.analysis.functions.iter().filter(|&(&entry, f)| recompiles(entry, f)).map(|(&e, f)| (e, f)).collect();
        let containers = containers(&functions);
        let names: BTreeMap<u32, String> = functions
            .iter()
            .map(|(&entry, f)| {
                let home = containers.get(&entry).copied().unwrap_or(entry);
                (key(entry, f.mode), name(&prefix, home, f.mode == Mode::Thumb))
            })
            .collect();
        functions.retain(|entry, _| !containers.contains_key(entry));

        let mut prototypes = String::new();
        if unit.module.is_some() {
            emit!(prototypes, "extern uint32_t {prefix}base;");
        }
        for (&entry, function) in &functions {
            emit!(prototypes, "void {}(Context *ctx);", name(&prefix, entry, function.mode == Mode::Thumb));
        }
        files.push((header.clone(), prototypes));

        let include = format!("#include \"{header}\"\n\n");
        for (&entry, function) in &functions {
            if source.is_empty() {
                source.push_str("#include \"recomp.h\"\n");
            }
            if included.insert(index) {
                source.push_str(&include);
            }
            let scope =
                Scope { labels: &function.labels, functions: &names, prefix: &prefix, relative: unit.module.is_some() };
            write_function(&mut source, unit.program, &scope, entry, function);
            size += function.instructions.len();
            if size >= FILE_SIZE {
                sources.push(std::mem::take(&mut source));
                included.clear();
                size = 0;
            }
        }

        // every label the host can resume at, preferring the function that
        // starts there
        let mut entries: BTreeMap<u32, String> = BTreeMap::new();
        for (&entry, function) in &functions {
            let owner = name(&prefix, entry, function.mode == Mode::Thumb);
            for &label in &function.labels {
                let slot = entries.entry(key(label, function.mode)).or_insert_with(|| owner.clone());
                if label == entry {
                    slot.clone_from(&owner);
                }
            }
        }
        tables.push_str(&include);
        let table = match unit.module {
            Some(module) => {
                emit!(tables, "uint32_t {prefix}base;");
                emit!(
                    modules,
                    "    {{\"{module}\", &{prefix}base, 0x{:X}u, {}, {prefix}entries}},",
                    unit.program.text.end(),
                    entries.len()
                );
                format!("static const Entry {prefix}entries[]")
            }
            None => {
                emit!(tables, "RECOMP_EXPORT const uint32_t recomp_entry_count = {};", entries.len());
                "RECOMP_EXPORT const Entry recomp_entries[]".to_owned()
            }
        };
        emit!(tables, "{table} = {{");
        for (label, owner) in entries {
            emit!(tables, "    {{0x{label:08X}u, {owner}}},");
        }
        emit!(tables, "}};\n");
    }
    if !source.is_empty() {
        sources.push(source);
    }

    emit!(tables, "RECOMP_EXPORT const uint32_t recomp_abi = RECOMP_ABI;");
    emit!(tables, "RECOMP_EXPORT const uint32_t recomp_module_count = {};", units.len() - 1);
    emit!(tables, "RECOMP_EXPORT const Module recomp_modules[] = {{\n{modules}}};");
    files.push(("entries.c".to_owned(), tables));
    files.extend(sources.into_iter().enumerate().map(|(i, source)| (format!("code{i:03}.c"), source)));
    files
}

fn write_function(out: &mut String, program: &Program, scope: &Scope, entry: u32, function: &Function) {
    let thumb = function.mode == Mode::Thumb;
    let state = if thumb { "ctx->thumb" } else { "!ctx->thumb" };
    emit!(out, "void {}(Context *ctx) {{", name(scope.prefix, entry, thumb));
    if scope.relative {
        emit!(out, "    const uint32_t module_base = {}base;", scope.prefix);
    }
    emit!(out, "    uint32_t target = ctx->r[15];");
    emit!(out, "    if (LIKELY(target == {} && {state})) goto L_{entry:08X};", scope.at(entry));
    emit!(out, "dispatch:");
    let offset = if scope.relative { "target - module_base" } else { "target" };
    emit!(out, "    if ({state}) switch ({offset}) {{");
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
            emit!(out, "    BUDGET({}, {run});", scope.at(address));
        }
        let (continues, size) = if thumb {
            let op = program.text.read16(address).unwrap_or(0) as u32;
            let second = program.text.read16(address + 2).unwrap_or(0) as u32;
            let size = crate::thumb::decode(op as u16, Some(second as u16), address).1;
            emit!(out, "    /* {address:08X} {op:04X} */");
            (thumb::lower(out, scope, address, op, second), size)
        } else {
            let op = program.text.read32(address).unwrap_or(0);
            emit!(out, "    /* {address:08X} {op:08X} */");
            (arm::lower(out, scope, address, op), 4)
        };
        let next = address + size;
        if continues && instructions.get(i + 1) != Some(&next) {
            emit!(out, "    target = {}; goto dispatch;", scope.at(next));
        }
    }
    emit!(out, "}}\n");
}
