//! turning the functions discovery found into C.
//!
//! every function becomes a C function that can be entered at any of its
//! labels. guest calls are C calls, and anything the code cannot follow on
//! its own, an svc, an unknown target, a full budget, returns all the way
//! out to the host, which picks up again from r15.

mod arm;
mod locals;
mod thumb;
mod vfp;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::discover::{Analysis, Function, Mode, Program};
use crate::overrides::Override;

pub use recomp_abi::HEADER;

/// what the lowering of one instruction may refer to.
pub(crate) struct Scope<'a> {
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
    /// the instructions left to the interpreter, which can end the code's
    /// run, so that it gets entered again right after them.
    pub interpreted: &'a std::cell::RefCell<Vec<u32>>,
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

/// the words a load or store multiple moves, from p up, a destination for
/// each when loading and a value for each when storing, both as C. they
/// nearly always lie on one page the code reaches directly, which one
/// check covers, and otherwise go through the usual path one at a time.
fn words(out: &mut String, load: bool, words: &[String]) {
    let bytes = words.len() * 4;
    if let [word] = words {
        // nothing to share
        if load {
            emit!(out, "    {word} = mem_read32(ctx, p);");
        } else {
            emit!(out, "    mem_write32(ctx, p, {word});");
        }
        return;
    }
    if load {
        emit!(out, "    {{ const uint8_t *span = mem_read_span(ctx, p, {bytes}u);");
        emit!(out, "    if (LIKELY(span)) {{");
        for (i, destination) in words.iter().enumerate() {
            emit!(out, "    {destination} = load32(span + {});", i * 4);
        }
        emit!(out, "    }} else {{");
        for (i, destination) in words.iter().enumerate() {
            emit!(out, "    {destination} = mem_read32(ctx, p + {}u);", i * 4);
        }
    } else {
        emit!(out, "    {{ uint8_t *span = mem_write_span(ctx, p, {bytes}u);");
        emit!(out, "    if (LIKELY(span)) {{");
        for (i, value) in words.iter().enumerate() {
            emit!(out, "    store32(span + {}, {value});", i * 4);
        }
        emit!(out, "    }} else {{");
        for (i, value) in words.iter().enumerate() {
            emit!(out, "    mem_write32(ctx, p + {}u, {value});", i * 4);
        }
    }
    emit!(out, "    }} }}");
}

/// a branch without link, to a label of this function if it is one.
fn jump(out: &mut String, scope: &Scope, target: u32, thumb: bool) -> bool {
    if scope.labels.contains(&target) {
        emit!(out, "    goto L_{target:08X};");
    } else if let Some(name) = scope.function(target, thumb) {
        // a tail call
        emit!(out, "    ctx->r[15] = {}; CALL({name}); RETURN();", scope.at(target));
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
/// contents. the overrides take the place of the functions they replace,
/// which overrides.h lets them still call.
pub fn generate(units: &[Unit], overrides: &[Override]) -> Vec<(String, String)> {
    let mut files = vec![("recomp.h".to_owned(), HEADER.to_owned())];
    let mut sources: Vec<String> = Vec::new();
    let mut source = String::new();
    // the headers the file being written includes
    let mut included = BTreeSet::new();
    let mut size = 0;
    let mut tables = String::from("#include \"recomp.h\"\n");
    let mut modules = String::new();
    let mut originals = String::new();
    let mut original_headers = BTreeSet::new();

    for (index, unit) in units.iter().enumerate() {
        let prefix = if unit.module.is_some() { format!("m{index:03}_") } else { String::new() };
        let header = format!("{}functions.h", prefix);
        let mut functions: BTreeMap<u32, &Function> =
            unit.analysis.functions.iter().filter(|&(&entry, f)| recompiles(entry, f)).map(|(&e, f)| (e, f)).collect();
        let containers = containers(&functions);
        let mut names: BTreeMap<u32, String> = functions
            .iter()
            .map(|(&entry, f)| {
                let home = containers.get(&entry).copied().unwrap_or(entry);
                (key(entry, f.mode), name(&prefix, home, f.mode == Mode::Thumb))
            })
            .collect();
        functions.retain(|entry, _| !containers.contains_key(entry));

        // calls go to the functions written by hand, which reach the
        // generated ones through a function that enters them where they
        // replace them
        let replaced: Vec<&Override> = overrides.iter().filter(|o| o.module.as_deref() == unit.module).collect();
        for &item in &replaced {
            let Some(original) = names.insert(item.address, item.name.clone()) else { continue };
            let address = item.address & !1;
            let at = if unit.module.is_some() { format!("{prefix}base + 0x{address:X}u") } else { format!("0x{address:08X}u") };
            emit!(originals, "static inline void {}(Context *ctx) {{", item.original);
            emit!(originals, "    ctx->r[15] = {at};");
            emit!(originals, "    ctx->thumb = {};", item.address & 1);
            emit!(originals, "    {original}(ctx);");
            emit!(originals, "}}\n");
            original_headers.insert(header.clone());
        }

        let mut prototypes = String::new();
        if unit.module.is_some() {
            emit!(prototypes, "extern uint32_t {prefix}base;");
        }
        for item in &replaced {
            emit!(prototypes, "void {}(Context *ctx);", item.name);
        }
        for (&entry, function) in &functions {
            emit!(prototypes, "void {}(Context *ctx);", name(&prefix, entry, function.mode == Mode::Thumb));
        }
        files.push((header.clone(), prototypes));

        let include = format!("#include \"{header}\"\n\n");
        // each function's labels with those after what it interprets
        let mut resumed: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for (&entry, function) in &functions {
            if source.is_empty() {
                source.push_str("#include \"recomp.h\"\n");
            }
            if included.insert(index) {
                source.push_str(&include);
            }
            // written once to see what goes to the interpreter, the code
            // can stop after any of those, and then again with a label
            // after each, where the host comes back in
            let interpreted = std::cell::RefCell::new(Vec::new());
            let relative = unit.module.is_some();
            let scope = Scope { labels: &function.labels, functions: &names, prefix: &prefix, relative, interpreted: &interpreted };
            write_function(&mut String::new(), unit.program, &scope, entry, function);
            let mut resumable = (*function).clone();
            for address in interpreted.take() {
                let at = function.instructions.iter().position(|&a| a == address);
                if let Some(&next) = at.and_then(|i| function.instructions.get(i + 1)) {
                    resumable.labels.insert(next);
                }
            }
            let scope = Scope { labels: &resumable.labels, functions: &names, prefix: &prefix, relative, interpreted: &interpreted };
            write_function(&mut source, unit.program, &scope, entry, &resumable);
            resumed.insert(entry, resumable.labels);
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
            for &label in resumed.get(&entry).unwrap_or(&function.labels) {
                let slot = entries.entry(key(label, function.mode)).or_insert_with(|| owner.clone());
                if label == entry {
                    slot.clone_from(&owner);
                }
            }
        }
        for item in &replaced {
            entries.insert(item.address, item.name.clone());
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
    if !overrides.is_empty() {
        let mut header = String::from("/* what overrides include, see docs/overrides.md. */\n\n#include \"recomp.h\"\n");
        for included in &original_headers {
            emit!(header, "#include \"{included}\"");
        }
        emit!(header, "\n/* the generated functions the overrides replace. */\n\n{originals}");
        files.push(("overrides.h".to_owned(), header));
    }
    files.extend(sources.into_iter().enumerate().map(|(i, source)| (format!("code{i:03}.c"), source)));
    files
}

fn write_function(out: &mut String, program: &Program, scope: &Scope, entry: u32, function: &Function) {
    let thumb = function.mode == Mode::Thumb;
    emit!(out, "void {}(Context *ctx) {{", name(scope.prefix, entry, thumb));
    let mut body = String::new();
    write_body(&mut body, program, scope, entry, function);
    out.push_str(&locals::keep(&body));
    emit!(out, "}}");
    out.push_str(locals::RESET);
    out.push('\n');
}

/// what a function does, between its braces.
fn write_body(out: &mut String, program: &Program, scope: &Scope, entry: u32, function: &Function) {
    let thumb = function.mode == Mode::Thumb;
    let state = if thumb { "ctx->thumb" } else { "!ctx->thumb" };
    if scope.relative {
        emit!(out, "    const uint32_t module_base = {}base;", scope.prefix);
    }
    emit!(out, "    uint32_t target = ctx->r[15], resume = 0;");
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
    emit!(out, "    RETURN();");

    let instructions = &function.instructions;
    for (i, &address) in instructions.iter().enumerate() {
        if function.labels.contains(&address) {
            let run = instructions[i + 1..].iter().take_while(|a| !function.labels.contains(a)).count() + 1;
            emit!(out, "L_{address:08X}:");
            emit!(out, "    BLOCK({}, {run});", scope.at(address));
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
    emit!(out, "    OUT_OF_BUDGET();");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{self, Source};
    use crate::image::Segment;

    const BASE: u32 = 0x0010_0000;

    /// the files for ARM code at BASE, entered at its start.
    fn files(words: &[u32], overrides: &[Override]) -> BTreeMap<String, String> {
        let program = Program {
            text: Segment { base: BASE, bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect() },
            seeds: vec![(BASE, Source::Entry)],
            slots: None,
        };
        let analysis = discover::analyze(&program);
        let units = [Unit { module: None, program: &program, analysis: &analysis }];
        generate(&units, overrides).into_iter().collect()
    }

    /// the files for a function that calls another, the callee replaced.
    fn generated(overrides: &[Override]) -> BTreeMap<String, String> {
        // bl BASE + 8, bx lr, bx lr
        files(&[0xEB00_0000, 0xE12F_FF1E, 0xE12F_FF1E], overrides)
    }

    #[test]
    fn multiple_transfers_check_one_page_for_all_their_words() {
        // push {r4, r5, lr}, vpush {d8}, vpop {d8}, pop {r4, r5, pc}
        let files = files(&[0xE92D_4030, 0xED2D_8B02, 0xECBD_8B02, 0xE8BD_8030], &[]);
        let code = &files["code000.c"];
        assert!(code.contains("mem_write_span(ctx, p, 12u)"));
        assert!(code.contains("store32(span + 8, reg14_);"));
        assert!(code.contains("mem_write_span(ctx, p, 8u)"));
        assert!(code.contains("mem_read_span(ctx, p, 12u)"));
        assert!(code.contains("next = load32(span + 8);"));
        assert!(code.contains("RETURN_TO(next);"));

        compiles("transfers", &files, &["code000.c"]);
    }

    /// compiles sources among files, in a folder of their own named after
    /// test, panicking with the compiler's complaint when they do not.
    fn compiles(test: &str, files: &BTreeMap<String, String>, sources: &[&str]) {
        let dir = std::env::temp_dir().join(format!("3dsrecomp-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        let built = crate::compile::objects(&dir, &sources, &|_, _| true);
        std::fs::remove_dir_all(&dir).ok();
        built.unwrap();
    }

    #[test]
    fn overrides_written_as_the_docs_show_compile() {
        let replaced = Override {
            module: None,
            address: BASE + 8,
            name: "override_0x00100008".to_owned(),
            original: "original_0x00100008".to_owned(),
        };
        let mut files = generated(std::slice::from_ref(&replaced));
        files.insert(
            "override.c".to_owned(),
            r#"#include "overrides.h"

RECOMP_OVERRIDE(0x00100008) {
    uint32_t start = ctx->r[0], end = start;
    BUDGET(0x00100008u, 4);
    while (mem_read8(ctx, end))
        end++;
    mem_write32(ctx, ctx->r[1], mem_read32(ctx, ctx->r[2]));
    vfp_set_s(ctx, 0, vfp_s(ctx, 1) * 2.0f);
    vfp_set_d(ctx, 1, vfp_d(ctx, 2) + 1.0);
    vfp_compare(ctx, vfp_d(ctx, 1), 0.0);
    ctx->r[0] = end - start;
    if (ctx->r[0] == 0) {
        CALL(RECOMP_ORIGINAL(0x00100008));
        return;
    }
    RETURN_TO(ctx->r[14]);
}
"#
            .to_owned(),
        );
        compiles("overrides", &files, &["code000.c", "override.c"]);
    }

    #[test]
    fn overrides_take_the_place_of_what_they_replace() {
        let replaced = Override {
            module: None,
            address: BASE + 8,
            name: "override_0x00100008".to_owned(),
            original: "original_0x00100008".to_owned(),
        };
        let files = generated(std::slice::from_ref(&replaced));
        let code = &files["code000.c"];
        assert!(code.contains("CALL(override_0x00100008);"));
        assert!(files["functions.h"].contains("void override_0x00100008(Context *ctx);"));
        assert!(files["entries.c"].contains("{0x00100008u, override_0x00100008},"));
        let header = &files["overrides.h"];
        assert!(header.contains("static inline void original_0x00100008(Context *ctx) {"));
        assert!(header.contains("f_00100008(ctx);"));

        // without overrides nothing changes
        let plain = generated(&[]);
        assert!(plain["code000.c"].contains("CALL(f_00100008);"));
        assert!(!plain.contains_key("overrides.h"));
    }
}
