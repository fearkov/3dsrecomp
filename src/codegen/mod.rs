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

/// instructions per source file, so the files compile in parallel. gcc
/// keeps a whole file in memory, and files of 20,000 took it up to 7.8 GB.
const FILE_SIZE: usize = 5_000;

/// the instructions up to which a function another one holds is still
/// written as a function of its own.
const OWN_FUNCTION: usize = 128;

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
    // each unit's Origins, the executable's first
    let mut origins = String::new();
    let mut originals = String::new();
    let mut original_headers = BTreeSet::new();

    for (index, unit) in units.iter().enumerate() {
        let prefix = if unit.module.is_some() { format!("m{index:03}_") } else { String::new() };
        let header = format!("{}functions.h", prefix);
        let mut functions: BTreeMap<u32, &Function> =
            unit.analysis.functions.iter().filter(|&(&entry, f)| recompiles(entry, f)).map(|(&e, f)| (e, f)).collect();
        // a small function another one holds still gets a C function of its
        // own, so that calls to it skip the bigger one's way in, its loads
        // and its dispatch
        let containers: BTreeMap<u32, u32> = containers(&functions)
            .into_iter()
            .filter(|(entry, _)| functions[entry].instructions.len() > OWN_FUNCTION)
            .collect();
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
        emit!(prototypes, "extern RECOMP_HIDDEN uint8_t {prefix}recomp_stale[];");
        emit!(prototypes, "extern RECOMP_HIDDEN uint32_t {prefix}recomp_starts[];");
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
        for (number, (&entry, function)) in functions.iter().enumerate() {
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
            write_function(&mut String::new(), unit.program, &scope, entry, function, number);
            let mut resumable = (*function).clone();
            for address in interpreted.take() {
                let at = function.instructions.iter().position(|&a| a == address);
                if let Some(&next) = at.and_then(|i| function.instructions.get(i + 1)) {
                    resumable.labels.insert(next);
                }
            }
            let scope = Scope { labels: &resumable.labels, functions: &names, prefix: &prefix, relative, interpreted: &interpreted };
            write_function(&mut source, unit.program, &scope, entry, &resumable, number);
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
        let mut entries: BTreeMap<u32, (String, u32)> = BTreeMap::new();
        for (number, (&entry, function)) in functions.iter().enumerate() {
            let owner = (name(&prefix, entry, function.mode == Mode::Thumb), number as u32);
            for &label in resumed.get(&entry).unwrap_or(&function.labels) {
                let slot = entries.entry(key(label, function.mode)).or_insert_with(|| owner.clone());
                if label == entry {
                    slot.clone_from(&owner);
                }
            }
        }
        for item in &replaced {
            entries.insert(item.address, (item.name.clone(), recomp_abi::NO_ORIGIN));
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
        for (label, (owner, _)) in &entries {
            emit!(tables, "    {{0x{label:08X}u, {owner}}},");
        }
        emit!(tables, "}};\n");
        write_origins(&mut tables, &mut origins, &prefix, unit.program, &functions, &entries);
    }
    if !source.is_empty() {
        sources.push(source);
    }

    emit!(tables, "RECOMP_EXPORT const uint32_t recomp_abi = RECOMP_ABI;");
    emit!(tables, "RECOMP_EXPORT const uint32_t recomp_generation = {}u;", recomp_abi::GENERATION);
    emit!(tables, "RECOMP_EXPORT const uint32_t recomp_module_count = {};", units.len() - 1);
    emit!(tables, "RECOMP_EXPORT const Module recomp_modules[] = {{\n{modules}}};");
    emit!(tables, "RECOMP_EXPORT const Origins recomp_origins[] = {{\n{origins}}};");
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

/// the stretches of code a function was made from, as runs of instructions
/// one right after another.
fn spans(program: &Program, function: &Function) -> Vec<(u32, u32)> {
    let mut spans: Vec<(u32, u32)> = Vec::new();
    for &address in &function.instructions {
        let size = if function.mode == Mode::Thumb {
            let op = program.text.read16(address).unwrap_or(0);
            crate::thumb::decode(op, program.text.read16(address + 2), address).1
        } else {
            4
        };
        match spans.last_mut() {
            Some(last) if last.1 == address => last.1 = address + size,
            _ => spans.push((address, address + size)),
        }
    }
    spans
}

/// a unit's stale flags and the tables saying what its functions were
/// made from, with its Origins added to origins. the code is cut into pieces
/// wherever a function's code starts or ends, so that the host hashes every
/// byte once, functions holding the code of others as they do.
fn write_origins(
    tables: &mut String,
    origins: &mut String,
    prefix: &str,
    program: &Program,
    functions: &BTreeMap<u32, &Function>,
    entries: &BTreeMap<u32, (String, u32)>,
) {
    let count = functions.len();
    emit!(tables, "RECOMP_HIDDEN uint8_t {prefix}recomp_stale[{}];", count.max(1));
    let starts: Vec<String> = functions.keys().map(|entry| format!("0x{entry:08X}u")).collect();
    emit!(tables, "RECOMP_HIDDEN uint32_t {prefix}recomp_starts[{}] = {{{}}};", count.max(1), starts.join(", "));
    let spans: Vec<Vec<(u32, u32)>> = functions.values().map(|function| spans(program, function)).collect();
    let pieces = pieces(spans.iter().flatten().copied());
    if pieces.is_empty() {
        emit!(origins, "    {{0, 0, 0, 0, 0, 0, {prefix}recomp_stale, {prefix}recomp_starts}},");
        return;
    }

    emit!(tables, "static const Piece {prefix}origin_pieces[] = {{");
    let at = |address: u32| address.wrapping_sub(program.text.base) as usize;
    for &(start, end) in &pieces {
        let mut hash = recomp_abi::CodeHash::default();
        hash.add(program.text.bytes.get(at(start)..at(end)).unwrap_or_default());
        emit!(tables, "    {{0x{start:08X}u, 0x{end:08X}u, 0x{:016X}ull}},", hash.value());
    }
    emit!(tables, "}};");
    let (mut made, mut runs) = (String::new(), Vec::new());
    for (spans, entry) in spans.iter().zip(functions.keys()) {
        emit!(made, "    {{{}, {}, 0x{entry:08X}u}},", runs.len(), spans.len());
        for &(start, end) in spans {
            let first = pieces.partition_point(|&(piece, _)| piece < start);
            let last = pieces.partition_point(|&(piece, _)| piece < end);
            runs.push((first, last));
        }
    }
    emit!(tables, "static const Origin {prefix}origin_functions[] = {{\n{made}}};");
    emit!(tables, "static const Run {prefix}origin_runs[] = {{");
    for (first, end) in runs {
        emit!(tables, "    {{{first}, {end}}},");
    }
    emit!(tables, "}};");
    emit!(tables, "static const uint32_t {prefix}origin_owners[] = {{");
    for (_, owner) in entries.values() {
        emit!(tables, "    {owner}u,");
    }
    emit!(tables, "}};\n");
    emit!(
        origins,
        "    {{{count}, {}, {prefix}origin_pieces, {prefix}origin_functions, {prefix}origin_runs, {prefix}origin_owners, {prefix}recomp_stale, {prefix}recomp_starts}},",
        pieces.len()
    );
}

/// the pieces spans cut the code into, in order and without overlaps: the
/// code some span covers, cut wherever any of them starts or ends.
fn pieces(spans: impl Iterator<Item = (u32, u32)>) -> Vec<(u32, u32)> {
    let mut spans: Vec<(u32, u32)> = spans.collect();
    spans.sort_unstable();
    let cuts: BTreeSet<u32> = spans.iter().flat_map(|&(start, end)| [start, end]).collect();
    let mut pieces = Vec::new();
    let mut covered: Option<(u32, u32)> = None;
    // each stretch covered without a gap, cut at every start and end in it
    let cut = |(start, end): (u32, u32), pieces: &mut Vec<(u32, u32)>| {
        let mut from = start;
        for &at in cuts.range(start + 1..end) {
            pieces.push((from, at));
            from = at;
        }
        pieces.push((from, end));
    };
    for (start, end) in spans {
        match covered {
            Some((from, to)) if start <= to => covered = Some((from, to.max(end))),
            _ => {
                if let Some(stretch) = covered {
                    cut(stretch, &mut pieces);
                }
                covered = Some((start, end));
            }
        }
    }
    if let Some(stretch) = covered {
        cut(stretch, &mut pieces);
    }
    pieces
}

/// a function, the number-th of its unit.
fn write_function(out: &mut String, program: &Program, scope: &Scope, entry: u32, function: &Function, number: usize) {
    let thumb = function.mode == Mode::Thumb;
    emit!(out, "void {}(Context *ctx) {{", name(scope.prefix, entry, thumb));
    let mut body = String::new();
    write_body(&mut body, program, scope, entry, function, number);
    out.push_str(&locals::keep(&body));
    emit!(out, "}}");
    out.push_str(locals::RESET);
    out.push('\n');
}

/// what a function does, between its braces.
fn write_body(out: &mut String, program: &Program, scope: &Scope, entry: u32, function: &Function, number: usize) {
    let thumb = function.mode == Mode::Thumb;
    let state = if thumb { "ctx->thumb" } else { "!ctx->thumb" };
    if scope.relative {
        emit!(out, "    const uint32_t module_base = {}base;", scope.prefix);
    }
    emit!(out, "    uint32_t target = ctx->r[15], resume = 0;");
    // a function is only ever entered in its own state, callers and the
    // host's lookups see to that, so the entry needs no look at thumb
    // its start comes from memory, where the host puts an address nothing
    // starts at once the function is stale, so that calls pay for the check
    // with nothing more than the compare they make anyway, and whatever
    // misses goes past the flag
    let prefix = scope.prefix;
    let start = if scope.relative { format!("(module_base + {prefix}recomp_starts[{number}])") } else { format!("{prefix}recomp_starts[{number}]") };
    emit!(out, "    if (LIKELY(target == {start})) goto L_{entry:08X};");
    emit!(out, "    STALE_CHECK({prefix}recomp_stale[{number}])");
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
        assert!(code.contains("RETURN_TO_A(next);"));

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

    /// every function starts by checking its stale flag, and the tables say
    /// what it was made from, a span for each run of its instructions and
    /// the hash of their bytes.
    #[test]
    fn functions_say_what_they_were_made_from() {
        // bl BASE + 8, bx lr, then the callee, bx lr
        let files = generated(&[]);
        let code = &files["code000.c"];
        assert!(code.contains("if (LIKELY(target == recomp_starts[0])) goto L_00100000;\n    STALE_CHECK(recomp_stale[0])"));
        assert!(code.contains("STALE_CHECK(recomp_stale[1])"));
        assert!(files["entries.c"].contains("uint32_t recomp_starts[2] = {0x00100000u, 0x00100008u};"));
        let tables = &files["entries.c"];
        let mut caller = recomp_abi::CodeHash::default();
        caller.add(&[0x00, 0x00, 0x00, 0xEB, 0x1E, 0xFF, 0x2F, 0xE1]);
        assert!(tables.contains(&format!("{{0x00100000u, 0x00100008u, 0x{:016X}ull}},", caller.value())), "{tables}");
        assert!(tables.contains("{0x00100008u, 0x0010000Cu, 0x"));
        // a function each, a run of one piece each
        assert!(tables.contains("static const Run origin_runs[] = {\n    {0, 1},\n    {1, 2},\n};"), "{tables}");
        assert!(tables.contains("RECOMP_EXPORT const Origins recomp_origins[] = {\n    {2, 2, origin_pieces, origin_functions, origin_runs, origin_owners, recomp_stale, recomp_starts},"));

        compiles("origins", &files, &["code000.c", "entries.c"]);
    }

    /// code several functions hold is cut where any of them starts or ends,
    /// and each function's code is whole pieces.
    #[test]
    fn overlapping_code_is_cut_into_pieces() {
        let pieces = pieces([(0x100, 0x120), (0x110, 0x118), (0x118, 0x130), (0x200, 0x204)].into_iter());
        assert_eq!(pieces, [(0x100, 0x110), (0x110, 0x118), (0x118, 0x120), (0x120, 0x130), (0x200, 0x204)]);
    }

    /// a file holding functions of the executable and of a module declares
    /// what both use.
    #[test]
    fn units_that_share_a_file_compile() {
        let program = Program {
            text: Segment { base: BASE, bytes: [0xEB00_0000u32, 0xE12F_FF1E, 0xE12F_FF1E].iter().flat_map(|w| w.to_le_bytes()).collect() },
            seeds: vec![(BASE, Source::Entry)],
            slots: None,
        };
        let analysis = discover::analyze(&program);
        let units = [
            Unit { module: None, program: &program, analysis: &analysis },
            Unit { module: Some("First"), program: &program, analysis: &analysis },
            Unit { module: Some("Second"), program: &program, analysis: &analysis },
        ];
        let files: BTreeMap<String, String> = generate(&units, &[]).into_iter().collect();
        let code = &files["code000.c"];
        assert!(code.contains("#include \"m001_functions.h\"") && code.contains("#include \"m002_functions.h\""));
        assert!(code.contains("STALE_CHECK(m002_recomp_stale[1])"));
        assert!(code.contains("if (LIKELY(target == (module_base + m002_recomp_starts[1])))"));
        assert!(files["entries.c"].contains("{2, 2, m002_origin_pieces, m002_origin_functions, m002_origin_runs, m002_origin_owners, m002_recomp_stale, m002_recomp_starts},"));

        compiles("units", &files, &["code000.c", "entries.c"]);
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
        assert!(files["entries.c"].contains(&format!("recomp_generation = {}u;", recomp_abi::GENERATION)));
        let header = &files["overrides.h"];
        assert!(header.contains("static inline void original_0x00100008(Context *ctx) {"));
        assert!(header.contains("f_00100008(ctx);"));

        // without overrides nothing changes
        let plain = generated(&[]);
        assert!(plain["code000.c"].contains("CALL(f_00100008);"));
        assert!(!plain.contains_key("overrides.h"));
    }
}
