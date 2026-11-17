//! turns the funcs discovery found into C
//!
//! every func becomes a C func you can enter at any of its labels
//! guest calls are C calls, an svc is a call to the host
//! anything the code can't follow alone (unknown target, budget's gone, an svc the host needs more for)
//! returns all the way out and the host picks up again from r15

mod arm;
mod hoist;
mod locals;
mod thumb;
mod vfp;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::discover::{Analysis, Function, Mode, Program};
use crate::overrides::Override;

pub use recomp_abi::HEADER;

/// what lowering one instruction may refer to
pub(crate) struct Scope<'a> {
    /// labels of the func being written
    pub labels: &'a BTreeSet<u32>,
    /// the C func running each func, by entry w/ bit 0 for Thumb
    pub functions: &'a BTreeMap<u32, String>,
    /// func name prefix, keeps modules apart
    pub prefix: &'a str,
    /// if the code moves, addrs are offsets from where the host loaded it
    pub relative: bool,
    /// instrs left to the interpreter, they can end the run so we get entered again right after them
    pub interpreted: &'a std::cell::RefCell<Vec<u32>>,
    /// loads and stores at reg plus const so far
    pub accesses: &'a std::cell::RefCell<Vec<hoist::Access>>,
    /// the page table looks they share, once worked out
    pub plan: Option<&'a hoist::Plan>,
}

impl Scope<'_> {
    fn at(&self, address: u32) -> String {
        if self.relative { format!("(module_base + 0x{address:X}u)") } else { format!("0x{address:08X}u") }
    }

    /// a return addr as lr holds it (bit 0 for Thumb) as C
    fn link(&self, link: u32) -> String {
        if link & 1 != 0 { format!("({} | 1)", self.at(link & !1)) } else { self.at(link) }
    }

    /// the C func running the func at target, if any
    fn function(&self, target: u32, thumb: bool) -> Option<String> {
        self.functions.get(&(target | thumb as u32)).cloned()
    }

    /// notes a load or store at reg plus const and hands back its span if it has one
    fn access(&self, at: u32, base: u32, offset: i32, size: u32, write: bool) -> Option<hoist::Covered> {
        let mut accesses = self.accesses.borrow_mut();
        let ordinal = accesses.iter().rev().take_while(|access| access.at == at).count();
        accesses.push(hoist::Access { at, base, offset, size, write });
        self.plan.and_then(|plan| plan.covered.get(&(at, ordinal)).cloned())
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

/// a call, link is the return addr as lr holds it, bit 0 when the caller is Thumb
fn call(out: &mut String, scope: &Scope, link: u32, target: u32, thumb: bool) -> bool {
    let caller_thumb = link & 1 != 0;
    let lr = scope.link(link);
    emit!(out, "    ctx->r[14] = {lr}; ctx->r[15] = {};", scope.at(target));
    if thumb != caller_thumb {
        emit!(out, "    ctx->thumb = {};", thumb as u8);
    }
    let callee = scope.function(target, thumb).unwrap_or_else(|| "recomp_call".to_owned());
    emit!(out, "    CALL_RETURNING({callee}, {lr});");
    true
}

/// the words an ldm or stm moves from p up, a dest each when loading, a value each when storing, both as C
/// they nearly always sit on one directly reachable page (one check), else they go the slow way one by one
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

/// a branch w/o link, to a label of this func if it's one
fn jump(out: &mut String, scope: &Scope, target: u32, thumb: bool) -> bool {
    if scope.labels.contains(&target) {
        emit!(out, "    goto L_{target:08X};");
    } else if let Some(name) = scope.function(target, thumb) {
        // a tail call
        emit!(out, "    ctx->r[15] = {}; TAIL_CALL({name});", scope.at(target));
    } else {
        emit!(out, "    target = {}; goto dispatch;", scope.at(target));
    }
    false
}

/// instrs per source file so files compile in parallel
/// gcc keeps a whole file in memory and 20k instr files ate 7.8 GB, yikes
const FILE_SIZE: usize = 5_000;

/// up to this many instrs a func another one holds still gets its own func
const OWN_FUNCTION: usize = 128;

/// does a func become C, yes unless its entry turned out not to be code
pub fn recompiles(entry: u32, function: &Function) -> bool {
    function.labels.contains(&entry)
}

/// an addr as the host looks it up, bit 0 for Thumb
fn key(address: u32, mode: Mode) -> u32 {
    address | (mode == Mode::Thumb) as u32
}

/// funcs whose code another func already has, each w/ the entry of the func running it
/// jump table cases and tail call targets show up both ways, as their own funcs and inside whoever reaches them
fn containers(functions: &BTreeMap<u32, &Function>) -> BTreeMap<u32, u32> {
    let mut owners: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (&entry, function) in functions {
        for &label in &function.labels {
            owners.entry(label).or_default().push(entry);
        }
    }
    // a func only moves into a bigger one, so links can't loop
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

/// a program to write as C, the exe or one of its modules
pub struct Unit<'a> {
    /// module name, None for the exe whose code never moves
    pub module: Option<&'a str>,
    pub program: &'a Program,
    pub analysis: &'a Analysis,
}

/// the C sources for the units, exe first, as (name, contents)
/// overrides replace the funcs they override, overrides.h still lets them call those
pub fn generate(units: &[Unit], overrides: &[Override]) -> Vec<(String, String)> {
    let mut files = vec![("recomp.h".to_owned(), HEADER.to_owned())];
    let mut sources: Vec<String> = Vec::new();
    let mut source = String::new();
    // headers the current file includes
    let mut included = BTreeSet::new();
    let mut size = 0;
    let mut tables = String::from("#include \"recomp.h\"\n");
    let mut modules = String::new();
    // each unit's Origins, exe first
    let mut origins = String::new();
    let mut originals = String::new();
    let mut original_headers = BTreeSet::new();

    for (index, unit) in units.iter().enumerate() {
        let prefix = if unit.module.is_some() { format!("m{index:03}_") } else { String::new() };
        let header = format!("{}functions.h", prefix);
        let mut functions: BTreeMap<u32, &Function> =
            unit.analysis.functions.iter().filter(|&(&entry, f)| recompiles(entry, f)).map(|(&e, f)| (e, f)).collect();
        // a small func another one holds still gets its own C func
        // so calls to it skip the big one's way in, its loads and its dispatch
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

        // calls go to the handwritten funcs, they reach the generated ones thru a func that enters them where they replace them
        let replaced: Vec<&Override> = overrides.iter().filter(|o| o.module.as_deref() == unit.module).collect();
        for &item in &replaced {
            let Some(original) = names.insert(item.address, item.name.clone()) else { continue };
            let address = item.address & !1;
            let at = if unit.module.is_some() { format!("{prefix}base + 0x{address:X}u") } else { format!("0x{address:08X}u") };
            emit!(originals, "static inline uint32_t {}(Context *ctx) {{", item.original);
            emit!(originals, "    ctx->r[15] = {at};");
            emit!(originals, "    ctx->thumb = {};", item.address & 1);
            emit!(originals, "    return {original}(ctx);");
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
            emit!(prototypes, "uint32_t {}(Context *ctx);", item.name);
        }
        for (&entry, function) in &functions {
            emit!(prototypes, "uint32_t {}(Context *ctx);", name(&prefix, entry, function.mode == Mode::Thumb));
        }
        files.push((header.clone(), prototypes));

        let include = format!("#include \"{header}\"\n\n");
        // each func's labels plus the ones after what it interprets
        let mut resumed: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for (number, (&entry, function)) in functions.iter().enumerate() {
            if source.is_empty() {
                source.push_str("#include \"recomp.h\"\n");
            }
            if included.insert(index) {
                source.push_str(&include);
            }
            // written once to see what goes to the interpreter (the code can stop after any of those)
            // then again w/ a label after each, where the host comes back in
            // plus the loads, stores and where each instr's C sits, which the shared page table looks come from
            let interpreted = std::cell::RefCell::new(Vec::new());
            let accesses = std::cell::RefCell::new(Vec::new());
            let relative = unit.module.is_some();
            let scope = Scope {
                labels: &function.labels,
                functions: &names,
                prefix: &prefix,
                relative,
                interpreted: &interpreted,
                accesses: &accesses,
                plan: None,
            };
            let (mut body, mut pieces) = (String::new(), Vec::new());
            write_body(&mut body, unit.program, &scope, entry, function, number, Some(&mut pieces));
            let mut resumable = (*function).clone();
            for address in interpreted.take() {
                let at = function.instructions.iter().position(|&a| a == address);
                if let Some(&next) = at.and_then(|i| function.instructions.get(i + 1)) {
                    resumable.labels.insert(next);
                }
            }
            let lowered: Vec<(u32, &str)> = pieces.iter().map(|(at, range)| (*at, &body[range.clone()])).collect();
            let plan = hoist::plan(&resumable.labels, &lowered, &accesses.take());
            let scope = Scope {
                labels: &resumable.labels,
                functions: &names,
                prefix: &prefix,
                relative,
                interpreted: &interpreted,
                accesses: &accesses,
                plan: Some(&plan),
            };
            write_function(&mut source, unit.program, &scope, entry, &resumable, number);
            resumed.insert(entry, resumable.labels);
            size += function.instructions.len();
            if size >= FILE_SIZE {
                sources.push(std::mem::take(&mut source));
                included.clear();
                size = 0;
            }
        }

        // every label the host can resume at, preferring the func that starts there
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

/// the stretches of code a func was made from, as runs of back to back instrs
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

/// a unit's stale flags and the tables saying what its funcs came from, its Origins added to origins
/// code gets cut wherever a func starts or ends so the host hashes every byte once, even w/ funcs holding each other's code
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

/// the pieces spans cut the code into, in order, no overlaps, cut wherever any span starts or ends
fn pieces(spans: impl Iterator<Item = (u32, u32)>) -> Vec<(u32, u32)> {
    let mut spans: Vec<(u32, u32)> = spans.collect();
    spans.sort_unstable();
    let cuts: BTreeSet<u32> = spans.iter().flat_map(|&(start, end)| [start, end]).collect();
    let mut pieces = Vec::new();
    let mut covered: Option<(u32, u32)> = None;
    // each stretch covered w/o gaps, cut at every start and end in it
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

/// a func, the number'th of its unit
fn write_function(out: &mut String, program: &Program, scope: &Scope, entry: u32, function: &Function, number: usize) {
    let thumb = function.mode == Mode::Thumb;
    emit!(out, "uint32_t {}(Context *ctx) {{", name(scope.prefix, entry, thumb));
    emit!(out, "    STACK_CHECK();");
    let mut body = String::new();
    write_body(&mut body, program, scope, entry, function, number, None);
    out.push_str(&locals::keep(&body));
    emit!(out, "}}");
    out.push_str(locals::RESET);
    out.push('\n');
}

/// what a func does between its braces, noting where each instr's C sits when pieces is given
fn write_body(
    out: &mut String,
    program: &Program,
    scope: &Scope,
    entry: u32,
    function: &Function,
    number: usize,
    mut pieces: Option<&mut Vec<(u32, std::ops::Range<usize>)>>,
) {
    let thumb = function.mode == Mode::Thumb;
    let state = if thumb { "ctx->thumb" } else { "!ctx->thumb" };
    if scope.relative {
        emit!(out, "    const uint32_t module_base = {}base;", scope.prefix);
    }
    emit!(out, "    uint32_t target = ctx->r[15], resume = 0;");
    // a func only gets entered in its own state (callers and host lookups make sure), so no thumb check at entry
    // its start comes from memory, the host puts an addr nothing starts at there once it's stale
    // so calls pay for the check w/ the compare they do anyway, and misses go past the flag
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
    emit!(out, "    TAIL_CALL(recomp_call);");
    // where calls that come back anywhere else go
    emit!(out, "    RETURNED_ELSEWHERE();");

    let instructions = &function.instructions;
    for (i, &address) in instructions.iter().enumerate() {
        if function.labels.contains(&address) {
            let run = instructions[i + 1..].iter().take_while(|a| !function.labels.contains(a)).count() + 1;
            emit!(out, "L_{address:08X}:");
            emit!(out, "    BLOCK({}, {run});", scope.at(address));
        }
        let start = out.len();
        let (continues, size) = if thumb {
            let op = program.text.read16(address).unwrap_or(0) as u32;
            let second = program.text.read16(address + 2).unwrap_or(0) as u32;
            let size = crate::thumb::decode(op as u16, Some(second as u16), address).1;
            emit!(out, "    /* {address:08X} {op:04X} */");
            take_spans(out, scope, address);
            (thumb::lower(out, scope, address, op, second), size)
        } else {
            let op = program.text.read32(address).unwrap_or(0);
            emit!(out, "    /* {address:08X} {op:08X} */");
            // b4 the condition, which may skip the instr, but not the ones after it that use the span too
            take_spans(out, scope, address);
            (arm::lower(out, scope, address, op), 4)
        };
        if let Some(pieces) = pieces.as_mut() {
            pieces.push((address, start..out.len()));
        }
        let next = address + size;
        if continues && instructions.get(i + 1) != Some(&next) {
            emit!(out, "    target = {}; goto dispatch;", scope.at(next));
        }
    }
    emit!(out, "    OUT_OF_BUDGET();");
}

/// page table looks to take b4 the instr at address
fn take_spans(out: &mut String, scope: &Scope, address: u32) {
    for span in scope.plan.and_then(|plan| plan.before.get(&address)).into_iter().flatten() {
        emit!(out, "{}", hoist::take(span));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{self, Source};
    use crate::image::Segment;

    const BASE: u32 = 0x0010_0000;

    /// files for ARM code at BASE, entered at its start
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

    /// files for a func calling another, callee replaced
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

    /// two loads and two stores off r4 share one look each way, b4 the first of them, then go thru the spans delta bytes in
    #[test]
    fn accesses_off_one_register_share_a_look() {
        // ldr r0, [r4, #4], ldr r1, [r4, #8], str r0, [r4, #12],
        // strh r1, [r4, #16], bx lr
        let files = files(&[0xE594_0004, 0xE594_1008, 0xE584_000C, 0xE1C4_11B0, 0xE12F_FF1E], &[]);
        let code = &files["code000.c"];
        let read = code.find("const uint8_t *hs0_ = mem_read_span(ctx, reg4_ + 0x4u, 8u);").expect("a look for the loads");
        let write = code.find("uint8_t *hs1_ = mem_write_span(ctx, reg4_ + 0xCu, 6u);").expect("a look for the stores");
        let first = code.find("SPAN_READ32(hs0_, 0, oa)").expect("the first load through it");
        assert!(read < first && write < first);
        assert!(code.contains("SPAN_READ32(hs0_, 4, oa)"));
        assert!(code.contains("SPAN_WRITE32(hs1_, 0, oa, reg0_)"));
        assert!(code.contains("SPAN_WRITE16(hs1_, 4, oa, (uint16_t)reg1_)"));

        compiles("hoist", &files, &["code000.c"]);
    }

    /// after an svc (the host ran it) the code goes on into the next instr, where the host comes back in if it stops instead
    /// GetSystemTick, WaitSynchronizationN and ReleaseMutex the code can answer itself
    #[test]
    fn an_svc_goes_on_to_the_next_instruction() {
        // svceq 0x28, svc 0x32, bx lr
        let plain = files(&[0x0F00_0028, 0xEF00_0032, 0xE12F_FF1E], &[]);
        let code = &plain["code000.c"];
        let conditional = code.find("SVC_TICK(0x00100004u, 0u);").expect("the first svc");
        let svc = code.find("SVC(0x00100008u, 0x32u);").expect("the second svc");
        let next = code.find("L_00100008:").expect("a label after it");
        assert!(conditional < svc && svc < next);
        assert!(!code[svc..next].contains("goto"), "{}", &code[svc..next]);

        // Thumb, svc 0x28, bx lr
        let program = Program {
            text: Segment { base: BASE, bytes: [0xDF28u16, 0x4770].iter().flat_map(|h| h.to_le_bytes()).collect() },
            seeds: vec![(BASE | 1, Source::Entry)],
            slots: None,
        };
        let analysis = discover::analyze(&program);
        let units = [Unit { module: None, program: &program, analysis: &analysis }];
        let thumb: BTreeMap<String, String> = generate(&units, &[]).into_iter().collect();
        assert!(thumb["code000.c"].contains("SVC_TICK(0x00100002u, 1u);"), "{}", thumb["code000.c"]);

        // svc 0x25, svc 0x14, bx lr, and the same in Thumb
        let mutex = files(&[0xEF00_0025, 0xEF00_0014, 0xE12F_FF1E], &[]);
        assert!(mutex["code000.c"].contains("SVC_WAIT(0x00100004u, 0u);"), "{}", mutex["code000.c"]);
        assert!(mutex["code000.c"].contains("SVC_RELEASE(0x00100008u, 0u);"), "{}", mutex["code000.c"]);
        let program = Program {
            text: Segment { base: BASE, bytes: [0xDF25u16, 0xDF14, 0x4770].iter().flat_map(|h| h.to_le_bytes()).collect() },
            seeds: vec![(BASE | 1, Source::Entry)],
            slots: None,
        };
        let analysis = discover::analyze(&program);
        let units = [Unit { module: None, program: &program, analysis: &analysis }];
        let thumb_mutex: BTreeMap<String, String> = generate(&units, &[]).into_iter().collect();
        assert!(thumb_mutex["code000.c"].contains("SVC_WAIT(0x00100002u, 1u);"), "{}", thumb_mutex["code000.c"]);
        assert!(thumb_mutex["code000.c"].contains("SVC_RELEASE(0x00100004u, 1u);"), "{}", thumb_mutex["code000.c"]);

        compiles("svc", &plain, &["code000.c"]);
        compiles("thumb-svc", &thumb, &["code000.c"]);
        compiles("mutex-svc", &mutex, &["code000.c"]);
        compiles("thumb-mutex-svc", &thumb_mutex, &["code000.c"]);
    }

    /// a call checks where the callee came back to w/ one compare against its link (Thumb in bit 0)
    /// every func checks the stack first and keeps one exit for calls that came back elsewhere
    #[test]
    fn calls_compare_where_the_callee_came_back_to() {
        // bl BASE + 8, bx lr, bx lr
        let files = generated(&[]);
        let code = &files["code000.c"];
        assert!(code.contains("uint32_t f_00100000(Context *ctx) {\n    STACK_CHECK();"));
        assert!(code.contains("CALL_RETURNING(f_00100008, 0x00100004u);"));
        assert!(code.contains("    TAIL_CALL(recomp_call);\n    RETURNED_ELSEWHERE();"));
        assert!(!code.contains("RETURNED("));
        assert!(files["functions.h"].contains("uint32_t f_00100008(Context *ctx);"));

        // Thumb, bl BASE + 6 (two halves), bx lr, bx lr
        let program = Program {
            text: Segment { base: BASE, bytes: [0xF000u16, 0xF801, 0x4770, 0x4770].iter().flat_map(|h| h.to_le_bytes()).collect() },
            seeds: vec![(BASE | 1, Source::Entry)],
            slots: None,
        };
        let analysis = discover::analyze(&program);
        let units = [Unit { module: None, program: &program, analysis: &analysis }];
        let thumb: BTreeMap<String, String> = generate(&units, &[]).into_iter().collect();
        assert!(thumb["code000.c"].contains("CALL_RETURNING(t_00100006, (0x00100004u | 1));"), "{}", thumb["code000.c"]);
        compiles("calls", &files, &["code000.c"]);
        compiles("thumb-calls", &thumb, &["code000.c"]);
    }

    /// guest code run for real thru the tiniest host possible
    /// a callee coming back anywhere but its link sends the caller on from there
    /// recursion deeper than the host's C stack unwinds to the host, which carries on where it stopped
    #[cfg(feature = "host")]
    #[test]
    fn calls_come_back_and_unwind() {
        use recomp_abi::{Code, Context, Host, Library, EXIT_NONE, EXIT_UNWIND, STOPPED};
        use std::sync::atomic::{AtomicBool, Ordering};

        static WRONG: AtomicBool = AtomicBool::new(false);
        // nothing should need the host but lookups
        fn wrong() {
            WRONG.store(true, Ordering::Relaxed);
        }
        unsafe extern "C" fn read8(_: *mut Context, _: u32) -> u8 {
            wrong();
            0
        }
        unsafe extern "C" fn read16(_: *mut Context, _: u32) -> u16 {
            wrong();
            0
        }
        unsafe extern "C" fn read32(_: *mut Context, _: u32) -> u32 {
            wrong();
            0
        }
        unsafe extern "C" fn write8(_: *mut Context, _: u32, _: u8) {
            wrong();
        }
        unsafe extern "C" fn write16(_: *mut Context, _: u32, _: u16) {
            wrong();
        }
        unsafe extern "C" fn write32(_: *mut Context, _: u32, _: u32) {
            wrong();
        }
        unsafe extern "C" fn interpret(ctx: *mut Context, _: u32, _: u32) {
            wrong();
            (*ctx).exit = EXIT_UNWIND;
        }
        unsafe extern "C" fn svc(ctx: *mut Context, _: u32) {
            wrong();
            (*ctx).exit = EXIT_UNWIND;
        }
        unsafe extern "C" fn lookup(ctx: *mut Context, address: u32) -> Option<Code> {
            (*((*ctx).user as *const Library)).lookup(address)
        }
        static HOST: Host = Host { read8, read16, read32, write8, write16, write32, interpret, lookup, svc };

        let words: [u32; 18] = [
            // f = push {lr}, mov r0, #0, bl g, add r0, r0, #1, bl h,
            // add r0, r0, #100, pop {pc}
            0xE52D_E004, 0xE3A0_0000, 0xEB00_0003, 0xE280_0001, 0xEB00_0003, 0xE280_0064, 0xE49D_F004,
            // g = add lr, lr, #8, bx lr, comes back past f's add and bl h (sneaky)
            0xE28E_E008, 0xE12F_FF1E,
            // h = add r0, r0, #200, bx lr
            0xE280_00C8, 0xE12F_FF1E,
            // r = cmp r0, #0, bxeq lr, push {lr}, sub r0, r0, #1, bl r,
            // add r1, r1, #1, pop {pc}
            0xE350_0000, 0x012F_FF1E, 0xE52D_E004, 0xE240_0001, 0xEBFF_FFFA, 0xE281_1001, 0xE49D_F004,
        ];
        let program = Program {
            text: Segment { base: BASE, bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect() },
            seeds: vec![(BASE, Source::Entry), (BASE + 0x2C, Source::Entry)],
            slots: None,
        };
        let library = library("run", &program);

        // guest stack, directly reachable
        const STACK_TOP: u32 = 0x0810_0000;
        let mut stack = vec![0u8; 0x8_0000];
        let mut read_pages = vec![std::ptr::null_mut::<u8>(); 1 << 20];
        for (i, page) in stack.chunks_mut(0x1000).enumerate() {
            read_pages[(STACK_TOP as usize - 0x8_0000) / 0x1000 + i] = page.as_mut_ptr();
        }
        let write_pages = read_pages.clone();
        let (mut vfp, mut fpscr) = ([0u32; 32], 0u32);
        let mut ctx = Context {
            r: [0; 16],
            n: 0,
            z: 0,
            c: 0,
            v: 0,
            q: 0,
            thumb: 0,
            ge: 0,
            exclusive: 0,
            budget: 0,
            exit: 0,
            svc: 0,
            depth: 0,
            exclusive_address: 0,
            tls: 0,
            read_pages: read_pages.as_ptr(),
            write_pages: write_pages.as_ptr(),
            vfp: vfp.as_mut_ptr(),
            fpscr: &mut fpscr,
            host: &HOST,
            user: &library as *const Library as *mut std::ffi::c_void,
            stack_limit: 0,
            tick_end: 0,
            tick_last: 0,
            tick_floor: i32::MAX,
            tick_cost: 0,
            tick_at: recomp_abi::NO_TICKS,
            ticks: 0,
            wait_at: recomp_abi::NO_TICKS,
            release_at: recomp_abi::NO_TICKS,
            held: 0,
            holding: 0,
            held_floor: recomp_abi::NOTHING_HELD,
            done: 0,
            trail: [0; recomp_abi::TRAIL],
        };
        // where the guest returns to the host, no code lives there
        const DONE: u32 = 0x0020_0000;
        // runs from r15 till the guest returns to DONE, counting host entries and how many unwound
        let run = |ctx: &mut Context| {
            let (mut entries, mut unwound) = (0, 0);
            while ctx.r[15] != DONE {
                let code = library.lookup(ctx.r[15] | ctx.thumb as u32).expect("code for r15");
                ctx.exit = EXIT_NONE;
                ctx.budget = i32::MAX;
                ctx.stack_limit = recomp_abi::stack_limit();
                // safe bc the code came from the lib and the context has what it needs
                let back = unsafe { code(ctx) };
                entries += 1;
                match ctx.exit {
                    EXIT_NONE => assert_eq!(back, ctx.r[15]),
                    EXIT_UNWIND => {
                        assert_eq!(back, STOPPED);
                        assert_eq!(ctx.r[15], BASE + 0x2C, "unwound on the way into r");
                        unwound += 1;
                    }
                    other => panic!("exit {other}"),
                }
            }
            (entries, unwound)
        };

        ctx.r[13] = STACK_TOP;
        ctx.r[14] = DONE;
        ctx.r[15] = BASE;
        let (entries, unwound) = run(&mut ctx);
        // g came back past the add and the call to h
        assert_eq!(ctx.r[0], 100);
        assert_eq!((entries, unwound, ctx.r[13]), (1, 0, STACK_TOP));

        let deep = 60_000;
        ctx.r[0] = deep;
        ctx.r[1] = 0;
        ctx.r[14] = DONE;
        ctx.r[15] = BASE + 0x2C;
        let (entries, unwound) = run(&mut ctx);
        assert_eq!((ctx.r[0], ctx.r[1], ctx.r[13]), (0, deep, STACK_TOP));
        assert!(unwound >= 1 && entries > unwound, "{entries} entries, {unwound} unwound");
        assert!(!WRONG.load(Ordering::Relaxed), "the code asked the host for more than lookups");
    }

    /// the code for program, built and loaded, in a folder named after test while it builds
    #[cfg(feature = "host")]
    fn library(test: &str, program: &Program) -> recomp_abi::Library {
        let analysis = discover::analyze(program);
        let units = [Unit { module: None, program, analysis: &analysis }];
        let files = generate(&units, &[]);
        let dir = std::env::temp_dir().join(format!("3dsrecomp-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in &files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        let sources: Vec<String> = files.iter().map(|(name, _)| name.clone()).filter(|name| name.ends_with(".c")).collect();
        let path = dir.join(recomp_abi::library_name(1));
        let compiler = crate::compile::check(None).expect("a C compiler");
        crate::compile::compile(&compiler, &dir, &sources, &path, &|_, _| true, false).unwrap();
        let library = recomp_abi::Library::open(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        library
    }

    /// GetSystemTick for real, the code answers it at the one spot the host allows while budget > floor, host answers the rest
    #[cfg(feature = "host")]
    #[test]
    fn the_code_reads_the_clock_where_the_host_lets_it() {
        use recomp_abi::{Code, Context, Host, Library, EXIT_NONE};
        use std::sync::atomic::{AtomicU32, Ordering};

        static ASKED: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn read8(_: *mut Context, _: u32) -> u8 {
            0
        }
        unsafe extern "C" fn read16(_: *mut Context, _: u32) -> u16 {
            0
        }
        unsafe extern "C" fn read32(_: *mut Context, _: u32) -> u32 {
            0
        }
        unsafe extern "C" fn write8(_: *mut Context, _: u32, _: u8) {}
        unsafe extern "C" fn write16(_: *mut Context, _: u32, _: u16) {}
        unsafe extern "C" fn write32(_: *mut Context, _: u32, _: u32) {}
        unsafe extern "C" fn interpret(_: *mut Context, _: u32, _: u32) {}
        // the host's tick, which the code's never is
        unsafe extern "C" fn svc(ctx: *mut Context, number: u32) {
            assert_eq!(number, 0x28);
            ASKED.fetch_add(1, Ordering::Relaxed);
            (*ctx).r[0] = 7;
            (*ctx).r[1] = 0;
        }
        unsafe extern "C" fn lookup(ctx: *mut Context, address: u32) -> Option<Code> {
            (*((*ctx).user as *const Library)).lookup(address)
        }
        static HOST: Host = Host { read8, read16, read32, write8, write16, write32, interpret, lookup, svc };

        // svc 0x28, mov r2, r0, svc 0x28, bx lr
        let words = [0xEF00_0028u32, 0xE1A0_2000, 0xEF00_0028, 0xE12F_FF1E];
        let program = Program {
            text: Segment { base: BASE, bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect() },
            seeds: vec![(BASE, Source::Entry)],
            slots: None,
        };
        let library = library("ticks", &program);
        let (mut vfp, mut fpscr) = ([0u32; 32], 0u32);
        let pages = vec![std::ptr::null_mut::<u8>(); 1 << 20];
        let mut ctx = Context {
            r: [0; 16],
            n: 0,
            z: 0,
            c: 0,
            v: 0,
            q: 0,
            thumb: 0,
            ge: 0,
            exclusive: 0,
            budget: 0,
            exit: 0,
            svc: 0,
            depth: 0,
            exclusive_address: 0,
            tls: 0,
            read_pages: pages.as_ptr(),
            write_pages: pages.as_ptr(),
            vfp: vfp.as_mut_ptr(),
            fpscr: &mut fpscr,
            host: &HOST,
            user: &library as *const Library as *mut std::ffi::c_void,
            stack_limit: 0,
            tick_end: 1000,
            tick_last: 0,
            tick_floor: 10,
            tick_cost: 150,
            tick_at: BASE + 4,
            ticks: 0,
            wait_at: recomp_abi::NO_TICKS,
            release_at: recomp_abi::NO_TICKS,
            held: 0,
            holding: 0,
            held_floor: recomp_abi::NOTHING_HELD,
            done: 0,
            trail: [0; recomp_abi::TRAIL],
        };
        let run = |ctx: &mut Context, floor: i32| {
            ASKED.store(0, Ordering::Relaxed);
            (ctx.r[14], ctx.r[15], ctx.budget, ctx.ticks, ctx.tick_floor) = (0x0020_0000, BASE, 500, 0, floor);
            ctx.exit = EXIT_NONE;
            ctx.stack_limit = recomp_abi::stack_limit();
            let code = library.lookup(BASE).expect("code for the program");
            // safe bc the code came from the lib and the context has what it needs
            let back = unsafe { code(ctx) };
            assert_eq!((back, ctx.exit), (0x0020_0000, EXIT_NONE));
            ASKED.load(Ordering::Relaxed)
        };

        // 1st is the code's (clock minus budget), 2nd the host's, w/ the addr after it not the one the host named
        assert_eq!(run(&mut ctx, 10), 1);
        assert_eq!((ctx.r[0], ctx.ticks), (7, 1));
        assert_eq!(ctx.r[2] as u64, ctx.tick_last);
        assert!((1000 - 500..=1000 - 496).contains(&ctx.tick_last), "{}", ctx.tick_last);
        assert_eq!(ctx.budget, 500 - 4 - 150, "four instructions and a tick");

        // budget at or below the floor, host answers both
        assert_eq!(run(&mut ctx, 500), 2);
        assert_eq!((ctx.r[0], ctx.r[2], ctx.ticks, ctx.budget), (7, 7, 0, 500 - 4));
    }

    /// WaitSynchronizationN and ReleaseMutex for real
    /// the code takes and drops the lent mutex itself where the host allows while budget > floor, logging each in the trail w/ the ticks
    /// host answers the rest
    #[cfg(feature = "host")]
    #[test]
    fn the_code_takes_the_mutex_the_host_lends_it() {
        use recomp_abi::{Code, Context, Host, Library, EXIT_NONE, TRAIL};
        use std::sync::Mutex;

        static ASKED: Mutex<Vec<u32>> = Mutex::new(Vec::new());
        unsafe extern "C" fn read8(_: *mut Context, _: u32) -> u8 {
            0
        }
        unsafe extern "C" fn read16(_: *mut Context, _: u32) -> u16 {
            0
        }
        unsafe extern "C" fn read32(_: *mut Context, _: u32) -> u32 {
            0
        }
        unsafe extern "C" fn write8(_: *mut Context, _: u32, _: u8) {}
        unsafe extern "C" fn write16(_: *mut Context, _: u32, _: u16) {}
        unsafe extern "C" fn write32(_: *mut Context, _: u32, _: u32) {}
        unsafe extern "C" fn interpret(_: *mut Context, _: u32, _: u32) {}
        unsafe extern "C" fn svc(ctx: *mut Context, number: u32) {
            ASKED.lock().unwrap().push(number);
            let r = &mut (*ctx).r;
            match number {
                0x25 => (r[0], r[1]) = (0, 0),
                0x14 => r[0] = 0,
                _ => (r[0], r[1]) = (7, 0),
            }
        }
        unsafe extern "C" fn lookup(ctx: *mut Context, address: u32) -> Option<Code> {
            (*((*ctx).user as *const Library)).lookup(address)
        }
        static HOST: Host = Host { read8, read16, read32, write8, write16, write32, interpret, lookup, svc };

        // svc 0x25, mov r0, r5, svc 0x14, svc 0x28, bx lr
        let words = [0xEF00_0025u32, 0xE1A0_0005, 0xEF00_0014, 0xEF00_0028, 0xE12F_FF1E];
        let program = Program {
            text: Segment { base: BASE, bytes: words.iter().flat_map(|w| w.to_le_bytes()).collect() },
            seeds: vec![(BASE, Source::Entry)],
            slots: None,
        };
        let library = library("mutex", &program);
        // where the handles are, a reachable page and its last word
        const HANDLES: u32 = 0x0810_0000;
        const HELD: u32 = 0x0001_0012;
        let mut page = vec![0u8; 0x1000];
        page[..4].copy_from_slice(&HELD.to_le_bytes());
        page[0xFFC..].copy_from_slice(&HELD.to_le_bytes());
        page[8..12].copy_from_slice(&0x0001_0013u32.to_le_bytes());
        let mut pages = vec![std::ptr::null_mut::<u8>(); 1 << 20];
        pages[HANDLES as usize >> 12] = page.as_mut_ptr();
        let (mut vfp, mut fpscr) = ([0u32; 32], 0u32);
        let mut ctx = Context {
            r: [0; 16],
            n: 0,
            z: 0,
            c: 0,
            v: 0,
            q: 0,
            thumb: 0,
            ge: 0,
            exclusive: 0,
            budget: 0,
            exit: 0,
            svc: 0,
            depth: 0,
            exclusive_address: 0,
            tls: 0,
            read_pages: pages.as_ptr(),
            write_pages: pages.as_ptr(),
            vfp: vfp.as_mut_ptr(),
            fpscr: &mut fpscr,
            host: &HOST,
            user: &library as *const Library as *mut std::ffi::c_void,
            stack_limit: 0,
            tick_end: 1000,
            tick_last: 0,
            tick_floor: 10,
            tick_cost: 150,
            tick_at: BASE + 0x10,
            ticks: 0,
            wait_at: BASE + 4,
            release_at: BASE + 0xC,
            held: HELD,
            holding: 0,
            held_floor: 10,
            done: 0,
            trail: [0; TRAIL],
        };
        // runs the program from the top w/ the handles at handles, count of them, the released handle in r5, and floor
        let run = |ctx: &mut Context, handles: u32, count: u32, floor: i32| {
            ASKED.lock().unwrap().clear();
            (ctx.r[14], ctx.r[15], ctx.budget, ctx.ticks) = (0x0020_0000, BASE, 500, 0);
            (ctx.r[1], ctx.r[2], ctx.r[5], ctx.held_floor) = (handles, count, HELD, floor);
            ctx.exit = EXIT_NONE;
            ctx.stack_limit = recomp_abi::stack_limit();
            let code = library.lookup(BASE).expect("code for the program");
            // safe bc the code came from the lib and the context has what it needs
            let back = unsafe { code(ctx) };
            assert_eq!((back, ctx.exit), (0x0020_0000, EXIT_NONE));
            std::mem::take(&mut *ASKED.lock().unwrap())
        };

        // the code takes it, drops it and reads the clock, all by itself
        ctx.done = 0;
        assert_eq!(run(&mut ctx, HANDLES, 1, 10), []);
        assert_eq!((ctx.holding, ctx.done, ctx.ticks, ctx.r[0], ctx.r[1]), (0, 3, 1, ctx.tick_last as u32, 0));
        assert!((1000 - 500..=1000 - 495).contains(&ctx.tick_last), "{}", ctx.tick_last);
        assert_eq!(ctx.trail[..3], [BASE + 4, BASE + 0xC, BASE + 0x10]);
        assert_eq!(ctx.budget, 500 - 5 - 150, "five instructions and a tick");
        // last word of a page, held once already
        (ctx.holding, ctx.done) = (1, 0);
        assert_eq!(run(&mut ctx, HANDLES + 0xFFC, 1, 10), []);
        assert_eq!((ctx.holding, ctx.done), (1, 3));
        // the trail wraps around
        (ctx.holding, ctx.done) = (0, TRAIL as u32 - 1);
        assert_eq!(run(&mut ctx, HANDLES, 1, 10), []);
        assert_eq!((ctx.done, ctx.trail[TRAIL - 1], ctx.trail[0], ctx.trail[1]), (TRAIL as u32 + 2, BASE + 4, BASE + 0xC, BASE + 0x10));
        ctx.done = 0;

        // host answers another handle, two of them, one past the page or on none, and releasing a mutex the thread doesn't hold
        assert_eq!(run(&mut ctx, HANDLES + 8, 1, 10), [0x25, 0x14]);
        assert_eq!(run(&mut ctx, HANDLES, 2, 10), [0x25, 0x14]);
        assert_eq!(run(&mut ctx, HANDLES + 0xFFE, 1, 10), [0x25, 0x14]);
        assert_eq!(run(&mut ctx, HANDLES + 0x1000, 1, 10), [0x25, 0x14]);
        // only the ticks went in the trail
        assert_eq!((ctx.holding, ctx.done, ctx.ticks), (0, 4, 1));
        assert_eq!(ctx.trail[..4], [BASE + 0x10; 4]);
        // plus waits and releases at or below the floor, not the tick
        ctx.done = 0;
        assert_eq!(run(&mut ctx, HANDLES, 1, 500), [0x25, 0x14]);
        assert_eq!((ctx.holding, ctx.done, ctx.ticks), (0, 1, 1));
    }

    /// compiles sources among files in their own folder named after test, panics w/ the compiler's whining if they don't
    fn compiles(test: &str, files: &BTreeMap<String, String>, sources: &[&str]) {
        let dir = std::env::temp_dir().join(format!("3dsrecomp-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        let compiler = crate::compile::check(None).expect("a C compiler");
        let built = crate::compile::objects(&compiler, &dir, &sources, &|_, _| true, false);
        std::fs::remove_dir_all(&dir).ok();
        built.unwrap();
    }

    /// every func checks its stale flag first, the tables say what it came from, a span per run of instrs and their bytes' hash
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
        // a func each, one run of one piece each
        assert!(tables.contains("static const Run origin_runs[] = {\n    {0, 1},\n    {1, 2},\n};"), "{tables}");
        assert!(tables.contains("RECOMP_EXPORT const Origins recomp_origins[] = {\n    {2, 2, origin_pieces, origin_functions, origin_runs, origin_owners, recomp_stale, recomp_starts},"));

        compiles("origins", &files, &["code000.c", "entries.c"]);
    }

    /// code several funcs hold gets cut where any of them starts or ends, each func's code is whole pieces
    #[test]
    fn overlapping_code_is_cut_into_pieces() {
        let pieces = pieces([(0x100, 0x120), (0x110, 0x118), (0x118, 0x130), (0x200, 0x204)].into_iter());
        assert_eq!(pieces, [(0x100, 0x110), (0x110, 0x118), (0x118, 0x120), (0x120, 0x130), (0x200, 0x204)]);
    }

    /// a file w/ funcs from the exe and a module declares what both use
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
        TAIL_CALL(RECOMP_ORIGINAL(0x00100008));
    }
    if (ctx->r[0] == 1) {
        CALL(RECOMP_ORIGINAL(0x00100008));
        ctx->r[0] += 1;
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
        assert!(code.contains("CALL_RETURNING(override_0x00100008, 0x00100004u);"));
        assert!(files["functions.h"].contains("uint32_t override_0x00100008(Context *ctx);"));
        assert!(files["entries.c"].contains("{0x00100008u, override_0x00100008},"));
        assert!(files["entries.c"].contains(&format!("recomp_generation = {}u;", recomp_abi::GENERATION)));
        let header = &files["overrides.h"];
        assert!(header.contains("static inline uint32_t original_0x00100008(Context *ctx) {"));
        assert!(header.contains("return f_00100008(ctx);"));

        // no overrides, nothing changes
        let plain = generated(&[]);
        assert!(plain["code000.c"].contains("CALL_RETURNING(f_00100008, 0x00100004u);"));
        assert!(!plain.contains_key("overrides.h"));
    }
}
