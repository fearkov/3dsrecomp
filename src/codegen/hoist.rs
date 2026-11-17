//! one page table look for all the loads and stores a stretch of code makes off the same reg plus a const, not one each
//! a stretch runs from a label (or the host's last turn) to the next of either
//! along it nothing takes a page from the code, accesses the host handles only give pages back (docs/interface.md)
//! so a look's span stays good while the reg keeps its value, each access then just tests that the look found its page

use std::collections::{BTreeMap, BTreeSet};

/// a load or store at reg plus const, in the order the instr makes them
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Access {
    /// the instr's addr
    pub at: u32,
    pub base: u32,
    pub offset: i32,
    pub size: u32,
    pub write: bool,
}

/// the span covering a load or store, and where in it the access starts
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Covered {
    pub span: String,
    pub delta: u32,
}

/// a look to take b4 an instr, at reg plus const, for length bytes
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Span {
    pub name: String,
    pub base: u32,
    pub offset: i32,
    pub length: u32,
    pub write: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Plan {
    /// looks to take b4 each instr
    pub before: BTreeMap<u32, Vec<Span>>,
    /// accesses a span covers, by instr and their order in it
    pub covered: BTreeMap<(u32, usize), Covered>,
}

/// max bytes a span covers, keeps it from crossing pages except rarely, a func's frame and struct fields fit
const MOST: i64 = 512;

/// words in an instr's C that hand control to the host or other code
/// they can do anything to the page tables and locals get reloaded after
const TURNS: &[&str] =
    &["CALL(", "CALL_RETURNING(", "SVC(", "SVC_TICK(", "SVC_WAIT(", "SVC_RELEASE(", "INTERPRET(", "RETURN", "JUMP_TO(", "VFP_VECTOR(", "OUT_OF_BUDGET", "SYNC_"];

/// does an instr's C let the host or other code run
fn turns(text: &str) -> bool {
    TURNS.iter().any(|word| text.contains(word))
}

/// regs an instr's C may write, by assignment, compound assignment, increment or taking their addr
fn written(text: &str) -> BTreeSet<u32> {
    let mut registers = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(found) = text[from..].find("ctx->r[") {
        let start = from + found;
        let digits = start + "ctx->r[".len();
        let length = bytes[digits..].iter().take_while(|b| b.is_ascii_digit()).count();
        from = digits + length;
        let (Ok(register), Some(b']')) = (text[digits..digits + length].parse::<u32>(), bytes.get(from).copied()) else {
            continue;
        };
        let after = text[from + 1..].trim_start();
        let assigned = (after.starts_with('=') && !after.starts_with("=="))
            || ["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "++", "--"].iter().any(|op| after.starts_with(op));
        let before = text[..start].trim_end();
        let taken = (before.ends_with('&') && !before.ends_with("&&")) || before.ends_with("++") || before.ends_with("--");
        if assigned || taken {
            registers.insert(register);
        }
    }
    registers
}

/// accesses off one reg w/o a write to it between, from the instr the look goes b4
struct Group {
    first: u32,
    members: Vec<((u32, usize), Access)>,
}

/// looks for a func given its labels and each instr's addr and C in order, plus the accesses they made
pub(crate) fn plan(labels: &BTreeSet<u32>, lowered: &[(u32, &str)], accesses: &[Access]) -> Plan {
    let mut by_instruction: BTreeMap<u32, Vec<Access>> = BTreeMap::new();
    for access in accesses {
        by_instruction.entry(access.at).or_default().push(*access);
    }
    let mut groups: Vec<Group> = Vec::new();
    // the group still open for each reg
    let mut open: BTreeMap<u32, usize> = BTreeMap::new();
    for &(at, text) in lowered {
        if labels.contains(&at) {
            open.clear();
        }
        if turns(text) {
            open.clear();
            continue;
        }
        for (ordinal, access) in by_instruction.get(&at).into_iter().flatten().enumerate() {
            let group = *open.entry(access.base).or_insert_with(|| {
                groups.push(Group { first: at, members: Vec::new() });
                groups.len() - 1
            });
            groups[group].members.push(((at, ordinal), *access));
        }
        for register in written(text) {
            open.remove(&register);
        }
    }

    let mut plan = Plan::default();
    let mut names = 0;
    for group in groups {
        for write in [false, true] {
            let mut members: Vec<&((u32, usize), Access)> = group.members.iter().filter(|(_, a)| a.write == write).collect();
            members.sort_by_key(|(_, access)| access.offset);
            // runs of them close enough for one look
            let mut i = 0;
            while i < members.len() {
                let start = members[i].1.offset as i64;
                let mut end = start + members[i].1.size as i64;
                let mut j = i;
                while let Some((_, next)) = members.get(j + 1) {
                    let reach = end.max(next.offset as i64 + next.size as i64);
                    if reach - start > MOST {
                        break;
                    }
                    end = reach;
                    j += 1;
                }
                if j > i {
                    let name = format!("hs{names}_");
                    names += 1;
                    let base = members[i].1.base;
                    plan.before.entry(group.first).or_default().push(Span {
                        name: name.clone(),
                        base,
                        offset: start as i32,
                        length: (end - start) as u32,
                        write,
                    });
                    for (key, access) in &members[i..=j] {
                        let delta = (access.offset as i64 - start) as u32;
                        plan.covered.insert(*key, Covered { span: name.clone(), delta });
                    }
                }
                i = j + 1;
            }
        }
    }
    plan
}

/// the C taking a span, goes b4 its instr
pub(crate) fn take(span: &Span) -> String {
    let base = format!("ctx->r[{}]", span.base);
    let at = match span.offset {
        0 => base,
        offset if offset < 0 => format!("{base} - 0x{:X}u", offset.unsigned_abs()),
        offset => format!("{base} + 0x{offset:X}u"),
    };
    if span.write {
        format!("    uint8_t *{} = mem_write_span(ctx, {at}, {}u);", span.name, span.length)
    } else {
        format!("    const uint8_t *{} = mem_read_span(ctx, {at}, {}u);", span.name, span.length)
    }
}

/// a load of size bytes from address, thru the covering span if there is one
pub(crate) fn read(covered: Option<Covered>, size: u32, address: &str) -> String {
    match covered {
        Some(Covered { span, delta }) => format!("SPAN_READ{}({span}, {delta}, {address})", size * 8),
        None => format!("mem_read{}(ctx, {address})", size * 8),
    }
}

/// a store of size bytes of value at address, same deal, as a statement w/o its semicolon
pub(crate) fn write(covered: Option<Covered>, size: u32, address: &str, value: &str) -> String {
    match covered {
        Some(Covered { span, delta }) => format!("SPAN_WRITE{}({span}, {delta}, {address}, {value})", size * 8),
        None => format!("mem_write{}(ctx, {address}, {value})", size * 8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(at: u32, base: u32, offset: i32, size: u32, write: bool) -> Access {
        Access { at, base, offset, size, write }
    }

    /// two loads off r4 share a look, a third after r4 changes gets its own group, a load after a call stays as is
    #[test]
    fn loads_off_one_register_share_a_look_until_it_changes() {
        let lowered = [
            (0x100, "ctx->r[0] = mem_read32(ctx, ctx->r[4] + 0x4u);"),
            (0x102, "ctx->r[1] = mem_read32(ctx, ctx->r[4] + 0x8u);"),
            (0x104, "ctx->r[4] = ctx->r[4] + 0x10u;"),
            (0x106, "ctx->r[2] = mem_read32(ctx, ctx->r[4] + 0x0u);"),
            (0x108, "ctx->r[3] = mem_read32(ctx, ctx->r[5] + 0x0u);"),
            (0x10A, "CALL(f_00100000);"),
            (0x10C, "ctx->r[3] = mem_read32(ctx, ctx->r[5] + 0x4u);"),
        ];
        let accesses = [
            access(0x100, 4, 4, 4, false),
            access(0x102, 4, 8, 4, false),
            access(0x106, 4, 0, 4, false),
            access(0x108, 5, 0, 4, false),
            access(0x10C, 5, 4, 4, false),
        ];
        let plan = plan(&BTreeSet::new(), &lowered, &accesses);
        assert_eq!(plan.before.len(), 1);
        let span = &plan.before[&0x100][0];
        assert_eq!((span.base, span.offset, span.length, span.write), (4, 4, 8, false));
        assert_eq!(plan.covered[&(0x100, 0)].delta, 0);
        assert_eq!(plan.covered[&(0x102, 0)].delta, 4);
        assert_eq!(plan.covered.len(), 2);
        assert_eq!(take(span), "    const uint8_t *hs0_ = mem_read_span(ctx, ctx->r[4] + 0x4u, 8u);");
    }

    /// a label restarts the stretch, loads and stores look separately, accesses too far apart get their own looks
    #[test]
    fn labels_directions_and_distance_split_looks() {
        let lowered = [
            (0x200, "mem_write32(ctx, ctx->r[13] + 0x0u, ctx->r[0]);"),
            (0x204, "ctx->r[1] = mem_read32(ctx, ctx->r[13] + 0x4u);"),
            (0x208, "mem_write32(ctx, ctx->r[13] + 0x8u, ctx->r[1]);"),
            (0x20C, "ctx->r[2] = mem_read32(ctx, ctx->r[13] + 0x400u);"),
            (0x210, "ctx->r[3] = mem_read32(ctx, ctx->r[13] + 0x404u);"),
            (0x214, "ctx->r[3] = mem_read32(ctx, ctx->r[13] - 0x4u);"),
            (0x218, "ctx->r[3] = mem_read32(ctx, ctx->r[13] + 0x0u);"),
        ];
        let accesses = [
            access(0x200, 13, 0, 4, true),
            access(0x204, 13, 4, 4, false),
            access(0x208, 13, 8, 4, true),
            access(0x20C, 13, 0x400, 4, false),
            access(0x210, 13, 0x404, 4, false),
            access(0x214, 13, -4, 4, false),
            access(0x218, 13, 0, 4, false),
        ];
        let labels: BTreeSet<u32> = [0x214].into();
        let plan = plan(&labels, &lowered, &accesses);
        let first: Vec<(i32, u32, bool)> = plan.before[&0x200].iter().map(|s| (s.offset, s.length, s.write)).collect();
        // the read at 4 alone, then 0x400 and 0x404 together, the two writes
        assert_eq!(first, [(0x400, 8, false), (0, 12, true)]);
        assert!(!plan.covered.contains_key(&(0x204, 0)));
        assert_eq!(plan.covered[&(0x208, 0)].delta, 8);
        let after: Vec<(i32, u32)> = plan.before[&0x214].iter().map(|s| (s.offset, s.length)).collect();
        assert_eq!(after, [(-4, 8)]);
        assert_eq!(take(&plan.before[&0x214][0]), "    const uint8_t *hs2_ = mem_read_span(ctx, ctx->r[13] - 0x4u, 8u);");
    }

    #[test]
    fn writes_are_told_from_reads() {
        assert_eq!(written("ctx->r[3] = ctx->r[4]; ctx->r[5] += 1; ctx->r[6]++; f(&ctx->r[7]); x = ctx->r[8] == 1;"), [3, 5, 6, 7].into());
        assert!(written("if (ctx->r[1] && ctx->r[2]) ctx->n = 1;").is_empty());
    }
}
