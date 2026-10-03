//! keeping the guest's registers, flags and fpscr in locals for the length
//! of a function, with the budget and the page tables. in the context,
//! every store to guest memory, which goes through a byte pointer, makes the
//! compiler read them all again, while locals it can hold in host registers.
//!
//! the context has to be complete whenever anything else can look at it, a
//! call, the interpreter, a short vector, a return, an svc, a jump through
//! dispatch, the end of the budget. recomp.h's SYNC_OUT stores the locals
//! there, and SYNC_IN takes them all again after. SYNC_OUT only stores the
//! locals that may have changed since the context last had them, which a
//! pass over the function's lines works out, and each line that syncs gets
//! the SYNC_OUT it needs defined before it. that keeps a call from storing
//! every register the function ever writes, and lets the compiler drop the
//! loads of the registers a function writes before it reads them.

use std::collections::BTreeMap;
use std::fmt::Write;

/// what puts the default SYNC_OUT, SYNC_IN, BUDGET_LEFT, page tables and
/// fpscr back after a function, for whatever follows it in the file.
pub const RESET: &str = "#undef SYNC_OUT\n#undef SYNC_IN\n#undef BUDGET_LEFT\n#undef READ_PAGES\n#undef WRITE_PAGES\n#undef FPSCR\n\
#define SYNC_OUT() do { } while (0)\n#define SYNC_IN() do { } while (0)\n#define BUDGET_LEFT ctx->budget\n\
#define READ_PAGES(c) ((c)->read_pages)\n#define WRITE_PAGES(c) ((c)->write_pages)\n#define FPSCR(c) (*(c)->fpscr)\n";

/// the conditions recomp.h spells with the context's flags, spelled with
/// the locals, and the flags each reads.
const CONDITIONS: &[(&str, &str, &str)] = &[
    ("C_EQ", "(flag_z_)", "z"),
    ("C_NE", "(!flag_z_)", "z"),
    ("C_CS", "(flag_c_)", "c"),
    ("C_CC", "(!flag_c_)", "c"),
    ("C_MI", "(flag_n_)", "n"),
    ("C_PL", "(!flag_n_)", "n"),
    ("C_VS", "(flag_v_)", "v"),
    ("C_VC", "(!flag_v_)", "v"),
    ("C_HI", "(flag_c_ && !flag_z_)", "cz"),
    ("C_LS", "(!flag_c_ || flag_z_)", "cz"),
    ("C_GE", "(flag_n_ == flag_v_)", "nv"),
    ("C_LT", "(flag_n_ != flag_v_)", "nv"),
    ("C_GT", "(!flag_z_ && flag_n_ == flag_v_)", "znv"),
    ("C_LE", "(flag_z_ || flag_n_ != flag_v_)", "znv"),
];

const ASSIGNMENTS: &[&str] = &["<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "++", "--"];

/// the words that make what follows them run only sometimes.
const GUARDS: &[&str] = &["if", "else", "switch", "case", "for", "while"];

/// the locals are numbered r0 to r15, then the flags, then s0 to s31, then
/// fpscr.
const FLAGS: [char; 4] = ['n', 'z', 'c', 'v'];
const FLAG: usize = 16;
const VFP: usize = 20;
const FPSCR: usize = 52;

/// a set of locals, a bit for each.
type Set = u64;

fn identifier(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// the local numbered index, its type, and where it lives in the context.
fn local(index: usize) -> (String, &'static str, String) {
    match index {
        0..FLAG => (format!("reg{index}_"), "uint32_t", format!("ctx->r[{index}]")),
        FLAG..VFP => {
            let name = FLAGS[index - FLAG];
            (format!("flag_{name}_"), "uint8_t", format!("ctx->{name}"))
        }
        VFP..FPSCR => (format!("vfp{}_", index - VFP), "uint32_t", format!("ctx->vfp[{}]", index - VFP)),
        _ => ("fpscr_".to_owned(), "uint32_t", "*ctx->fpscr".to_owned()),
    }
}

/// a SYNC_OUT that stores the locals in set, and the budget when the
/// function counts one.
fn sync_out(set: Set, budget: bool) -> String {
    let mut stores = String::new();
    for index in (0..=FPSCR).filter(|index| set & (1 << index) != 0) {
        let (name, _, home) = local(index);
        write!(stores, "{home} = {name}; ").unwrap();
    }
    if budget {
        stores.push_str("ctx->budget = budget_; ");
    }
    format!("#undef SYNC_OUT\n#define SYNC_OUT() do {{ {stores}}} while (0)\n")
}

/// whether the token ending at end, and starting at start, is written, by an
/// assignment after it, an increment around it, or its address taken.
fn written(text: &[u8], start: usize, end: usize) -> bool {
    let after = &text[end..];
    let skipped = after.iter().take_while(|b| **b == b' ').count();
    let after = &after[skipped..];
    if after.first() == Some(&b'=') && after.get(1) != Some(&b'=') {
        return true;
    }
    if ASSIGNMENTS.iter().any(|op| after.starts_with(op.as_bytes())) {
        return true;
    }
    let before = &text[..start];
    let before = &before[..before.len() - before.iter().rev().take_while(|b| **b == b' ').count()];
    let address = before.last() == Some(&b'&') && before.get(before.len().wrapping_sub(2)) != Some(&b'&');
    address || before.ends_with(b"++") || before.ends_with(b"--")
}

/// the number text starts with, and how many digits it has.
fn number(text: &[u8]) -> Option<(u32, usize)> {
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    let value = std::str::from_utf8(&text[..digits]).ok()?.parse().ok()?;
    Some((value, digits))
}

/// the register number after prefix in text, and where what follows it
/// starts, when text is prefix, a number and then close.
fn indexed(text: &[u8], prefix: &str, close: &str) -> Option<(u32, usize)> {
    let rest = text.strip_prefix(prefix.as_bytes())?;
    let (value, digits) = number(rest)?;
    rest[digits..].starts_with(close.as_bytes()).then_some((value, prefix.len() + digits + close.len()))
}

/// what a line does that matters to which locals the context is behind on.
enum Event {
    /// a local takes a new value.
    Write(usize),
    /// the context has to be complete for a call, the interpreter or a
    /// short vector, and the locals are taken again after it.
    Sync,
    /// leaving the function, by a return or an svc, with the context
    /// complete.
    Leave,
    /// a jump through dispatch, which syncs first, so the labels it reaches
    /// start with the context complete.
    Dispatch,
    /// a jump to one of the function's labels.
    Goto(String),
    /// a block's budget check.
    Budget,
}

/// a line of the function, its locals in place, and what it does in order,
/// each with whether a condition guards it so that it may not happen.
struct Line {
    text: String,
    label: Option<String>,
    events: Vec<(Event, bool)>,
}

/// where the scan stands in the function's blocks, whether a condition
/// guards each open brace, and whether one guards the current statement.
#[derive(Default)]
struct Blocks {
    open: Vec<bool>,
    statement: bool,
}

impl Blocks {
    fn guarded(&self) -> bool {
        self.statement || self.open.iter().any(|guarded| *guarded)
    }
}

/// a line with the registers, flags, VFP registers and fpscr it touches as
/// locals, adding each to used.
fn scan(line: &str, used: &mut Set, blocks: &mut Blocks) -> Line {
    let text = line.as_bytes();
    let trimmed = line.trim();
    let label = if trimmed == "dispatch:" {
        Some("dispatch".to_owned())
    } else if trimmed.starts_with("L_") && trimmed.ends_with(':') && !trimmed.contains(' ') {
        Some(trimmed[..trimmed.len() - 1].to_owned())
    } else {
        None
    };
    let mut out = String::with_capacity(line.len() + 16);
    let mut events = Vec::new();
    let mut i = 0;
    let mut copied = 0;
    // puts with in place of the text from i to end, and goes on after it
    macro_rules! swap {
        ($end:expr, $($with:tt)*) => {{
            let end = $end;
            out.push_str(&line[copied..i]);
            write!(out, $($with)*).unwrap();
            i = end;
            copied = end;
            continue;
        }};
    }
    macro_rules! write_to {
        ($index:expr) => {
            events.push((Event::Write($index), blocks.guarded()))
        };
    }
    while i < text.len() {
        let rest = &text[i..];
        // the comment before each instruction, its address and opcode
        if rest.starts_with(b"/*") {
            i += rest.windows(2).position(|w| w == b"*/").map_or(rest.len(), |at| at + 2);
            continue;
        }
        match rest[0] {
            b'{' => {
                blocks.open.push(blocks.statement);
                blocks.statement = false;
            }
            b'}' => {
                blocks.open.pop();
                blocks.statement = false;
            }
            b';' => blocks.statement = false,
            b'?' => blocks.statement = true,
            _ => {}
        }
        if let Some((n, length)) = indexed(rest, "ctx->r[", "]") {
            *used |= 1 << n;
            if written(text, i, i + length) {
                write_to!(n as usize);
            }
            swap!(i + length, "reg{n}_");
        }
        if let Some((n, length)) = indexed(rest, "ctx->vfp[", "]") {
            *used |= 1 << (VFP + n as usize);
            if written(text, i, i + length) {
                write_to!(VFP + n as usize);
            }
            swap!(i + length, "vfp{n}_");
        }
        if rest.starts_with(b"*ctx->fpscr") && !rest.get(11).is_some_and(|b| identifier(*b)) {
            *used |= 1 << FPSCR;
            if written(text, i, i + 11) {
                write_to!(FPSCR);
            }
            swap!(i + 11, "fpscr_");
        }
        if i > 0 && identifier(text[i - 1]) {
            i += 1;
            continue;
        }
        let word = rest.iter().take_while(|b| identifier(**b)).count();
        if GUARDS.iter().any(|guard| guard.as_bytes() == &rest[..word]) {
            blocks.statement = true;
        }
        if rest.starts_with(b"ctx->") && rest.len() > 5 {
            let name = rest[5];
            let single = !rest.get(6).is_some_and(|b| identifier(*b));
            if let Some(flag) = FLAGS.iter().position(|f| *f as u8 == name).filter(|_| single) {
                *used |= 1 << (FLAG + flag);
                if written(text, i, i + 6) {
                    write_to!(FLAG + flag);
                }
                swap!(i + 6, "flag_{}_", name as char);
            }
        }
        if let Some((_, expansion, flags)) = CONDITIONS.iter().find(|(name, ..)| name.as_bytes() == &rest[..word]) {
            for flag in flags.chars() {
                *used |= 1 << (FLAG + FLAGS.iter().position(|f| *f == flag).expect("a flag"));
            }
            swap!(i + word, "{expansion}");
        }
        if rest.starts_with(b"vfp_") {
            // a double is two singles, 2N and 2N + 1
            if let Some((n, length)) = indexed(rest, "vfp_s(ctx, ", ")") {
                *used |= 1 << (VFP + n as usize);
                swap!(i + length, "vfp_from_s(vfp{n}_)");
            }
            if let Some((d, length)) = indexed(rest, "vfp_d(ctx, ", ")") {
                *used |= 3 << (VFP + 2 * d as usize);
                swap!(i + length, "vfp_from_d(vfp{}_, vfp{}_)", 2 * d, 2 * d + 1);
            }
            // the value that follows closes what replaces the start
            if let Some((n, length)) = indexed(rest, "vfp_set_s(ctx, ", ", ") {
                *used |= 1 << (VFP + n as usize) | 1 << FPSCR;
                write_to!(VFP + n as usize);
                swap!(i + length, "vfp{n}_ = vfp_to_s(ctx, ");
            }
            if let Some((d, length)) = indexed(rest, "vfp_set_d(ctx, ", ", ") {
                *used |= 3 << (VFP + 2 * d as usize) | 1 << FPSCR;
                write_to!(VFP + 2 * d as usize);
                write_to!(VFP + 2 * d as usize + 1);
                swap!(i + length, "VFP_SET_D(vfp{}_, vfp{}_, ", 2 * d, 2 * d + 1);
            }
            if rest.starts_with(b"vfp_vector(") {
                events.push((Event::Sync, blocks.guarded()));
                swap!(i + 11, "VFP_VECTOR(");
            }
            if rest.starts_with(b"vfp_compare(") {
                *used |= 1 << FPSCR;
                write_to!(FPSCR);
            }
        }
        let guarded = blocks.guarded();
        match &rest[..word] {
            b"CALL" | b"INTERPRET" => events.push((Event::Sync, guarded)),
            b"RETURN" | b"RETURN_TO" | b"SVC" => events.push((Event::Leave, guarded)),
            b"JUMP_TO" => events.push((Event::Dispatch, guarded)),
            b"BLOCK" => events.push((Event::Budget, guarded)),
            b"goto" if rest.starts_with(b"goto dispatch;") => {
                events.push((Event::Dispatch, guarded));
                // one statement still, should it follow a bare if, and the
                // statement ends with it
                blocks.statement = false;
                swap!(i + 14, "{{ SYNC_OUT(); goto dispatch; }}");
            }
            b"goto" if rest.starts_with(b"goto L_") => {
                let length = rest[7..].iter().take_while(|b| b.is_ascii_hexdigit()).count();
                events.push((Event::Goto(line[i + 5..i + 7 + length].to_owned()), guarded));
            }
            _ => {}
        }
        i += word.max(1);
    }
    out.push_str(&line[copied..]);
    Line { text: out, label, events }
}

/// the body with the registers, flags and fpscr it uses in locals, loaded
/// first, SYNC_IN defined for them, and before each line that syncs the
/// SYNC_OUT it needs.
pub fn keep(body: &str) -> String {
    let mut used: Set = 0;
    let mut blocks = Blocks::default();
    let lines: Vec<Line> = body.lines().map(|line| scan(line, &mut used, &mut blocks)).collect();
    let budget = lines.iter().any(|line| line.events.iter().any(|(event, _)| matches!(event, Event::Budget)));

    // which locals the context may be behind on where each line starts,
    // and what each line's syncs store. a jump to a label carries what it
    // was behind on there, dispatch starts with nothing behind, and a sync
    // that surely happens, nothing guarding it, leaves nothing behind.
    let labels: BTreeMap<&str, usize> =
        lines.iter().enumerate().filter_map(|(i, line)| line.label.as_deref().map(|label| (label, i))).collect();
    let mut jumped = vec![0 as Set; lines.len()];
    let mut stores: Vec<Option<Set>> = vec![None; lines.len()];
    let mut budgets: Vec<Option<Set>> = vec![None; lines.len()];
    loop {
        let mut changed = false;
        // the function starts with the context complete
        let mut falling = Some(0);
        for (i, line) in lines.iter().enumerate() {
            let mut behind = falling.unwrap_or(0) | jumped[i];
            let mut syncs: Option<Set> = None;
            let mut ends = false;
            for (event, guarded) in &line.events {
                match event {
                    Event::Write(index) => behind |= 1 << index,
                    Event::Sync => {
                        *syncs.get_or_insert(0) |= behind;
                        if !guarded {
                            behind = 0;
                        }
                    }
                    Event::Leave | Event::Dispatch => {
                        *syncs.get_or_insert(0) |= behind;
                        ends = !guarded;
                    }
                    Event::Goto(label) => {
                        if let Some(&target) = labels.get(label.as_str()) {
                            changed |= jumped[target] | behind != jumped[target];
                            jumped[target] |= behind;
                        }
                        ends = !guarded;
                    }
                    Event::Budget => budgets[i] = Some(behind),
                }
                if ends {
                    break;
                }
            }
            stores[i] = syncs;
            falling = (!ends).then_some(behind);
        }
        if !changed {
            break;
        }
    }

    let mut prologue = String::new();
    for index in (0..FPSCR).filter(|index| used & (1 << index) != 0) {
        let (name, kind, home) = local(index);
        writeln!(prologue, "    {kind} {name} = {home};").unwrap();
    }
    let mut loads: Vec<String> = (0..FPSCR)
        .filter(|index| used & (1 << index) != 0)
        .map(|index| {
            let (name, _, home) = local(index);
            format!("{name} = {home};")
        })
        .collect();
    writeln!(prologue, "#undef SYNC_OUT\n#undef SYNC_IN").unwrap();
    if used & (1 << FPSCR) != 0 {
        writeln!(prologue, "    uint32_t fpscr_ = *ctx->fpscr;\n#undef FPSCR\n#define FPSCR(c) fpscr_").unwrap();
        loads.push("fpscr_ = *ctx->fpscr;".to_owned());
    }
    if budget {
        writeln!(prologue, "    int32_t budget_ = ctx->budget;\n#undef BUDGET_LEFT\n#define BUDGET_LEFT budget_").unwrap();
        loads.push("budget_ = ctx->budget;".to_owned());
    }
    // the page tables only ever get read, and anything that could change
    // which ones the code uses is something it syncs around
    if body.contains("mem_") {
        writeln!(prologue, "    uint8_t *const *read_pages_ = ctx->read_pages, *const *write_pages_ = ctx->write_pages;").unwrap();
        writeln!(prologue, "#undef READ_PAGES\n#undef WRITE_PAGES\n#define READ_PAGES(c) read_pages_\n#define WRITE_PAGES(c) write_pages_").unwrap();
        loads.push("read_pages_ = ctx->read_pages; write_pages_ = ctx->write_pages;".to_owned());
    }
    writeln!(prologue, "#define SYNC_IN() do {{ {} }} while (0)", loads.join(" ")).unwrap();

    // the blocks the budget can stop with nothing behind leave without
    // storing anything, the others store what any of them can be behind on
    let behind_at_budgets = budgets.iter().flatten().fold(0, |all, behind| all | behind);
    let mut out = prologue;
    let mut defined = 0;
    out.push_str(&sync_out(0, budget));
    for (i, line) in lines.iter().enumerate() {
        if line.text.trim() == "OUT_OF_BUDGET();" {
            out.push_str(&sync_out(0, budget));
            out.push_str("    OUT_OF_BUDGET_CLEAN();\n");
            out.push_str(&sync_out(behind_at_budgets, budget));
            out.push_str("    OUT_OF_BUDGET();\n");
            defined = behind_at_budgets;
            continue;
        }
        if let Some(set) = stores[i].filter(|set| *set != defined) {
            out.push_str(&sync_out(set, budget));
            defined = set;
        }
        if budgets[i] == Some(0) {
            out.push_str(&line.text.replacen("BLOCK(", "BLOCK_CLEAN(", 1));
        } else {
            out.push_str(&line.text);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_and_flags_become_locals() {
        let body = "    uint32_t target = ctx->r[15];\n    ctx->r[4] = ctx->r[0] + 1;\n    if (C_GE) ctx->z = 1;\n    shift_lsl(ctx->r[2], 3, &ctx->c);\n    ctx->ge = ctx->r[3];\n";
        let kept = keep(body);
        assert!(kept.contains("uint32_t target = reg15_;"));
        assert!(kept.contains("reg4_ = reg0_ + 1;"));
        assert!(kept.contains("if ((flag_n_ == flag_v_)) flag_z_ = 1;"));
        assert!(kept.contains("shift_lsl(reg2_, 3, &flag_c_);"));
        // other fields stay in the context
        assert!(kept.contains("ctx->ge = reg3_;"));
        assert!(kept.contains("reg0_ = ctx->r[0]; reg2_ = ctx->r[2]; reg3_ = ctx->r[3]; reg4_ = ctx->r[4]; reg15_ = ctx->r[15];"));
        assert!(kept.contains("uint8_t flag_v_ = ctx->v;"));
    }

    /// the SYNC_OUT defined right before the first line containing what.
    fn sync_before<'a>(kept: &'a str, what: &str) -> &'a str {
        let at = kept.find(what).expect("the line");
        let define = kept[..at].rfind("#define SYNC_OUT() ").expect("a SYNC_OUT");
        kept[define..].lines().next().unwrap()
    }

    #[test]
    fn a_call_stores_what_changed_since_the_last_sync() {
        let body = "L_00100000:\n    BLOCK(0x00100000u, 6);\n    ctx->r[4] = ctx->r[0] + 1;\n\
            \x20   ctx->r[14] = 0x00100008u; ctx->r[15] = 0x00200000u;\n    CALL(f_00200000);\n    RETURNED(0x00100008u);\n\
            \x20   ctx->r[0] = ctx->r[4];\n    CALL(f_00300000);\n    RETURNED(0x0010000Cu);\n\
            \x20   ctx->r[15] = ctx->r[14] & ~3u; RETURN();\n    OUT_OF_BUDGET();\n";
        let kept = keep(body);
        assert_eq!(
            sync_before(&kept, "CALL(f_00200000)"),
            "#define SYNC_OUT() do { ctx->r[4] = reg4_; ctx->r[14] = reg14_; ctx->r[15] = reg15_; ctx->budget = budget_; } while (0)"
        );
        assert_eq!(sync_before(&kept, "CALL(f_00300000)"), "#define SYNC_OUT() do { ctx->r[0] = reg0_; ctx->budget = budget_; } while (0)");
        assert_eq!(sync_before(&kept, "RETURN();"), "#define SYNC_OUT() do { ctx->r[15] = reg15_; ctx->budget = budget_; } while (0)");
        // nothing changed yet where the budget is checked
        assert!(kept.contains("BLOCK_CLEAN(0x00100000u, 6);"));
        assert!(kept.contains("OUT_OF_BUDGET_CLEAN();"));
    }

    #[test]
    fn a_guarded_call_may_not_happen() {
        let body = "    ctx->r[4] = 1;\n    if (C_EQ) {\n    CALL(f_00200000);\n    RETURNED(0x00100008u);\n    }\n\
            \x20   ctx->r[0] = 2;\n    CALL(f_00200000);\n    RETURNED(0x0010000Cu);\n";
        let kept = keep(body);
        let second = kept.rfind("    CALL(f_00200000);").unwrap();
        let define = kept[..second].rfind("#define SYNC_OUT() ").unwrap();
        assert_eq!(kept[define..].lines().next().unwrap(), "#define SYNC_OUT() do { ctx->r[0] = reg0_; ctx->r[4] = reg4_; } while (0)");
    }

    #[test]
    fn a_loop_carries_what_changed_back_to_its_label() {
        let body = "    uint32_t target = ctx->r[15], resume = 0;\n    if (LIKELY(target == 0x00100000u && !ctx->thumb)) goto L_00100000;\n\
            L_00100000:\n    BLOCK(0x00100000u, 2);\n    /* 00100000 E2800001 */\n    ctx->r[0] = ctx->r[0] + 1;\n\
            \x20   /* 00100004 EAFFFFFD */\n    goto L_00100000;\n    OUT_OF_BUDGET();\n";
        let kept = keep(body);
        assert!(kept.contains("    BLOCK(0x00100000u, 2);"));
        assert_eq!(sync_before(&kept, "    OUT_OF_BUDGET();"), "#define SYNC_OUT() do { ctx->r[0] = reg0_; ctx->budget = budget_; } while (0)");
    }

    #[test]
    fn a_jump_through_dispatch_syncs_first() {
        let kept = keep("    ctx->r[3] = 1; target = 0x00200000u; goto dispatch;\n");
        assert!(kept.contains("reg3_ = 1; target = 0x00200000u; { SYNC_OUT(); goto dispatch; }"));
        let guarded = keep("    if (C_EQ) goto dispatch;\n");
        assert!(guarded.contains("if ((flag_z_)) { SYNC_OUT(); goto dispatch; }"));
        assert_eq!(sync_before(&kept, "goto dispatch"), "#define SYNC_OUT() do { ctx->r[3] = reg3_; } while (0)");
    }

    #[test]
    fn the_budget_counts_down_in_a_local() {
        let kept = keep("L_00100000:\n    BLOCK(0x00100000u, 3);\n    ctx->r[0] = 1;\n    OUT_OF_BUDGET();\n");
        assert!(kept.contains("int32_t budget_ = ctx->budget;"));
        assert!(kept.contains("#define BUDGET_LEFT budget_"));
        assert!(kept.contains("budget_ = ctx->budget; } while (0)"));
        assert!(!keep("    ctx->r[0] = 1;\n").contains("budget_"));
    }

    #[test]
    fn vfp_registers_and_fpscr_become_locals() {
        let body = "    { float a = vfp_s(ctx, 3), b = vfp_s(ctx, 4); vfp_set_s(ctx, 3, a * b); }\n\
            \x20   { double a = vfp_d(ctx, 1); vfp_set_d(ctx, 2, a + 1.0); }\n\
            \x20   ctx->r[0] = ctx->vfp[7]; vfp_compare(ctx, vfp_d(ctx, 1), 0.0);\n\
            \x20   if (UNLIKELY(*ctx->fpscr & FPSCR_LEN)) vfp_vector(ctx, 6, 0, 8, 9, 10); else { }\n";
        let kept = keep(body);
        assert!(kept.contains("float a = vfp_from_s(vfp3_), b = vfp_from_s(vfp4_); vfp3_ = vfp_to_s(ctx, a * b);"));
        assert!(kept.contains("double a = vfp_from_d(vfp2_, vfp3_); VFP_SET_D(vfp4_, vfp5_, a + 1.0);"));
        assert!(kept.contains("reg0_ = vfp7_; vfp_compare(ctx, vfp_from_d(vfp2_, vfp3_), 0.0);"));
        assert!(kept.contains("if (UNLIKELY(fpscr_ & FPSCR_LEN)) VFP_VECTOR(ctx, 6, 0, 8, 9, 10);"));
        assert!(kept.contains("uint32_t vfp7_ = ctx->vfp[7];"));
        assert!(kept.contains("uint32_t fpscr_ = *ctx->fpscr;"));
        assert_eq!(
            sync_before(&kept, "VFP_VECTOR("),
            "#define SYNC_OUT() do { ctx->r[0] = reg0_; ctx->vfp[3] = vfp3_; ctx->vfp[4] = vfp4_; ctx->vfp[5] = vfp5_; *ctx->fpscr = fpscr_; } while (0)"
        );
    }

    #[test]
    fn comparisons_are_not_writes() {
        let kept = keep("    if (ctx->r[1] == 0 && ctx->z != 1) ctx->r[2] = 0;\n    RETURN();\n");
        assert_eq!(sync_before(&kept, "RETURN();"), "#define SYNC_OUT() do { ctx->r[2] = reg2_; } while (0)");
    }
}
