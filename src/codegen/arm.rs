//! lowers ARM instrs to C
//! decoding follows `zakuro-cpu`'s, down to which pipeline offset each form reads r15 with, so both agree on every instr
//! anything weird is left to the interpreter

use std::fmt::Write;

use super::hoist::{read, write};
use super::{Scope, call, jump, vfp, words};

macro_rules! emit {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).unwrap()
    };
}

const CONDITIONS: [&str; 14] = [
    "C_EQ", "C_NE", "C_CS", "C_CC", "C_MI", "C_PL", "C_VS", "C_VC", "C_HI", "C_LS", "C_GE", "C_LT", "C_GT", "C_LE",
];

fn sign_extend_24(value: u32) -> u32 {
    (((value << 8) as i32) >> 8) as u32
}

/// reads a reg, r15 being whatever addr the pipeline gives it
fn reg(scope: &Scope, register: u32, pc: u32) -> String {
    if register == 15 { scope.at(pc) } else { format!("ctx->r[{register}]") }
}

/// writes the C for the instr at address, returns whether execution can fall into the next one
pub fn lower(out: &mut String, scope: &Scope, address: u32, op: u32) -> bool {
    let condition = op >> 28;
    if condition == 0xF {
        return unconditional(out, scope, address, op);
    }
    if condition == 0xE {
        return body(out, scope, address, op);
    }
    emit!(out, "    if ({}) {{", CONDITIONS[condition as usize]);
    body(out, scope, address, op);
    emit!(out, "    }}");
    true
}

fn body(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    match (op >> 25) & 7 {
        0b000 => register_space(out, scope, a, op),
        // msr w/ an immediate lives in the compare opcodes w/o s, and w/ no fields to write it's nop and the other hints
        0b001 if (op >> 23) & 3 == 0b10 && op & (1 << 20) == 0 => {
            if op & (1 << 21) != 0 && (op >> 16) & 0xF == 0 { true } else { status_register(out, scope, a, op) }
        }
        0b001 => data_processing(out, scope, a, op),
        0b010 => single_transfer(out, scope, a, op),
        0b011 if op & 0x10 != 0 => media(out, scope, a, op),
        0b011 => single_transfer(out, scope, a, op),
        0b100 => block_transfer(out, scope, a, op),
        0b101 => {
            let target = (a + 8).wrapping_add(sign_extend_24(op & 0x00FF_FFFF) << 2);
            if op & (1 << 24) != 0 { call(out, scope, a + 4, target, false) } else { jump(out, scope, target, false) }
        }
        0b110 => vfp::load_store(out, scope, a, op),
        // the host runs an svc in place and the code goes on after it
        // the code reads the clock and takes the lent mutex itself where the host allows
        0b111 if op & (1 << 24) != 0 => {
            match op & 0x00FF_FFFF {
                0x28 => emit!(out, "    SVC_TICK({}, 0u);", scope.at(a + 4)),
                0x25 => emit!(out, "    SVC_WAIT({}, 0u);", scope.at(a + 4)),
                0x14 => emit!(out, "    SVC_RELEASE({}, 0u);", scope.at(a + 4)),
                number => emit!(out, "    SVC({}, 0x{:X}u);", scope.at(a + 4), number),
            }
            true
        }
        0b111 if op & 0x10 != 0 && matches!((op >> 8) & 0xF, 10 | 11) => vfp::register_transfer(out, scope, a, op),
        // cp15, reading the TLS addr is common enough to do here
        // so are the barriers and dcache maintenance, which do nothing for code that sees memory as is
        0b111 if op & 0x10 != 0 => {
            let rd = (op >> 12) & 0xF;
            let data_cache = op & 0x0FFF_0F10 == 0x0E07_0F10 && !matches!(op & 0xF, 5 | 7 | 13);
            if op & 0x0FFF_0FFF == 0x0E1D_0F70 && rd != 15 {
                emit!(out, "    ctx->r[{rd}] = ctx->tls;");
                true
            } else if data_cache {
                true
            } else {
                interpret(out, scope, a, op)
            }
        }
        _ => vfp::data_processing(out, scope, a, op),
    }
}

/// the reg data processing space, w/ the multiplies, extra loads and stores and misc instrs in its holes
fn register_space(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    if op & 0x90 == 0x90 {
        if (op >> 5) & 3 != 0 {
            return extra_transfer(out, scope, a, op);
        }
        if op & (1 << 24) != 0 {
            return if op & (1 << 23) != 0 { exclusive(out, scope, a, op) } else { swap(out, scope, a, op) };
        }
        return match (op >> 21) & 7 {
            0b000 | 0b001 => multiply(out, scope, a, op),
            0b010 | 0b100..=0b111 => multiply_long(out, scope, a, op),
            _ => interpret(out, scope, a, op),
        };
    }
    if (op >> 23) & 3 == 0b10 && op & (1 << 20) == 0 {
        return match (op >> 4) & 0xF {
            0b0000 => status_register(out, scope, a, op),
            0b0001 if (op >> 21) & 3 == 0b11 => clz(out, scope, a, op),
            0b0001 | 0b0011 => branch_exchange(out, scope, a, op),
            0b0101 => saturating(out, scope, a, op),
            kind if kind & 0b1001 == 0b1000 => halfword_multiply(out, scope, a, op),
            _ => interpret(out, scope, a, op),
        };
    }
    data_processing(out, scope, a, op)
}

fn interpret(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    emit!(out, "    INTERPRET({}, 0x{op:08X}u);", scope.at(a));
    scope.interpreted.borrow_mut().push(a);
    true
}

/// mrs and msr on the cpsr
/// titles run in system mode and only ever touch the flags and ge this way, so reads give those over that mode
/// a write to anything else (or the spsr) goes to the interpreter
fn status_register(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    if op & (1 << 22) != 0 {
        return interpret(out, scope, a, op);
    }
    if op & (1 << 21) == 0 {
        let rd = (op >> 12) & 0xF;
        if rd == 15 {
            return interpret(out, scope, a, op);
        }
        emit!(
            out,
            "    ctx->r[{rd}] = ((uint32_t)ctx->n << 31) | ((uint32_t)ctx->z << 30) | ((uint32_t)ctx->c << 29) \
             | ((uint32_t)ctx->v << 28) | ((uint32_t)ctx->q << 27) | ((uint32_t)(ctx->ge & 0xF) << 16) | 0x1Fu;"
        );
        return true;
    }
    let mask = (op >> 16) & 0xF;
    if mask & 0b0011 != 0 {
        return interpret(out, scope, a, op);
    }
    let value = if op & (1 << 25) != 0 {
        format!("0x{:08X}u", (op & 0xFF).rotate_right(((op >> 8) & 0xF) * 2))
    } else {
        reg(scope, op & 0xF, a + 8)
    };
    emit!(out, "    {{");
    emit!(out, "    uint32_t value = {value};");
    if mask & 0b1000 != 0 {
        emit!(out, "    ctx->n = value >> 31; ctx->z = (value >> 30) & 1; ctx->c = (value >> 29) & 1;");
        emit!(out, "    ctx->v = (value >> 28) & 1; ctx->q = (value >> 27) & 1;");
    }
    if mask & 0b0100 != 0 {
        emit!(out, "    ctx->ge = (value >> 16) & 0xF;");
    }
    emit!(out, "    }}");
    true
}

/// the shifter operand as b, and its carry as sc when the flags need it
fn shifter_operand(out: &mut String, scope: &Scope, a: u32, op: u32, carry: bool) {
    if op & (1 << 25) != 0 {
        let rotate = ((op >> 8) & 0xF) * 2;
        let value = (op & 0xFF).rotate_right(rotate);
        emit!(out, "    uint32_t b = 0x{value:08X}u;");
        if carry {
            if rotate == 0 {
                emit!(out, "    uint8_t sc = ctx->c;");
            } else {
                emit!(out, "    uint8_t sc = {};", value >> 31);
            }
        }
        return;
    }
    let rm = op & 0xF;
    let kind = (op >> 5) & 3;
    if op & (1 << 4) != 0 {
        let rs = (op >> 8) & 0xF;
        let shift = ["shift_lsl", "shift_lsr", "shift_asr", "shift_ror"][kind as usize];
        emit!(out, "    uint8_t sc = ctx->c;");
        emit!(out, "    uint32_t b = {shift}({}, {}, &sc);", reg(scope, rm, a + 12), reg(scope, rs, a + 12));
        return;
    }
    let amount = (op >> 7) & 0x1F;
    emit!(out, "    uint32_t m = {};", reg(scope, rm, a + 8));
    let (value, carry_out) = match (kind, amount) {
        (0, 0) => ("m".to_owned(), "ctx->c".to_owned()),
        (0, n) => (format!("m << {n}"), format!("(m >> {}) & 1", 32 - n)),
        (1, 0) => ("0".to_owned(), "m >> 31".to_owned()),
        (1, n) => (format!("m >> {n}"), format!("(m >> {}) & 1", n - 1)),
        (2, 0) => ("(uint32_t)((int32_t)m >> 31)".to_owned(), "m >> 31".to_owned()),
        (2, n) => (format!("(uint32_t)((int32_t)m >> {n})"), format!("(m >> {}) & 1", n - 1)),
        // ror 0 is rrx
        (_, 0) => ("((uint32_t)ctx->c << 31) | (m >> 1)".to_owned(), "m & 1".to_owned()),
        (_, n) => (format!("(m >> {n}) | (m << {})", 32 - n), format!("(m >> {}) & 1", n - 1)),
    };
    emit!(out, "    uint32_t b = {value};");
    if carry {
        emit!(out, "    uint8_t sc = {carry_out};");
    }
}

fn data_processing(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let opcode = (op >> 21) & 0xF;
    let set_flags = op & (1 << 20) != 0;
    let rn = (op >> 16) & 0xF;
    let rd = (op >> 12) & 0xF;
    let compare = (8..=11).contains(&opcode);
    if set_flags && rd == 15 && !compare {
        // an exception return, also restores cpsr
        return interpret(out, scope, a, op);
    }
    let register_shift = op & (1 << 25) == 0 && op & (1 << 4) != 0;
    let logical = matches!(opcode, 0 | 1 | 8 | 9 | 12..=15);

    emit!(out, "    {{");
    shifter_operand(out, scope, a, op, set_flags && logical);
    if !matches!(opcode, 13 | 15) {
        emit!(out, "    uint32_t a = {};", reg(scope, rn, if register_shift { a + 12 } else { a + 8 }));
    }
    if matches!(opcode, 5..=7) {
        emit!(out, "    uint8_t ci = ctx->c;");
    }
    let result = match opcode {
        0 | 8 => "a & b",
        1 | 9 => "a ^ b",
        2 | 10 => "a - b",
        3 => "b - a",
        4 | 11 => "a + b",
        5 => "a + b + ci",
        6 => "a - b - !ci",
        7 => "b - a - !ci",
        12 => "a | b",
        13 => "b",
        14 => "a & ~b",
        _ => "~b",
    };
    emit!(out, "    uint32_t r = {result};");
    if set_flags {
        emit!(out, "    ctx->n = r >> 31; ctx->z = r == 0;");
        match opcode {
            2 | 10 => emit!(out, "    ctx->c = a >= b; ctx->v = ((a ^ b) & (a ^ r)) >> 31;"),
            3 => emit!(out, "    ctx->c = b >= a; ctx->v = ((b ^ a) & (b ^ r)) >> 31;"),
            4 | 11 => emit!(out, "    ctx->c = r < a; ctx->v = ((a ^ r) & (b ^ r)) >> 31;"),
            5 => emit!(out, "    ctx->c = ((uint64_t)a + b + ci) >> 32; ctx->v = ((a ^ r) & (b ^ r)) >> 31;"),
            6 => emit!(out, "    ctx->c = (uint64_t)a >= (uint64_t)b + !ci; ctx->v = ((a ^ b) & (a ^ r)) >> 31;"),
            7 => emit!(out, "    ctx->c = (uint64_t)b >= (uint64_t)a + !ci; ctx->v = ((b ^ a) & (b ^ r)) >> 31;"),
            _ => emit!(out, "    ctx->c = sc;"),
        }
    }
    let continues = if compare {
        true
    } else if rd == 15 {
        // mov pc, lr returns, any other write to pc jumps
        if opcode == 13 && op & 0x0200_0FFF == 14 {
            emit!(out, "    ctx->r[15] = r & ~3u; RETURN();");
        } else {
            emit!(out, "    target = r & ~3u; goto dispatch;");
        }
        false
    } else {
        emit!(out, "    ctx->r[{rd}] = r;");
        true
    };
    emit!(out, "    }}");
    continues
}

/// ldr, str, ldrb and strb
fn single_transfer(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rn = (op >> 16) & 0xF;
    let rd = (op >> 12) & 0xF;
    let pre = op & (1 << 24) != 0;
    let byte = op & (1 << 22) != 0;
    let load = op & (1 << 20) != 0;
    let writeback = !pre || op & (1 << 21) != 0;
    if writeback && rn == 15 {
        return interpret(out, scope, a, op);
    }
    let offset = if op & (1 << 25) != 0 {
        let m = reg(scope, op & 0xF, a + 8);
        match ((op >> 5) & 3, (op >> 7) & 0x1F) {
            (0, n) => format!("({m} << {n})"),
            (1, 0) => "0".to_owned(),
            (1, n) => format!("({m} >> {n})"),
            (2, 0) => format!("(uint32_t)((int32_t){m} >> 31)"),
            (2, n) => format!("(uint32_t)((int32_t){m} >> {n})"),
            (_, 0) => format!("(((uint32_t)ctx->c << 31) | ({m} >> 1))"),
            (_, n) => format!("ror32({m}, {n})"),
        }
    } else {
        format!("0x{:X}u", op & 0xFFF)
    };
    let sign = if op & (1 << 23) != 0 { '+' } else { '-' };
    let address = if pre { "oa" } else { "base" };
    let size = if byte { 1 } else { 4 };
    // at base plus a const, a span off the base can cover it
    let covered = if op & (1 << 25) == 0 && rn != 15 {
        let offset = if !pre { 0 } else if sign == '+' { (op & 0xFFF) as i32 } else { -((op & 0xFFF) as i32) };
        scope.access(a, rn, offset, size, !load)
    } else {
        None
    };
    emit!(out, "    {{ uint32_t base = {}, oa = base {sign} {offset};", reg(scope, rn, a + 8));
    if load {
        emit!(out, "    uint32_t v = {};", read(covered, size, address));
        if writeback && rn != rd {
            emit!(out, "    ctx->r[{rn}] = oa;");
        }
        if rd == 15 {
            // ldr pc, [sp], 4 is a pop
            let pop = rn == 13 && !pre && sign == '+' && op & (1 << 25) == 0 && op & 0xFFF == 4;
            emit!(out, "    {}(v); }}", if pop { "RETURN_TO_A" } else { "JUMP_TO" });
            return false;
        }
        emit!(out, "    ctx->r[{rd}] = v; }}");
    } else {
        // storing r15 stores the addr plus 12 (arm being arm)
        let value = if rd == 15 { scope.at(a + 12) } else { format!("ctx->r[{rd}]") };
        let value = if byte { format!("(uint8_t){value}") } else { value };
        emit!(out, "    {};", write(covered, size, address, &value));
        if writeback {
            emit!(out, "    ctx->r[{rn}] = oa;");
        }
        emit!(out, "    }}");
    }
    true
}

/// ldrh, strh, ldrsb, ldrsh, ldrd and strd
fn extra_transfer(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rn = (op >> 16) & 0xF;
    let rd = (op >> 12) & 0xF;
    let pre = op & (1 << 24) != 0;
    let load = op & (1 << 20) != 0;
    let writeback = !pre || op & (1 << 21) != 0;
    let kind = (op >> 5) & 3;
    let pair = kind >= 2 && !load;
    if (writeback && rn == 15) || (load && rd == 15) || (pair && (rd & 1 != 0 || rd == 14)) {
        return interpret(out, scope, a, op);
    }
    let offset = if op & (1 << 22) != 0 {
        format!("0x{:X}u", ((op >> 4) & 0xF0) | (op & 0xF))
    } else {
        reg(scope, op & 0xF, a + 8)
    };
    let sign = if op & (1 << 23) != 0 { '+' } else { '-' };
    let address = if pre { "oa" } else { "base" };
    let back = if writeback { format!(" ctx->r[{rn}] = oa;") } else { String::new() };
    // what a span off the base can cover, at base plus a const
    let constant = op & (1 << 22) != 0 && rn != 15;
    let at = if !pre {
        0
    } else {
        let immediate = (((op >> 4) & 0xF0) | (op & 0xF)) as i32;
        if sign == '+' { immediate } else { -immediate }
    };
    let access = |offset: i32, size: u32, write: bool| if constant { scope.access(a, rn, at + offset, size, write) } else { None };
    emit!(out, "    {{ uint32_t base = {}, oa = base {sign} {offset};", reg(scope, rn, a + 8));
    match (kind, load) {
        (1, true) => {
            emit!(out, "    uint32_t v = {};{back} ctx->r[{rd}] = v; }}", read(access(0, 2, false), 2, address))
        }
        (1, false) => {
            let value = format!("(uint16_t){}", reg(scope, rd, a + 8));
            emit!(out, "    {};{back} }}", write(access(0, 2, true), 2, address, &value))
        }
        (2, true) => emit!(
            out,
            "    uint32_t v = (uint32_t)(int32_t)(int8_t){};{back} ctx->r[{rd}] = v; }}",
            read(access(0, 1, false), 1, address)
        ),
        (2, false) => {
            let (low, high) = (access(0, 4, false), access(4, 4, false));
            let next = format!("{address} + 4");
            emit!(
                out,
                "    uint32_t lo = {}, hi = {};{back} ctx->r[{rd}] = lo; ctx->r[{}] = hi; }}",
                read(low, 4, address),
                read(high, 4, &next),
                rd + 1
            )
        }
        (_, true) => emit!(
            out,
            "    uint32_t v = (uint32_t)(int32_t)(int16_t){};{back} ctx->r[{rd}] = v; }}",
            read(access(0, 2, false), 2, address)
        ),
        (_, false) => {
            let (low, high) = (access(0, 4, true), access(4, 4, true));
            let next = format!("{address} + 4");
            let (first, second) = (format!("ctx->r[{rd}]"), format!("ctx->r[{}]", rd + 1));
            emit!(out, "    {}; {};{back} }}", write(low, 4, address, &first), write(high, 4, &next, &second))
        }
    }
    true
}

/// ldm and stm
fn block_transfer(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rn = (op >> 16) & 0xF;
    let pre = op & (1 << 24) != 0;
    let up = op & (1 << 23) != 0;
    let writeback = op & (1 << 21) != 0;
    let load = op & (1 << 20) != 0;
    let list = op & 0xFFFF;
    // user bank forms, empty lists and r15 as base are rare enough to skip
    if op & (1 << 22) != 0 || list == 0 || rn == 15 {
        return interpret(out, scope, a, op);
    }
    let span = list.count_ones() * 4;
    let (lowest, last) = match (up, pre) {
        (true, false) => ("base".to_owned(), format!("base + {span}")),
        (true, true) => ("base + 4".to_owned(), format!("base + {span}")),
        (false, false) => (format!("base - {}", span - 4), format!("base - {span}")),
        (false, true) => (format!("base - {span}"), format!("base - {span}")),
    };
    emit!(out, "    {{ uint32_t base = ctx->r[{rn}], p = {lowest}, fin = {last};");
    let registers: Vec<u32> = (0..16).filter(|i| list & (1 << i) != 0).collect();
    if load {
        if writeback && list & (1 << rn) == 0 {
            emit!(out, "    ctx->r[{rn}] = fin;");
        }
        // r15 goes last, where it leads gets taken once the rest is in
        let destinations: Vec<String> =
            registers.iter().map(|&r| if r == 15 { "next".to_owned() } else { format!("ctx->r[{r}]") }).collect();
        if list & (1 << 15) != 0 {
            emit!(out, "    uint32_t next;");
            words(out, true, &destinations);
            let jump = if rn == 13 { "RETURN_TO_A" } else { "JUMP_TO" };
            emit!(out, "    {jump}(next); }}");
            return false;
        }
        words(out, true, &destinations);
    } else {
        let values: Vec<String> = registers
            .iter()
            .map(|&register| {
                if register == 15 {
                    scope.at(a + 12)
                } else if register == rn && writeback && list & ((1 << rn) - 1) != 0 {
                    // the base, when it's not the lowest reg, stores its new value
                    "fin".to_owned()
                } else {
                    format!("ctx->r[{register}]")
                }
            })
            .collect();
        words(out, false, &values);
        if writeback {
            emit!(out, "    ctx->r[{rn}] = fin;");
        }
    }
    emit!(out, "    (void)p; (void)fin; }}");
    true
}

/// swp and swpb
fn swap(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    let (read, write, cast) = if op & (1 << 22) != 0 { ("mem_read8", "mem_write8", "(uint8_t)") } else { ("mem_read32", "mem_write32", "") };
    emit!(
        out,
        "    {{ uint32_t address = {}, source = {}, old = {read}(ctx, address); {write}(ctx, address, {cast}source); ctx->r[{rd}] = old; }}",
        reg(scope, (op >> 16) & 0xF, a + 8),
        reg(scope, op & 0xF, a + 8)
    );
    true
}

/// ldrex and strex in every size, a store only goes thru while the monitor still has its addr, and a good one clears it
fn exclusive(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    let rm = op & 0xF;
    let size = (op >> 21) & 3;
    let load = op & (1 << 20) != 0;
    // r15 as a dest, or a pair running into it
    if rd == 15 || (size == 0b01 && (if load { rd } else { rm }) >= 14) {
        return interpret(out, scope, a, op);
    }
    let address = reg(scope, (op >> 16) & 0xF, a + 8);
    let (read, write, cast) = match size {
        0b00 | 0b01 => ("mem_read32", "mem_write32", ""),
        0b10 => ("mem_read8", "mem_write8", "(uint8_t)"),
        _ => ("mem_read16", "mem_write16", "(uint16_t)"),
    };
    if load {
        let value = if size == 0b01 {
            format!("ctx->r[{rd}] = mem_read32(ctx, address); ctx->r[{}] = mem_read32(ctx, address + 4);", rd + 1)
        } else {
            format!("ctx->r[{rd}] = {read}(ctx, address);")
        };
        emit!(out, "    {{ uint32_t address = {address}; ctx->exclusive = 1; ctx->exclusive_address = address; {value} }}");
    } else {
        let store = if size == 0b01 {
            format!("mem_write32(ctx, address, ctx->r[{rm}]); mem_write32(ctx, address + 4, ctx->r[{}]);", rm + 1)
        } else {
            format!("{write}(ctx, address, {cast}ctx->r[{rm}]);")
        };
        emit!(
            out,
            "    {{ uint32_t address = {address}; if (ctx->exclusive && ctx->exclusive_address == address) {{ {store} ctx->exclusive = 0; ctx->r[{rd}] = 0; }} else ctx->r[{rd}] = 1; }}"
        );
    }
    true
}

/// mul and mla
fn multiply(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 16) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    let product = format!("{} * {}", reg(scope, op & 0xF, a + 8), reg(scope, (op >> 8) & 0xF, a + 8));
    let sum = if op & (1 << 21) != 0 { format!(" + {}", reg(scope, (op >> 12) & 0xF, a + 8)) } else { String::new() };
    let flags = if op & (1 << 20) != 0 { " ctx->n = r >> 31; ctx->z = r == 0;" } else { "" };
    emit!(out, "    {{ uint32_t r = {product}{sum}; ctx->r[{rd}] = r;{flags} }}");
    true
}

/// umull, umlal, smull, smlal and umaal
fn multiply_long(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let hi = (op >> 16) & 0xF;
    let lo = (op >> 12) & 0xF;
    if hi == 15 || lo == 15 {
        return interpret(out, scope, a, op);
    }
    let m = reg(scope, op & 0xF, a + 8);
    let s = reg(scope, (op >> 8) & 0xF, a + 8);
    let kind = (op >> 21) & 7;
    let pair = format!("((uint64_t)ctx->r[{hi}] << 32 | ctx->r[{lo}])");
    let value = match kind {
        0b010 => format!("(uint64_t){m} * {s} + ctx->r[{lo}] + ctx->r[{hi}]"),
        0b100 => format!("(uint64_t){m} * {s}"),
        0b101 => format!("(uint64_t){m} * {s} + {pair}"),
        0b110 => format!("(uint64_t)((int64_t)(int32_t){m} * (int32_t){s})"),
        _ => format!("(uint64_t)((int64_t)(int32_t){m} * (int32_t){s}) + {pair}"),
    };
    let flags = if kind != 0b010 && op & (1 << 20) != 0 { " ctx->n = r >> 63; ctx->z = r == 0;" } else { "" };
    emit!(out, "    {{ uint64_t r = {value}; ctx->r[{lo}] = (uint32_t)r; ctx->r[{hi}] = (uint32_t)(r >> 32);{flags} }}");
    true
}

/// smlaxy, smlawy, smulwy, smlalxy and smulxy, the 32 bit accumulates wrap and set q on overflow
fn halfword_multiply(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 16) & 0xF;
    let rn = (op >> 12) & 0xF;
    let kind = (op >> 21) & 3;
    if rd == 15 || (kind == 0b10 && rn == 15) {
        return interpret(out, scope, a, op);
    }
    let (x, y) = ((op >> 5) & 1, (op >> 6) & 1);
    let m = reg(scope, op & 0xF, a + 8);
    let s = reg(scope, (op >> 8) & 0xF, a + 8);
    let n = reg(scope, rn, a + 8);
    match kind {
        0b00 => emit!(out, "    ctx->r[{rd}] = accumulate(ctx, HALF({m}, {x}) * HALF({s}, {y}) + (int32_t){n});"),
        0b01 => {
            let product = format!("((int64_t)(int32_t){m} * HALF({s}, {y})) >> 16");
            if x != 0 {
                emit!(out, "    ctx->r[{rd}] = (uint32_t)({product});");
            } else {
                emit!(out, "    ctx->r[{rd}] = accumulate(ctx, ({product}) + (int32_t){n});");
            }
        }
        0b10 => emit!(
            out,
            "    {{ uint64_t r = ((uint64_t)ctx->r[{rd}] << 32 | ctx->r[{rn}]) + (uint64_t)(HALF({m}, {x}) * HALF({s}, {y})); ctx->r[{rn}] = (uint32_t)r; ctx->r[{rd}] = (uint32_t)(r >> 32); }}"
        ),
        _ => emit!(out, "    ctx->r[{rd}] = (uint32_t)(HALF({m}, {x}) * HALF({s}, {y}));"),
    }
    true
}

/// qadd, qsub, qdadd and qdsub
fn saturating(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    let m = reg(scope, op & 0xF, a + 8);
    let n = reg(scope, (op >> 16) & 0xF, a + 8);
    let value = match (op >> 21) & 3 {
        0b00 => format!("saturate(ctx, (int64_t)(int32_t){m} + (int32_t){n})"),
        0b01 => format!("saturate(ctx, (int64_t)(int32_t){m} - (int32_t){n})"),
        0b10 => format!("saturate(ctx, (int64_t)(int32_t){m} + (int32_t)saturate(ctx, (int64_t)(int32_t){n} * 2))"),
        _ => format!("saturate(ctx, (int64_t)(int32_t){m} - (int32_t)saturate(ctx, (int64_t)(int32_t){n} * 2))"),
    };
    emit!(out, "    ctx->r[{rd}] = {value};");
    true
}

fn clz(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    emit!(out, "    {{ uint32_t m = {}; ctx->r[{rd}] = m ? __builtin_clz(m) : 32; }}", reg(scope, op & 0xF, a + 8));
    true
}

/// bx and blx thru a reg
fn branch_exchange(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rm = op & 0xF;
    if (op >> 4) & 0xF == 0b0011 {
        let next = a + 4;
        emit!(
            out,
            "    {{ uint32_t v = {}; ctx->r[14] = {}; ctx->thumb = v & 1; ctx->r[15] = v & (ctx->thumb ? ~1u : ~3u); }}",
            reg(scope, rm, a + 8),
            scope.at(next)
        );
        emit!(out, "    CALL_RETURNING(recomp_call, {});", scope.link(next));
        return true;
    }
    if rm == 14 {
        emit!(out, "    RETURN_TO_A(ctx->r[14]);");
    } else {
        emit!(out, "    JUMP_TO({});", reg(scope, rm, a + 8));
    }
    false
}

/// ARMv6 media instrs, decoded in `zakuro-cpu`'s order
fn media(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let op1 = (op >> 20) & 0x1F;
    let op2 = (op >> 5) & 7;
    match op1 >> 3 {
        0b00 => parallel(out, scope, a, op, op1, op2),
        0b01 => pack_saturate_extend(out, scope, a, op, op1, op2),
        0b10 => dual_multiply(out, scope, a, op, op1),
        _ if op1 == 0b11000 && op2 == 0 => usad8(out, scope, a, op),
        _ => interpret(out, scope, a, op),
    }
}

/// parallel adds and subs, sadd16 to uhsub8
fn parallel(out: &mut String, scope: &Scope, a: u32, op: u32, op1: u32, op2: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    if rd == 15 || op1 & 3 == 0 || matches!(op2, 5 | 6) {
        return interpret(out, scope, a, op);
    }
    let n = reg(scope, (op >> 16) & 0xF, a + 8);
    let m = reg(scope, op & 0xF, a + 8);
    emit!(out, "    ctx->r[{rd}] = media_parallel(ctx, {op1}, {op2}, {n}, {m});");
    true
}

/// packing, extends, sel, reversals and saturations
fn pack_saturate_extend(out: &mut String, scope: &Scope, a: u32, op: u32, op1: u32, op2: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    let rn = (op >> 16) & 0xF;
    let n = reg(scope, rn, a + 8);
    let m = reg(scope, op & 0xF, a + 8);
    let shift = (op >> 7) & 0x1F;
    let unsigned = op1 & 0b100 != 0;
    let value = match (op1 & 7, op2) {
        // pkhbt and pkhtb
        (0b000, 0 | 2 | 4 | 6) if op1 == 0b01000 => {
            if op & (1 << 6) != 0 {
                format!("((uint32_t)((int32_t){m} >> {}) & 0xFFFF) | ({n} & 0xFFFF0000u)", if shift == 0 { 31 } else { shift })
            } else {
                format!("({n} & 0xFFFF) | (({m} << {shift}) & 0xFFFF0000u)")
            }
        }
        (_, 0b011) => {
            let rotate = ((op >> 10) & 3) * 8;
            let x = if rotate == 0 { m } else { format!("ror32({m}, {rotate})") };
            let (extended, packed) = match op1 & 7 {
                0b000 => (
                    format!(
                        "(((uint32_t)(int32_t)(int8_t){x} & 0xFFFF) | (((uint32_t)(int32_t)(int8_t)({x} >> 16) & 0xFFFF) << 16))"
                    ),
                    true,
                ),
                0b010 => (format!("(uint32_t)(int32_t)(int8_t){x}"), false),
                0b011 => (format!("(uint32_t)(int32_t)(int16_t){x}"), false),
                0b100 => (format!("({x} & 0x00FF00FFu)"), true),
                0b110 => (format!("({x} & 0xFF)"), false),
                0b111 => (format!("({x} & 0xFFFF)"), false),
                _ => return interpret(out, scope, a, op),
            };
            match (rn, packed) {
                (15, _) => extended,
                (_, true) => format!("add_halves(ctx->r[{rn}], {extended})"),
                (_, false) => format!("ctx->r[{rn}] + {extended}"),
            }
        }
        (0b000, 0b101) if op1 == 0b01000 => format!("media_select(ctx, {n}, {m})"),
        (0b011, 0b001) if op1 == 0b01011 => format!("__builtin_bswap32({m})"),
        (0b011, 0b101) if op1 == 0b01011 => format!("((({m}) & 0x00FF00FFu) << 8) | ((({m}) & 0xFF00FF00u) >> 8)"),
        (0b111, 0b001) if op1 == 0b01111 => format!("reverse_bits({m})"),
        (0b111, 0b101) if op1 == 0b01111 => {
            format!("(uint32_t)(int32_t)(int16_t)(((({m}) & 0xFF) << 8) | ((({m}) >> 8) & 0xFF))")
        }
        // ssat16 and usat16
        (0b010 | 0b110, 0b001) => {
            let bits = ((op >> 16) & 0xF) + !unsigned as u32;
            format!("media_saturate16(ctx, {m}, {bits}, {})", unsigned as u8)
        }
        // ssat and usat of a value shifted first
        (_, o) if o & 1 == 0 && matches!((op1 >> 2) & 0b111, 0b010 | 0b011) => {
            let bits = ((op >> 16) & 0x1F) + !unsigned as u32;
            let shifted = if op & (1 << 6) != 0 {
                format!("(int64_t)((int32_t){m} >> {})", if shift == 0 { 31 } else { shift })
            } else {
                format!("(int64_t)(int32_t)({m} << {shift})")
            };
            format!("media_saturate(ctx, {shifted}, {bits}, {})", unsigned as u8)
        }
        _ => return interpret(out, scope, a, op),
    };
    emit!(out, "    ctx->r[{rd}] = {value};");
    true
}

/// smlad, smuad, smlsd, smusd, smlald, smlsld, smmul, smmla and smmls
fn dual_multiply(out: &mut String, scope: &Scope, a: u32, op: u32, op1: u32) -> bool {
    let rd = (op >> 16) & 0xF;
    let ra = (op >> 12) & 0xF;
    if rd == 15 || (op1 == 0b10100 && ra == 15) {
        return interpret(out, scope, a, op);
    }
    let m = reg(scope, op & 0xF, a + 8);
    let s = reg(scope, (op >> 8) & 0xF, a + 8);
    let bit5 = op & (1 << 5) != 0;
    let subtract = op & (1 << 6) != 0;
    match op1 {
        0b10000 | 0b10100 => {
            // bit 5 swaps the second operand's halves
            let b = if bit5 { format!("ror32({s}, 16)") } else { s };
            let sign = if subtract { '-' } else { '+' };
            let dual = format!(
                "((int64_t)(int16_t){m} * (int16_t){b} {sign} (int64_t)(int16_t)({m} >> 16) * (int16_t)({b} >> 16))"
            );
            if op1 == 0b10000 {
                let sum = if ra == 15 { dual } else { format!("{dual} + (int32_t)ctx->r[{ra}]") };
                emit!(out, "    ctx->r[{rd}] = accumulate(ctx, {sum});");
            } else {
                emit!(
                    out,
                    "    {{ uint64_t r = ((uint64_t)ctx->r[{rd}] << 32 | ctx->r[{ra}]) + (uint64_t){dual}; ctx->r[{ra}] = (uint32_t)r; ctx->r[{rd}] = (uint32_t)(r >> 32); }}"
                );
            }
        }
        // top of a full 64 bit product, bit 5 rounds it
        0b10101 => {
            let product = format!("(uint64_t)((int64_t)(int32_t){m} * (int32_t){s})");
            let acc = if ra == 15 { "0".to_owned() } else { format!("((uint64_t)ctx->r[{ra}] << 32)") };
            let sign = if subtract { '-' } else { '+' };
            let round = if bit5 { " + 0x80000000u" } else { "" };
            emit!(out, "    ctx->r[{rd}] = (uint32_t)(({acc} {sign} {product}{round}) >> 32);");
        }
        _ => return interpret(out, scope, a, op),
    }
    true
}

/// usad8 and usada8
fn usad8(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 16) & 0xF;
    let ra = (op >> 12) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    let sum = format!("media_usad8({}, {})", reg(scope, op & 0xF, a + 8), reg(scope, (op >> 8) & 0xF, a + 8));
    let value = if ra == 15 { sum } else { format!("{sum} + ctx->r[{ra}]") };
    emit!(out, "    ctx->r[{rd}] = {value};");
    true
}

/// the cond 0xF space
fn unconditional(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    if op & 0xFE00_0000 == 0xFA00_0000 {
        // blx to Thumb
        let offset = (sign_extend_24(op & 0x00FF_FFFF) << 2) | (((op >> 24) & 1) << 1);
        return call(out, scope, a + 4, (a + 8).wrapping_add(offset) & !1, true);
    }
    if op & 0xFFF0_00F0 == 0xF570_0010 {
        // clrex
        emit!(out, "    ctx->exclusive = 0;");
        return true;
    }
    if matches!((op >> 25) & 7, 0b010 | 0b011) {
        // pld and barriers do nothing here
        return true;
    }
    interpret(out, scope, a, op)
}
