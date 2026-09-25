//! lowering ARM instructions to C. the decoding follows zakuro-cpu's, down
//! to which pipeline offset each form reads r15 with, so that the two agree
//! on every instruction. anything uncommon is left to the interpreter.

use std::fmt::Write;

use super::{Scope, call, jump};

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

/// reading a register, where r15 is the address the pipeline gives it.
fn reg(scope: &Scope, register: u32, pc: u32) -> String {
    if register == 15 { scope.at(pc) } else { format!("ctx->r[{register}]") }
}

/// writes the C for the instruction at address, returning whether execution
/// can carry on to the next one.
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
        0b001 => {
            // msr with an immediate lives in the compare opcodes without s
            if (op >> 23) & 3 == 0b10 && op & (1 << 20) == 0 {
                interpret(out, scope, a, op)
            } else {
                data_processing(out, scope, a, op)
            }
        }
        0b010 => single_transfer(out, scope, a, op),
        0b011 if op & 0x10 != 0 => media(out, scope, a, op),
        0b011 => single_transfer(out, scope, a, op),
        0b100 => block_transfer(out, scope, a, op),
        0b101 => {
            let target = (a + 8).wrapping_add(sign_extend_24(op & 0x00FF_FFFF) << 2);
            if op & (1 << 24) != 0 { call(out, scope, a + 4, target, false) } else { jump(out, scope, target, false) }
        }
        0b111 if op & (1 << 24) != 0 => {
            emit!(out, "    SVC({}, 0x{:X}u);", scope.at(a + 4), op & 0x00FF_FFFF);
            false
        }
        // coprocessor and VFP
        _ => interpret(out, scope, a, op),
    }
}

/// the register data processing space, with the multiplies, extra loads
/// and stores and miscellaneous instructions in its holes.
fn register_space(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    if op & 0x90 == 0x90 {
        if (op >> 5) & 3 != 0 {
            return extra_transfer(out, scope, a, op);
        }
        if op & (1 << 24) != 0 {
            // swap and the exclusives
            return interpret(out, scope, a, op);
        }
        return match (op >> 21) & 7 {
            0b000 | 0b001 => multiply(out, scope, a, op),
            0b010 | 0b100..=0b111 => multiply_long(out, scope, a, op),
            _ => interpret(out, scope, a, op),
        };
    }
    if (op >> 23) & 3 == 0b10 && op & (1 << 20) == 0 {
        return match (op >> 4) & 0xF {
            0b0001 if (op >> 21) & 3 == 0b11 => clz(out, scope, a, op),
            0b0001 | 0b0011 => branch_exchange(out, scope, a, op),
            _ => interpret(out, scope, a, op),
        };
    }
    data_processing(out, scope, a, op)
}

fn interpret(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    emit!(out, "    INTERPRET({}, 0x{op:08X}u);", scope.at(a));
    true
}

/// the shifter operand as b, and its carry as sc when the flags need it.
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
        // an exception return, which also restores cpsr
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
            emit!(out, "    ctx->r[15] = r & ~3u; return;");
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

/// ldr, str, ldrb and strb.
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
    emit!(out, "    {{ uint32_t base = {}, oa = base {sign} {offset};", reg(scope, rn, a + 8));
    if load {
        let read = if byte { "mem_read8" } else { "mem_read32" };
        emit!(out, "    uint32_t v = {read}(ctx, {address});");
        if writeback && rn != rd {
            emit!(out, "    ctx->r[{rn}] = oa;");
        }
        if rd == 15 {
            // ldr pc, [sp], 4 is a pop
            let pop = rn == 13 && !pre && sign == '+' && op & (1 << 25) == 0 && op & 0xFFF == 4;
            emit!(out, "    {}(v); }}", if pop { "RETURN_TO" } else { "JUMP_TO" });
            return false;
        }
        emit!(out, "    ctx->r[{rd}] = v; }}");
    } else {
        // storing r15 stores the address plus 12
        let value = if rd == 15 { scope.at(a + 12) } else { format!("ctx->r[{rd}]") };
        if byte {
            emit!(out, "    mem_write8(ctx, {address}, (uint8_t){value});");
        } else {
            emit!(out, "    mem_write32(ctx, {address}, {value});");
        }
        if writeback {
            emit!(out, "    ctx->r[{rn}] = oa;");
        }
        emit!(out, "    }}");
    }
    true
}

/// ldrh, strh, ldrsb, ldrsh, ldrd and strd.
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
    emit!(out, "    {{ uint32_t base = {}, oa = base {sign} {offset};", reg(scope, rn, a + 8));
    match (kind, load) {
        (1, true) => emit!(out, "    uint32_t v = mem_read16(ctx, {address});{back} ctx->r[{rd}] = v; }}"),
        (1, false) => {
            emit!(out, "    mem_write16(ctx, {address}, (uint16_t){});{back} }}", reg(scope, rd, a + 8))
        }
        (2, true) => emit!(
            out,
            "    uint32_t v = (uint32_t)(int32_t)(int8_t)mem_read8(ctx, {address});{back} ctx->r[{rd}] = v; }}"
        ),
        (2, false) => emit!(
            out,
            "    uint32_t lo = mem_read32(ctx, {address}), hi = mem_read32(ctx, {address} + 4);{back} ctx->r[{rd}] = lo; ctx->r[{}] = hi; }}",
            rd + 1
        ),
        (_, true) => emit!(
            out,
            "    uint32_t v = (uint32_t)(int32_t)(int16_t)mem_read16(ctx, {address});{back} ctx->r[{rd}] = v; }}"
        ),
        (_, false) => emit!(
            out,
            "    mem_write32(ctx, {address}, ctx->r[{rd}]); mem_write32(ctx, {address} + 4, ctx->r[{}]);{back} }}",
            rd + 1
        ),
    }
    true
}

/// ldm and stm.
fn block_transfer(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rn = (op >> 16) & 0xF;
    let pre = op & (1 << 24) != 0;
    let up = op & (1 << 23) != 0;
    let writeback = op & (1 << 21) != 0;
    let load = op & (1 << 20) != 0;
    let list = op & 0xFFFF;
    // the user bank forms, empty lists and r15 as the base are rare enough
    // to leave alone
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
        for &register in &registers {
            if register == 15 {
                let jump = if rn == 13 { "RETURN_TO" } else { "JUMP_TO" };
                emit!(out, "    {jump}(mem_read32(ctx, p)); }}");
                return false;
            }
            emit!(out, "    ctx->r[{register}] = mem_read32(ctx, p); p += 4;");
        }
    } else {
        for &register in &registers {
            let value = if register == 15 {
                scope.at(a + 12)
            } else if register == rn && writeback && list & ((1 << rn) - 1) != 0 {
                // the base when it is not the lowest register stores its new value
                "fin".to_owned()
            } else {
                format!("ctx->r[{register}]")
            };
            emit!(out, "    mem_write32(ctx, p, {value}); p += 4;");
        }
        if writeback {
            emit!(out, "    ctx->r[{rn}] = fin;");
        }
    }
    emit!(out, "    (void)p; (void)fin; }}");
    true
}

/// mul and mla.
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

/// umull, umlal, smull, smlal and umaal.
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

fn clz(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op >> 12) & 0xF;
    if rd == 15 {
        return interpret(out, scope, a, op);
    }
    emit!(out, "    {{ uint32_t m = {}; ctx->r[{rd}] = m ? __builtin_clz(m) : 32; }}", reg(scope, op & 0xF, a + 8));
    true
}

/// bx and blx through a register.
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
        emit!(out, "    CALL(recomp_call);");
        emit!(out, "    RETURNED({});", scope.at(next));
        return true;
    }
    if rm == 14 {
        emit!(out, "    RETURN_TO(ctx->r[14]);");
    } else {
        emit!(out, "    JUMP_TO({});", reg(scope, rm, a + 8));
    }
    false
}

/// the sign and zero extensions and the byte reversals.
fn media(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let op1 = (op >> 20) & 0x1F;
    let op2 = (op >> 5) & 7;
    let rd = (op >> 12) & 0xF;
    if rd == 15 || op1 >> 3 != 0b01 {
        return interpret(out, scope, a, op);
    }
    let m = reg(scope, op & 0xF, a + 8);
    let value = match (op1, op2) {
        (_, 0b011) => {
            let rotate = ((op >> 10) & 3) * 8;
            let x = if rotate == 0 { m } else { format!("ror32({m}, {rotate})") };
            let extended = match op1 & 7 {
                0b010 => format!("(uint32_t)(int32_t)(int8_t){x}"),
                0b011 => format!("(uint32_t)(int32_t)(int16_t){x}"),
                0b110 => format!("({x} & 0xFF)"),
                0b111 => format!("({x} & 0xFFFF)"),
                // the packed halfword forms
                _ => return interpret(out, scope, a, op),
            };
            let rn = (op >> 16) & 0xF;
            if rn == 15 { extended } else { format!("ctx->r[{rn}] + {extended}") }
        }
        (0b01011, 0b001) => format!("__builtin_bswap32({m})"),
        (0b01011, 0b101) => format!("((({m}) & 0x00FF00FFu) << 8) | ((({m}) & 0xFF00FF00u) >> 8)"),
        (0b01111, 0b101) => format!("(uint32_t)(int32_t)(int16_t)(((({m}) & 0xFF) << 8) | ((({m}) >> 8) & 0xFF))"),
        _ => return interpret(out, scope, a, op),
    };
    emit!(out, "    ctx->r[{rd}] = {value};");
    true
}

/// the cond 0xF space.
fn unconditional(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    if op & 0xFE00_0000 == 0xFA00_0000 {
        // blx to Thumb
        let offset = (sign_extend_24(op & 0x00FF_FFFF) << 2) | (((op >> 24) & 1) << 1);
        return call(out, scope, a + 4, (a + 8).wrapping_add(offset) & !1, true);
    }
    if op & 0xFFF0_00F0 == 0xF570_0010 {
        // clrex, the reservation lives with the interpreter
        return interpret(out, scope, a, op);
    }
    if matches!((op >> 25) & 7, 0b010 | 0b011) {
        // pld and the barriers do nothing here
        return true;
    }
    interpret(out, scope, a, op)
}
