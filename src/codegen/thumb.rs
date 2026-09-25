//! lowering Thumb instructions to C, following zakuro-cpu's decoding the
//! same way the ARM side does. r15 reads as the address plus 4.

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

const NZ: &str = "ctx->n = r >> 31; ctx->z = r == 0;";
const ADD_FLAGS: &str = "ctx->n = r >> 31; ctx->z = r == 0; ctx->c = r < a; ctx->v = ((a ^ r) & (b ^ r)) >> 31;";
const SUB_FLAGS: &str = "ctx->n = r >> 31; ctx->z = r == 0; ctx->c = a >= b; ctx->v = ((a ^ b) & (a ^ r)) >> 31;";

fn sign_extend(value: u32, bits: u32) -> u32 {
    (((value << (32 - bits)) as i32) >> (32 - bits)) as u32
}

/// reading a register, where r15 is the address plus 4.
fn reg(scope: &Scope, register: u32, a: u32) -> String {
    if register == 15 { scope.at(a + 4) } else { format!("ctx->r[{register}]") }
}

fn interpret(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    emit!(out, "    INTERPRET({}, 0x{op:04X}u);", scope.at(a));
    true
}

/// writes the C for the instruction at address, second being the halfword
/// after it, returning whether execution can carry on to the next one.
pub fn lower(out: &mut String, scope: &Scope, a: u32, op: u32, second: u32) -> bool {
    match op >> 13 {
        0b000 if (op >> 11) & 3 == 0b11 => add_subtract(out, op),
        0b000 => shift_immediate(out, op),
        0b001 => immediate(out, op),
        0b010 if op & (1 << 12) != 0 => register_offset(out, op),
        0b010 if op & (1 << 11) != 0 => {
            let literal = ((a + 4) & !3) + (op & 0xFF) * 4;
            emit!(out, "    ctx->r[{}] = mem_read32(ctx, {});", (op >> 8) & 7, scope.at(literal));
            true
        }
        0b010 if op & (1 << 10) != 0 => high_register(out, scope, a, op),
        0b010 => alu(out, op),
        0b011 => immediate_offset(out, op),
        0b100 if op & (1 << 12) != 0 => {
            let rd = (op >> 8) & 7;
            let address = format!("ctx->r[13] + 0x{:X}u", (op & 0xFF) * 4);
            if op & (1 << 11) != 0 {
                emit!(out, "    ctx->r[{rd}] = mem_read32(ctx, {address});");
            } else {
                emit!(out, "    mem_write32(ctx, {address}, ctx->r[{rd}]);");
            }
            true
        }
        0b100 => {
            let (rd, rb) = (op & 7, (op >> 3) & 7);
            let address = format!("ctx->r[{rb}] + 0x{:X}u", ((op >> 6) & 0x1F) * 2);
            if op & (1 << 11) != 0 {
                emit!(out, "    ctx->r[{rd}] = mem_read16(ctx, {address});");
            } else {
                emit!(out, "    mem_write16(ctx, {address}, (uint16_t)ctx->r[{rd}]);");
            }
            true
        }
        0b101 if op & (1 << 12) != 0 => miscellaneous(out, scope, a, op),
        0b101 => {
            // add rd, pc or sp, imm
            let offset = (op & 0xFF) * 4;
            let rd = (op >> 8) & 7;
            if op & (1 << 11) != 0 {
                emit!(out, "    ctx->r[{rd}] = ctx->r[13] + 0x{offset:X}u;");
            } else {
                emit!(out, "    ctx->r[{rd}] = {};", scope.at(((a + 4) & !3) + offset));
            }
            true
        }
        0b110 if op & (1 << 12) != 0 => conditional_branch(out, scope, a, op),
        0b110 => block_transfer(out, op),
        _ => match op >> 11 {
            0b11100 => jump(out, scope, (a + 4).wrapping_add(sign_extend(op & 0x7FF, 11) << 1), true),
            0b11110 if matches!(second >> 11, 0b11111 | 0b11101) => {
                let high = sign_extend(op & 0x7FF, 11) << 12;
                let target = (a + 4).wrapping_add(high).wrapping_add((second & 0x7FF) << 1);
                if second >> 11 == 0b11111 {
                    call(out, scope, (a + 4) | 1, target, true)
                } else {
                    call(out, scope, (a + 4) | 1, target & !3, false)
                }
            }
            // a half of bl on its own
            _ => interpret(out, scope, a, op),
        },
    }
}

/// lsl, lsr and asr by an immediate.
fn shift_immediate(out: &mut String, op: u32) -> bool {
    let amount = (op >> 6) & 0x1F;
    let (value, carry) = match ((op >> 11) & 3, amount) {
        (0, 0) => ("m".to_owned(), None),
        (0, n) => (format!("m << {n}"), Some(format!("(m >> {}) & 1", 32 - n))),
        (1, 0) => ("0".to_owned(), Some("m >> 31".to_owned())),
        (1, n) => (format!("m >> {n}"), Some(format!("(m >> {}) & 1", n - 1))),
        (_, 0) => ("(uint32_t)((int32_t)m >> 31)".to_owned(), Some("m >> 31".to_owned())),
        (_, n) => (format!("(uint32_t)((int32_t)m >> {n})"), Some(format!("(m >> {}) & 1", n - 1))),
    };
    let carry = carry.map(|c| format!(" ctx->c = {c};")).unwrap_or_default();
    emit!(out, "    {{ uint32_t m = ctx->r[{}], r = {value};{carry} ctx->r[{}] = r; {NZ} }}", (op >> 3) & 7, op & 7);
    true
}

/// add and sub with a register or a 3 bit immediate.
fn add_subtract(out: &mut String, op: u32) -> bool {
    let field = (op >> 6) & 7;
    let b = if op & (1 << 10) != 0 { format!("{field}u") } else { format!("ctx->r[{field}]") };
    let (operation, flags) = if op & (1 << 9) != 0 { ("a - b", SUB_FLAGS) } else { ("a + b", ADD_FLAGS) };
    emit!(out, "    {{ uint32_t a = ctx->r[{}], b = {b}, r = {operation}; ctx->r[{}] = r; {flags} }}", (op >> 3) & 7, op & 7);
    true
}

/// mov, cmp, add and sub with an 8 bit immediate.
fn immediate(out: &mut String, op: u32) -> bool {
    let rd = (op >> 8) & 7;
    let imm = op & 0xFF;
    match (op >> 11) & 3 {
        0 => emit!(out, "    ctx->r[{rd}] = {imm}u; ctx->n = 0; ctx->z = {};", (imm == 0) as u8),
        1 => emit!(out, "    {{ uint32_t a = ctx->r[{rd}], b = {imm}u, r = a - b; {SUB_FLAGS} }}"),
        2 => emit!(out, "    {{ uint32_t a = ctx->r[{rd}], b = {imm}u, r = a + b; ctx->r[{rd}] = r; {ADD_FLAGS} }}"),
        _ => emit!(out, "    {{ uint32_t a = ctx->r[{rd}], b = {imm}u, r = a - b; ctx->r[{rd}] = r; {SUB_FLAGS} }}"),
    }
    true
}

/// the register to register ALU operations.
fn alu(out: &mut String, op: u32) -> bool {
    let rd = op & 7;
    let rs = (op >> 3) & 7;
    let body = match (op >> 6) & 0xF {
        0x0 => format!("r = a & b; ctx->r[{rd}] = r; {NZ}"),
        0x1 => format!("r = a ^ b; ctx->r[{rd}] = r; {NZ}"),
        kind @ (0x2 | 0x3 | 0x4 | 0x7) => {
            let shift = match kind {
                0x2 => "shift_lsl",
                0x3 => "shift_lsr",
                0x4 => "shift_asr",
                _ => "shift_ror",
            };
            format!("uint8_t sc = ctx->c; r = {shift}(a, b, &sc); ctx->r[{rd}] = r; {NZ} ctx->c = sc;")
        }
        0x5 => format!(
            "uint8_t ci = ctx->c; r = a + b + ci; ctx->r[{rd}] = r; {NZ} ctx->c = ((uint64_t)a + b + ci) >> 32; ctx->v = ((a ^ r) & (b ^ r)) >> 31;"
        ),
        0x6 => format!(
            "uint8_t ci = ctx->c; r = a - b - !ci; ctx->r[{rd}] = r; {NZ} ctx->c = (uint64_t)a >= (uint64_t)b + !ci; ctx->v = ((a ^ b) & (a ^ r)) >> 31;"
        ),
        0x8 => format!("r = a & b; {NZ}"),
        // neg is rsb 0
        0x9 => format!("r = 0 - b; ctx->r[{rd}] = r; {NZ} ctx->c = b == 0; ctx->v = (b & r) >> 31;"),
        0xA => format!("r = a - b; {SUB_FLAGS}"),
        0xB => format!("r = a + b; {ADD_FLAGS}"),
        0xC => format!("r = a | b; ctx->r[{rd}] = r; {NZ}"),
        0xD => format!("r = a * b; ctx->r[{rd}] = r; {NZ}"),
        0xE => format!("r = a & ~b; ctx->r[{rd}] = r; {NZ}"),
        _ => format!("r = ~b; ctx->r[{rd}] = r; {NZ}"),
    };
    emit!(out, "    {{ uint32_t a = ctx->r[{rd}], b = ctx->r[{rs}], r; {body} }}");
    true
}

/// add, cmp and mov on the high registers, and bx and blx.
fn high_register(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = (op & 7) | ((op >> 4) & 8);
    let rs = (op >> 3) & 0xF;
    let source = reg(scope, rs, a);
    match (op >> 8) & 3 {
        0 if rd == 15 => {
            // writing pc keeps Thumb
            emit!(out, "    target = ({} + {source}) & ~1u; goto dispatch;", reg(scope, rd, a));
            false
        }
        0 => {
            emit!(out, "    ctx->r[{rd}] = {} + {source};", reg(scope, rd, a));
            true
        }
        1 => {
            emit!(out, "    {{ uint32_t a = {}, b = {source}, r = a - b; {SUB_FLAGS} }}", reg(scope, rd, a));
            true
        }
        2 if rd == 15 && rs == 14 => {
            emit!(out, "    ctx->r[15] = ctx->r[14] & ~1u; return;");
            false
        }
        2 if rd == 15 => {
            emit!(out, "    target = {source} & ~1u; goto dispatch;");
            false
        }
        2 => {
            emit!(out, "    ctx->r[{rd}] = {source};");
            true
        }
        _ if op & (1 << 7) != 0 => {
            let next = a + 2;
            emit!(
                out,
                "    {{ uint32_t v = {source}; ctx->r[14] = {} | 1; ctx->thumb = v & 1; ctx->r[15] = v & (ctx->thumb ? ~1u : ~3u); }}",
                scope.at(next)
            );
            emit!(out, "    CALL(recomp_call);");
            emit!(out, "    RETURNED_T({});", scope.at(next));
            true
        }
        _ if rs == 14 => {
            emit!(out, "    RETURN_TO(ctx->r[14]);");
            false
        }
        _ => {
            emit!(out, "    JUMP_TO({source});");
            false
        }
    }
}

/// loads and stores with a register offset.
fn register_offset(out: &mut String, op: u32) -> bool {
    let rd = op & 7;
    let address = format!("ctx->r[{}] + ctx->r[{}]", (op >> 3) & 7, (op >> 6) & 7);
    let signed = op & (1 << 9) != 0;
    match ((op >> 10) & 3, signed) {
        (0, true) => emit!(out, "    mem_write16(ctx, {address}, (uint16_t)ctx->r[{rd}]);"),
        (1, true) => emit!(out, "    ctx->r[{rd}] = (uint32_t)(int32_t)(int8_t)mem_read8(ctx, {address});"),
        (2, true) => emit!(out, "    ctx->r[{rd}] = mem_read16(ctx, {address});"),
        (_, true) => emit!(out, "    ctx->r[{rd}] = (uint32_t)(int32_t)(int16_t)mem_read16(ctx, {address});"),
        (0, false) => emit!(out, "    mem_write32(ctx, {address}, ctx->r[{rd}]);"),
        (1, false) => emit!(out, "    mem_write8(ctx, {address}, (uint8_t)ctx->r[{rd}]);"),
        (2, false) => emit!(out, "    ctx->r[{rd}] = mem_read32(ctx, {address});"),
        (_, false) => emit!(out, "    ctx->r[{rd}] = mem_read8(ctx, {address});"),
    }
    true
}

/// ldr, str, ldrb and strb with an immediate offset.
fn immediate_offset(out: &mut String, op: u32) -> bool {
    let rd = op & 7;
    let byte = op & (1 << 12) != 0;
    let offset = ((op >> 6) & 0x1F) * if byte { 1 } else { 4 };
    let address = format!("ctx->r[{}] + 0x{offset:X}u", (op >> 3) & 7);
    match (op & (1 << 11) != 0, byte) {
        (true, false) => emit!(out, "    ctx->r[{rd}] = mem_read32(ctx, {address});"),
        (true, true) => emit!(out, "    ctx->r[{rd}] = mem_read8(ctx, {address});"),
        (false, false) => emit!(out, "    mem_write32(ctx, {address}, ctx->r[{rd}]);"),
        (false, true) => emit!(out, "    mem_write8(ctx, {address}, (uint8_t)ctx->r[{rd}]);"),
    }
    true
}

fn miscellaneous(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let rd = op & 7;
    let m = format!("ctx->r[{}]", (op >> 3) & 7);
    match (op >> 8) & 0xF {
        0b0000 => {
            let sign = if op & (1 << 7) != 0 { '-' } else { '+' };
            emit!(out, "    ctx->r[13] = ctx->r[13] {sign} 0x{:X}u;", (op & 0x7F) * 4);
            true
        }
        0b0010 => {
            let value = match (op >> 6) & 3 {
                0 => format!("(uint32_t)(int32_t)(int16_t){m}"),
                1 => format!("(uint32_t)(int32_t)(int8_t){m}"),
                2 => format!("({m} & 0xFFFF)"),
                _ => format!("({m} & 0xFF)"),
            };
            emit!(out, "    ctx->r[{rd}] = {value};");
            true
        }
        0b1010 => {
            let value = match (op >> 6) & 3 {
                0 => format!("__builtin_bswap32({m})"),
                1 => format!("(({m} & 0x00FF00FFu) << 8) | (({m} & 0xFF00FF00u) >> 8)"),
                3 => format!("(uint32_t)(int32_t)(int16_t)((({m} & 0xFF) << 8) | (({m} >> 8) & 0xFF))"),
                _ => return interpret(out, scope, a, op),
            };
            emit!(out, "    ctx->r[{rd}] = {value};");
            true
        }
        // cps, setend and the hints do nothing here
        0b0110 | 0b1111 => true,
        0b0100 | 0b0101 | 0b1100 | 0b1101 => push_pop(out, op),
        _ => interpret(out, scope, a, op),
    }
}

fn push_pop(out: &mut String, op: u32) -> bool {
    let list = op & 0xFF;
    let extra = op & (1 << 8) != 0;
    let count = list.count_ones() + extra as u32;
    let registers: Vec<u32> = (0..8).filter(|i| list & (1 << i) != 0).collect();
    if op & (1 << 11) != 0 {
        emit!(out, "    {{ uint32_t p = ctx->r[13];");
        for register in registers {
            emit!(out, "    ctx->r[{register}] = mem_read32(ctx, p); p += 4;");
        }
        emit!(out, "    ctx->r[13] += {}u;", count * 4);
        if extra {
            emit!(out, "    RETURN_TO(mem_read32(ctx, p)); }}");
            return false;
        }
        emit!(out, "    (void)p; }}");
    } else {
        emit!(out, "    {{ uint32_t start = ctx->r[13] - {}u, p = start;", count * 4);
        for register in registers {
            emit!(out, "    mem_write32(ctx, p, ctx->r[{register}]); p += 4;");
        }
        if extra {
            emit!(out, "    mem_write32(ctx, p, ctx->r[14]);");
        }
        emit!(out, "    ctx->r[13] = start; (void)p; }}");
    }
    true
}

/// ldmia and stmia.
fn block_transfer(out: &mut String, op: u32) -> bool {
    let rb = (op >> 8) & 7;
    let list = op & 0xFF;
    if list == 0 {
        emit!(out, "    ctx->r[{rb}] += 0x40u;");
        return true;
    }
    let load = op & (1 << 11) != 0;
    emit!(out, "    {{ uint32_t p = ctx->r[{rb}], fin = p + {}u;", list.count_ones() * 4);
    for register in (0..8).filter(|i| list & (1 << i) != 0) {
        if load {
            emit!(out, "    ctx->r[{register}] = mem_read32(ctx, p); p += 4;");
        } else {
            emit!(out, "    mem_write32(ctx, p, ctx->r[{register}]); p += 4;");
        }
    }
    if !(load && list & (1 << rb) != 0) {
        emit!(out, "    ctx->r[{rb}] = fin;");
    }
    emit!(out, "    (void)fin; }}");
    true
}

/// conditional branches, with svc and undefined in the last two conditions.
fn conditional_branch(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    match (op >> 8) & 0xF {
        0xF => {
            emit!(out, "    SVC({}, 0x{:X}u);", scope.at(a + 2), op & 0xFF);
            false
        }
        0xE => interpret(out, scope, a, op),
        condition => {
            let target = (a + 4).wrapping_add(sign_extend(op & 0xFF, 8) << 1);
            emit!(out, "    if ({}) {{", CONDITIONS[condition as usize]);
            jump(out, scope, target, true);
            emit!(out, "    }}");
            true
        }
    }
}
