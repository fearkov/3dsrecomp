//! lowering VFPv2 to C, following zakuro-cpu's VFP, which computes singles
//! as f32 and doubles as f64, rounding once, and flushes results to zero
//! when fpscr asks.

use std::fmt::Write;

use super::Scope;

macro_rules! emit {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).unwrap()
    };
}

fn interpret(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    emit!(out, "    INTERPRET({}, 0x{op:08X}u);", scope.at(a));
    true
}

fn sreg(vd: u32, extra: bool) -> u32 {
    ((vd << 1) | extra as u32) & 31
}

fn dreg(vd: u32, extra: bool) -> u32 {
    ((extra as u32) << 4) | vd
}

/// a register of either size as C, doubles taking the two singles at 2N.
fn get(double: bool, register: u32) -> String {
    if double { format!("vfp_d(ctx, {})", register & 15) } else { format!("vfp_s(ctx, {register})") }
}

fn set(double: bool, register: u32, value: &str) -> String {
    if double { format!("vfp_set_d(ctx, {}, {value});", register & 15) } else { format!("vfp_set_s(ctx, {register}, {value});") }
}

/// writes body, or when fpscr has the instruction working on a short
/// vector, which only a destination past the first bank can, the loop
/// over it. operation numbers the arithmetic the way vfp_apply does, and
/// registers are d, n and m.
fn scalar(out: &mut String, double: bool, operation: u32, registers: (u32, u32, u32), body: &str) -> bool {
    let (d, n, m) = registers;
    let bank = if double { 4 } else { 8 };
    if d < bank {
        emit!(out, "    {{ {body} }}");
    } else {
        emit!(
            out,
            "    if (UNLIKELY(*ctx->fpscr & FPSCR_LEN)) vfp_vector(ctx, {operation}, {}, {d}, {n}, {m}); else {{ {body} }}",
            double as u8
        );
    }
    true
}

/// the cdp space of coprocessors 10 and 11, the arithmetic, the unary
/// operations, comparisons and conversions.
pub fn data_processing(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let coprocessor = (op >> 8) & 0xF;
    if coprocessor != 10 && coprocessor != 11 {
        return interpret(out, scope, a, op);
    }
    let double = coprocessor == 11;
    let (vd, vn, vm) = ((op >> 12) & 0xF, (op >> 16) & 0xF, op & 0xF);
    let (d_bit, n_bit, m_bit) = (op & (1 << 22) != 0, op & (1 << 7) != 0, op & (1 << 5) != 0);
    let (rd, rn, rm) = if double {
        (dreg(vd, d_bit), dreg(vn, n_bit), dreg(vm, m_bit))
    } else {
        (sreg(vd, d_bit), sreg(vn, n_bit), sreg(vm, m_bit))
    };
    let negate = op & (1 << 6) != 0;
    let (operation, expression) = match ((op >> 20) & 0b1011, negate) {
        (0b0000, false) => (0, "acc + a * b"),
        (0b0000, true) => (1, "acc - a * b"),
        (0b0001, false) => (2, "-acc + a * b"),
        (0b0001, true) => (3, "-acc - a * b"),
        (0b0010, false) => (4, "a * b"),
        (0b0010, true) => (5, "-(a * b)"),
        (0b0011, false) => (6, "a + b"),
        (0b0011, true) => (7, "a - b"),
        (0b1000, false) => (8, "a / b"),
        (0b1011, true) => return extension(out, scope, a, op, double, rd, rm),
        _ => return interpret(out, scope, a, op),
    };
    // a vector runs its operand m as a scalar when m is in the first bank,
    // which only matters to the interpreter
    let kind = if double { "double" } else { "float" };
    let body = format!(
        "{kind} a = {}, b = {}, acc = {}; {}",
        get(double, rn),
        get(double, rm),
        get(double, rd),
        set(double, rd, expression)
    );
    scalar(out, double, operation, (rd, rn, rm), &body)
}

fn extension(out: &mut String, scope: &Scope, a: u32, op: u32, double: bool, rd: u32, rm: u32) -> bool {
    let top = op & (1 << 7) != 0;
    match ((op >> 16) & 0xF, top) {
        // vmov, vabs, vneg and vsqrt, singles move their bits untouched
        (0b0000 | 0b0001, _) => {
            let second = (op >> 16) & 1 != 0;
            let body = if double {
                let value = match (second, top) {
                    (false, false) => "v",
                    (false, true) => "fabs(v)",
                    (true, false) => "-v",
                    (true, true) => "sqrt(v)",
                };
                format!("double v = {}; {}", get(true, rm), set(true, rd, value))
            } else {
                match (second, top) {
                    (false, false) => format!("ctx->vfp[{rd}] = ctx->vfp[{rm}];"),
                    (false, true) => format!("ctx->vfp[{rd}] = ctx->vfp[{rm}] & 0x7FFFFFFFu;"),
                    (true, false) => format!("ctx->vfp[{rd}] = ctx->vfp[{rm}] ^ 0x80000000u;"),
                    (true, true) => set(false, rd, &format!("sqrtf({})", get(false, rm))),
                }
            };
            scalar(out, double, 9 + ((second as u32) << 1 | top as u32), (rd, rd, rm), &body)
        }
        // vcmp against a register or zero, singles compared as doubles
        (0b0100, _) => {
            emit!(out, "    vfp_compare(ctx, {}, {});", get(double, rd), get(double, rm));
            true
        }
        (0b0101, _) => {
            emit!(out, "    vfp_compare(ctx, {}, 0.0);", get(double, rd));
            true
        }
        // vcvt between single and double
        (0b0111, true) => {
            let (vd, vm) = ((op >> 12) & 0xF, op & 0xF);
            let (d_bit, m_bit) = (op & (1 << 22) != 0, op & (1 << 5) != 0);
            if double {
                emit!(out, "    {}", set(false, sreg(vd, d_bit), &format!("(float){}", get(true, rm))));
            } else {
                emit!(out, "    {}", set(true, dreg(vd, d_bit), &format!("(double){}", get(false, sreg(vm, m_bit)))));
            }
            true
        }
        // vcvt from an integer, bit 7 set for signed
        (0b1000, _) => {
            let source = sreg(op & 0xF, op & (1 << 5) != 0);
            let integer = if top { format!("(double)(int32_t)ctx->vfp[{source}]") } else { format!("(double)ctx->vfp[{source}]") };
            let value = if double { integer } else { format!("(float){integer}") };
            emit!(out, "    {}", set(double, rd, &value));
            true
        }
        // vcvt to an integer rounding toward zero, the other rounding modes
        // are rare enough for the interpreter
        (0b1100 | 0b1101, true) => {
            let source = if double { get(true, rm) } else { format!("(double){}", get(false, rm)) };
            let convert = if (op >> 16) & 1 != 0 { "vfp_to_s32" } else { "vfp_to_u32" };
            let destination = sreg((op >> 12) & 0xF, op & (1 << 22) != 0);
            emit!(out, "    ctx->vfp[{destination}] = {convert}({source});");
            true
        }
        _ => interpret(out, scope, a, op),
    }
}

/// the mrc and mcr space of coprocessors 10 and 11, moves between core and
/// VFP registers and to and from fpscr.
pub fn register_transfer(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let coprocessor = (op >> 8) & 0xF;
    let load = op & (1 << 20) != 0;
    let rt = (op >> 12) & 0xF;
    match (coprocessor, (op >> 21) & 7) {
        // vmrs and vmsr on fpscr
        (10 | 11, 7) if (op >> 16) & 0xF == 1 => {
            if !load {
                emit!(out, "    *ctx->fpscr = {};", if rt == 15 { scope.at(a + 8) } else { format!("ctx->r[{rt}]") });
            } else if rt == 15 {
                emit!(out, "    {{ uint32_t f = *ctx->fpscr; ctx->n = f >> 31; ctx->z = (f >> 30) & 1; ctx->c = (f >> 29) & 1; ctx->v = (f >> 28) & 1; }}");
            } else {
                emit!(out, "    ctx->r[{rt}] = *ctx->fpscr;");
            }
            true
        }
        // vmov between a core register and a single
        (10 | 11, 0) if rt != 15 => {
            let sn = sreg((op >> 16) & 0xF, op & (1 << 7) != 0);
            if load {
                emit!(out, "    ctx->r[{rt}] = ctx->vfp[{sn}];");
            } else {
                emit!(out, "    ctx->vfp[{sn}] = ctx->r[{rt}];");
            }
            true
        }
        _ => interpret(out, scope, a, op),
    }
}

/// the ldc and stc space of coprocessors 10 and 11, vldr, vstr, vldm and
/// vstm, and the moves between two core registers and a double.
pub fn load_store(out: &mut String, scope: &Scope, a: u32, op: u32) -> bool {
    let coprocessor = (op >> 8) & 0xF;
    if coprocessor != 10 && coprocessor != 11 {
        return interpret(out, scope, a, op);
    }
    let double = coprocessor == 11;
    if (op >> 21) & 0x7F == 0b110_0010 {
        return move_pair(out, scope, a, op, double);
    }
    let load = op & (1 << 20) != 0;
    let pre = op & (1 << 24) != 0;
    let up = op & (1 << 23) != 0;
    let writeback = op & (1 << 21) != 0;
    let rn = (op >> 16) & 0xF;
    if writeback && rn == 15 {
        return interpret(out, scope, a, op);
    }
    let offset = (op & 0xFF) * 4;
    let (vd, d_bit) = ((op >> 12) & 0xF, op & (1 << 22) != 0);
    let first = if double { dreg(vd, d_bit) } else { sreg(vd, d_bit) };
    let count = if pre && !writeback {
        1
    } else if double {
        (op & 0xFF) / 2
    } else {
        op & 0xFF
    };
    let base = if rn == 15 { scope.at(a + 8) } else { format!("ctx->r[{rn}]") };
    let start = match (up, pre && !writeback) {
        (true, true) => format!("base + 0x{offset:X}u"),
        (true, false) => "base".to_owned(),
        (false, _) => format!("base - 0x{offset:X}u"),
    };
    emit!(out, "    {{ uint32_t base = {base}, p = {start};");
    for i in 0..count.max(1) {
        let words: Vec<u32> = if double {
            let index = first + i;
            vec![(index * 2) & 31, (index * 2 + 1) & 31]
        } else {
            vec![(first + i) & 31]
        };
        for (j, word) in words.into_iter().enumerate() {
            let address = if j == 0 { "p".to_owned() } else { "p + 4".to_owned() };
            if load {
                emit!(out, "    ctx->vfp[{word}] = mem_read32(ctx, {address});");
            } else {
                emit!(out, "    mem_write32(ctx, {address}, ctx->vfp[{word}]);");
            }
        }
        emit!(out, "    p += {};", if double { 8 } else { 4 });
    }
    if writeback {
        let sign = if up { '+' } else { '-' };
        emit!(out, "    ctx->r[{rn}] = base {sign} 0x{offset:X}u;");
    }
    emit!(out, "    (void)p; }}");
    true
}

/// vmov between two core registers and a double or two singles.
fn move_pair(out: &mut String, scope: &Scope, a: u32, op: u32, double: bool) -> bool {
    let load = op & (1 << 20) != 0;
    let rt = (op >> 12) & 0xF;
    let rt2 = (op >> 16) & 0xF;
    if rt == 15 || rt2 == 15 {
        return interpret(out, scope, a, op);
    }
    let (vm, m_bit) = (op & 0xF, op & (1 << 5) != 0);
    let (low, high) = if double {
        let dm = dreg(vm, m_bit);
        ((dm * 2) & 31, (dm * 2 + 1) & 31)
    } else {
        let sm = sreg(vm, m_bit);
        (sm, (sm + 1) & 31)
    };
    if load {
        emit!(out, "    ctx->r[{rt}] = ctx->vfp[{low}]; ctx->r[{rt2}] = ctx->vfp[{high}];");
    } else {
        emit!(out, "    ctx->vfp[{low}] = ctx->r[{rt}]; ctx->vfp[{high}] = ctx->r[{rt2}];");
    }
    true
}
