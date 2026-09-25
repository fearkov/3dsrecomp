/* the interface between recompiled code and the emulator running it. */

#ifndef RECOMP_H
#define RECOMP_H

#include <math.h>
#include <stdint.h>
#include <string.h>

#define RECOMP_ABI 3

typedef struct Context Context;
typedef void (*Code)(Context *);

typedef struct Host {
    uint8_t (*read8)(Context *, uint32_t);
    uint16_t (*read16)(Context *, uint32_t);
    uint32_t (*read32)(Context *, uint32_t);
    void (*write8)(Context *, uint32_t, uint8_t);
    void (*write16)(Context *, uint32_t, uint16_t);
    void (*write32)(Context *, uint32_t, uint32_t);
    /* runs one instruction the recompiler left to the interpreter. when it
       branches or fails the host sets exit and r15. */
    void (*interpret)(Context *, uint32_t address, uint32_t opcode);
    /* the code for an address, bit 0 set for Thumb, or null. */
    Code (*lookup)(Context *, uint32_t address);
} Host;

/* why the code gave control back to the host. */
enum {
    EXIT_NONE,
    /* an svc, its number is in svc and r15 points after it. */
    EXIT_SVC,
    /* the budget ran out, r15 is where to resume. */
    EXIT_BUDGET,
    /* anything else, the host carries on from r15. */
    EXIT_UNWIND,
};

struct Context {
    uint32_t r[16];
    uint8_t n, z, c, v, q, thumb, ge, pad;
    int32_t budget;
    uint32_t exit;
    uint32_t svc;
    uint32_t depth;
    /* a host pointer for each 4 KiB page, or null when the host has to
       handle the access. */
    uint8_t *const *read_pages;
    uint8_t *const *write_pages;
    /* the VFP registers, s0 to s31 with dN in s2N and s2N+1, and fpscr,
       which the interpreter works on too. */
    uint32_t *vfp;
    uint32_t *fpscr;
    const Host *host;
    void *user;
};

typedef struct Entry {
    uint32_t address;
    Code code;
} Entry;

/* a module's code, whose entries are offsets from where it gets loaded. */
typedef struct Module {
    const char *name;
    /* where the host loaded it, which the code reads. */
    uint32_t *base;
    /* the end of its code, as an offset. */
    uint32_t size;
    uint32_t count;
    const Entry *entries;
} Module;

#define RECOMP_EXPORT __attribute__((visibility("default")))
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

static inline uint8_t mem_read8(Context *ctx, uint32_t address) {
    uint8_t *page = ctx->read_pages[address >> 12];
    if (LIKELY(page)) return page[address & 0xFFF];
    return ctx->host->read8(ctx, address);
}

static inline uint16_t mem_read16(Context *ctx, uint32_t address) {
    uint8_t *page = ctx->read_pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFE)) {
        uint16_t value;
        memcpy(&value, page + offset, 2);
        return value;
    }
    return ctx->host->read16(ctx, address);
}

static inline uint32_t mem_read32(Context *ctx, uint32_t address) {
    uint8_t *page = ctx->read_pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFC)) {
        uint32_t value;
        memcpy(&value, page + offset, 4);
        return value;
    }
    return ctx->host->read32(ctx, address);
}

static inline void mem_write8(Context *ctx, uint32_t address, uint8_t value) {
    uint8_t *page = ctx->write_pages[address >> 12];
    if (LIKELY(page)) page[address & 0xFFF] = value;
    else ctx->host->write8(ctx, address, value);
}

static inline void mem_write16(Context *ctx, uint32_t address, uint16_t value) {
    uint8_t *page = ctx->write_pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFE)) memcpy(page + offset, &value, 2);
    else ctx->host->write16(ctx, address, value);
}

static inline void mem_write32(Context *ctx, uint32_t address, uint32_t value) {
    uint8_t *page = ctx->write_pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFC)) memcpy(page + offset, &value, 4);
    else ctx->host->write32(ctx, address, value);
}

#define C_EQ (ctx->z)
#define C_NE (!ctx->z)
#define C_CS (ctx->c)
#define C_CC (!ctx->c)
#define C_MI (ctx->n)
#define C_PL (!ctx->n)
#define C_VS (ctx->v)
#define C_VC (!ctx->v)
#define C_HI (ctx->c && !ctx->z)
#define C_LS (!ctx->c || ctx->z)
#define C_GE (ctx->n == ctx->v)
#define C_LT (ctx->n != ctx->v)
#define C_GT (!ctx->z && ctx->n == ctx->v)
#define C_LE (ctx->z || ctx->n != ctx->v)

static inline uint32_t ror32(uint32_t value, uint32_t amount) {
    amount &= 31;
    return amount ? (value >> amount) | (value << (32 - amount)) : value;
}

/* shifts by a register, the amount is its bottom byte. */
static inline uint32_t shift_lsl(uint32_t value, uint32_t amount, uint8_t *carry) {
    amount &= 0xFF;
    if (amount == 0) return value;
    if (amount < 32) { *carry = (value >> (32 - amount)) & 1; return value << amount; }
    *carry = amount == 32 ? value & 1 : 0;
    return 0;
}

static inline uint32_t shift_lsr(uint32_t value, uint32_t amount, uint8_t *carry) {
    amount &= 0xFF;
    if (amount == 0) return value;
    if (amount < 32) { *carry = (value >> (amount - 1)) & 1; return value >> amount; }
    *carry = amount == 32 ? value >> 31 : 0;
    return 0;
}

static inline uint32_t shift_asr(uint32_t value, uint32_t amount, uint8_t *carry) {
    amount &= 0xFF;
    if (amount == 0) return value;
    if (amount < 32) { *carry = ((int32_t)value >> (amount - 1)) & 1; return (uint32_t)((int32_t)value >> amount); }
    *carry = value >> 31;
    return (uint32_t)((int32_t)value >> 31);
}

static inline uint32_t shift_ror(uint32_t value, uint32_t amount, uint8_t *carry) {
    amount &= 0xFF;
    if (amount == 0) return value;
    amount &= 31;
    if (amount == 0) { *carry = value >> 31; return value; }
    *carry = (value >> (amount - 1)) & 1;
    return ror32(value, amount);
}

#define FPSCR_FZ (1u << 24)
/* the short vector length, zero when an instruction works on one register. */
#define FPSCR_LEN (7u << 16)

static inline float vfp_s(Context *ctx, int r) {
    float value;
    memcpy(&value, &ctx->vfp[r], 4);
    return value;
}

static inline double vfp_d(Context *ctx, int d) {
    uint64_t bits = ctx->vfp[2 * d] | (uint64_t)ctx->vfp[2 * d + 1] << 32;
    double value;
    memcpy(&value, &bits, 8);
    return value;
}

/* stores a result, flushing a subnormal to zero when the guest asked. */
static inline void vfp_set_s(Context *ctx, int r, float value) {
    uint32_t bits;
    memcpy(&bits, &value, 4);
    if ((*ctx->fpscr & FPSCR_FZ) && !(bits & 0x7F800000u) && (bits & 0x007FFFFFu)) bits &= 0x80000000u;
    ctx->vfp[r] = bits;
}

static inline void vfp_set_d(Context *ctx, int d, double value) {
    uint64_t bits;
    memcpy(&bits, &value, 8);
    if ((*ctx->fpscr & FPSCR_FZ) && !(bits & 0x7FF0000000000000ull) && (bits & 0x000FFFFFFFFFFFFFull))
        bits &= 0x8000000000000000ull;
    ctx->vfp[2 * d] = (uint32_t)bits;
    ctx->vfp[2 * d + 1] = (uint32_t)(bits >> 32);
}

/* the comparison result in fpscr's top bits, the nzcv encoding. */
static inline void vfp_compare(Context *ctx, double a, double b) {
    uint32_t flags = (a != a || b != b) ? 0x3 : a == b ? 0x6 : a < b ? 0x8 : 0x2;
    *ctx->fpscr = (*ctx->fpscr & 0x0FFFFFFFu) | flags << 28;
}

/* conversions to integers, rounding toward zero and saturating. */
static inline uint32_t vfp_to_s32(double value) {
    if (value != value) return 0;
    if (value >= 2147483647.0) return 0x7FFFFFFFu;
    if (value <= -2147483648.0) return 0x80000000u;
    return (uint32_t)(int32_t)value;
}

static inline uint32_t vfp_to_u32(double value) {
    if (value != value) return 0;
    if (value >= 4294967295.0) return 0xFFFFFFFFu;
    if (value <= 0.0) return 0;
    return (uint32_t)value;
}

/* the arithmetic, numbered the way the code generator passes it, from the
   multiply-accumulates to vsqrt, whose operand is b. */
static inline float vfp_apply_s(int op, float a, float b, float acc) {
    switch (op) {
    case 0: return acc + a * b;
    case 1: return acc - a * b;
    case 2: return -acc + a * b;
    case 3: return -acc - a * b;
    case 4: return a * b;
    case 5: return -(a * b);
    case 6: return a + b;
    case 7: return a - b;
    case 8: return a / b;
    default: return sqrtf(b);
    }
}

static inline double vfp_apply_d(int op, double a, double b, double acc) {
    switch (op) {
    case 0: return acc + a * b;
    case 1: return acc - a * b;
    case 2: return -acc + a * b;
    case 3: return -acc - a * b;
    case 4: return a * b;
    case 5: return -(a * b);
    case 6: return a + b;
    case 7: return a - b;
    case 8: return a / b;
    case 9: return b;
    case 10: return fabs(b);
    case 11: return -b;
    default: return sqrt(b);
    }
}

/* where register reg is on step i of a short vector, going around its bank. */
static inline int vfp_step(int reg, int bank, int i, int stride) {
    return (reg & ~(bank - 1)) | ((reg + i * stride) & (bank - 1));
}

/* an operation on a short vector, which fpscr's len and stride shape. m
   stays put when it is in the first bank. */
static void vfp_vector(Context *ctx, int op, int wide, int d, int n, int m) {
    uint32_t fpscr = *ctx->fpscr;
    int length = ((fpscr >> 16) & 7) + 1;
    int stride = ((fpscr >> 20) & 3) == 3 ? 2 : 1;
    int bank = wide ? 4 : 8;
    for (int i = 0; i < length; i++) {
        int dd = vfp_step(d, bank, i, stride), nn = vfp_step(n, bank, i, stride);
        int mm = m < bank ? m : vfp_step(m, bank, i, stride);
        if (wide) {
            vfp_set_d(ctx, dd & 15, vfp_apply_d(op, vfp_d(ctx, nn & 15), vfp_d(ctx, mm & 15), vfp_d(ctx, dd & 15)));
        } else if (op >= 9 && op <= 11) {
            /* vmov, vabs and vneg move the bits untouched */
            uint32_t bits = ctx->vfp[mm];
            ctx->vfp[dd] = op == 9 ? bits : op == 10 ? bits & 0x7FFFFFFFu : bits ^ 0x80000000u;
        } else {
            vfp_set_s(ctx, dd, vfp_apply_s(op, vfp_s(ctx, nn), vfp_s(ctx, mm), vfp_s(ctx, dd)));
        }
    }
}

#define RECOMP_DEPTH_LIMIT 2048

/* a guest call, leaving the caller too when the host has to take over. */
#define CALL(code) do { \
    if (UNLIKELY(++ctx->depth > RECOMP_DEPTH_LIMIT)) { ctx->depth--; ctx->exit = EXIT_UNWIND; return; } \
    code(ctx); \
    ctx->depth--; \
    if (UNLIKELY(ctx->exit)) return; \
} while (0)

/* runs whatever code the host has for r15. */
static inline void recomp_call(Context *ctx) {
    Code code = ctx->host->lookup(ctx, ctx->r[15] | ctx->thumb);
    if (code) code(ctx);
    else ctx->exit = EXIT_UNWIND;
}

/* after a call, anything but a plain return to the next instruction goes
   through dispatch. */
#define RETURNED(address) \
    if (UNLIKELY(ctx->r[15] != (address) || ctx->thumb)) { target = ctx->r[15]; goto dispatch; }

#define RETURNED_T(address) \
    if (UNLIKELY(ctx->r[15] != (address) || !ctx->thumb)) { target = ctx->r[15]; goto dispatch; }

/* a return that may switch to Thumb. */
#define RETURN_TO(value) do { \
    uint32_t v_ = (value); \
    ctx->thumb = v_ & 1; \
    ctx->r[15] = v_ & (ctx->thumb ? ~1u : ~3u); \
    return; \
} while (0)

/* a jump that may switch to Thumb. */
#define JUMP_TO(value) do { \
    uint32_t v_ = (value); \
    ctx->thumb = v_ & 1; \
    target = v_ & (ctx->thumb ? ~1u : ~3u); \
    goto dispatch; \
} while (0)

#define BUDGET(address, count) \
    if (UNLIKELY((ctx->budget -= (count)) < 0)) { \
        ctx->budget += (count); \
        ctx->r[15] = (address); \
        ctx->exit = EXIT_BUDGET; \
        return; \
    }

#define SVC(next, number) do { \
    ctx->r[15] = (next); \
    ctx->svc = (number); \
    ctx->exit = EXIT_SVC; \
    return; \
} while (0)

#define INTERPRET(address, opcode) do { \
    ctx->host->interpret(ctx, (address), (opcode)); \
    if (UNLIKELY(ctx->exit)) return; \
} while (0)

#endif
