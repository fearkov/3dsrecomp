/* the interface between recompiled code and the emulator running it. */

#ifndef RECOMP_H
#define RECOMP_H

#include <math.h>
#include <stdint.h>
#include <string.h>

#define RECOMP_ABI 4

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
    uint8_t n, z, c, v, q, thumb, ge;
    /* whether ldrex marked exclusive_address. */
    uint8_t exclusive;
    int32_t budget;
    uint32_t exit;
    uint32_t svc;
    uint32_t depth;
    uint32_t exclusive_address;
    /* the read-only thread id register, which holds the thread's TLS
       address. */
    uint32_t tls;
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

/* a piece of guest code, from start up to end, as addresses or as offsets
   in a module, and a hash of its bytes, 64-bit FNV-1a. a unit's pieces come
   in order and never overlap, they are cut wherever a function's code starts
   or ends, so each function's code is a few runs of whole pieces and every
   byte is hashed once however many functions hold it. */
typedef struct Piece {
    uint32_t start;
    uint32_t end;
    uint64_t hash;
} Piece;

/* a run of a unit's pieces, from first up to end, as indices. */
typedef struct Run {
    uint32_t first;
    uint32_t end;
} Run;

/* a function's code, count runs from the unit's runs[first], and where it
   starts, as an address or an offset in its module. */
typedef struct Origin {
    uint32_t first;
    uint32_t count;
    uint32_t start;
} Origin;

/* the code of the executable or of a module, its functions, the entry each
   of its entries runs, and a flag for each function. a host sets a
   function's flag when the code in memory is no longer what it was made
   from, a mod changed it say, and from then on entering the function hands
   the host its address instead of running it. */
typedef struct Origins {
    uint32_t count;
    uint32_t piece_count;
    const Piece *pieces;
    const Origin *functions;
    const Run *runs;
    /* for each entry, the function that runs it, or NO_ORIGIN for code
       written by hand. */
    const uint32_t *owners;
    uint8_t *stale;
    /* the start each function compares r15 with on the way in, which a host
       sets to NO_START for a stale one, along with its flag. */
    uint32_t *starts;
} Origins;

#define NO_ORIGIN 0xFFFFFFFFu
/* an address no code starts at, odd and past everything. */
#define NO_START 0xFFFFFFFFu

#ifdef _WIN32
#define RECOMP_EXPORT __declspec(dllexport)
#define RECOMP_HIDDEN
#else
#define RECOMP_EXPORT __attribute__((visibility("default")))
/* shared between the generated files and nobody else, which keeps a read
   of it to a single instruction. */
#define RECOMP_HIDDEN __attribute__((visibility("hidden")))
#endif
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
/* the helpers every load, store and VFP register access goes through,
   inlined even where a big generated function makes the compiler give up on
   inlining, a call per access costs as much as the access itself */
#define ALWAYS_INLINE inline __attribute__((always_inline))

/* the page tables loads and stores go through. a generated function keeps
   them in locals, which a store to guest memory, through a byte pointer
   that could point anywhere, does not make the compiler read again. */
#define READ_PAGES(c) ((c)->read_pages)
#define WRITE_PAGES(c) ((c)->write_pages)

static ALWAYS_INLINE uint8_t mem_read8_in(Context *ctx, uint8_t *const *pages, uint32_t address) {
    uint8_t *page = pages[address >> 12];
    if (LIKELY(page)) return page[address & 0xFFF];
    return ctx->host->read8(ctx, address);
}

static ALWAYS_INLINE uint16_t mem_read16_in(Context *ctx, uint8_t *const *pages, uint32_t address) {
    uint8_t *page = pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFE)) {
        uint16_t value;
        memcpy(&value, page + offset, 2);
        return value;
    }
    return ctx->host->read16(ctx, address);
}

static ALWAYS_INLINE uint32_t mem_read32_in(Context *ctx, uint8_t *const *pages, uint32_t address) {
    uint8_t *page = pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFC)) {
        uint32_t value;
        memcpy(&value, page + offset, 4);
        return value;
    }
    return ctx->host->read32(ctx, address);
}

static ALWAYS_INLINE void mem_write8_in(Context *ctx, uint8_t *const *pages, uint32_t address, uint8_t value) {
    uint8_t *page = pages[address >> 12];
    if (LIKELY(page)) page[address & 0xFFF] = value;
    else ctx->host->write8(ctx, address, value);
}

static ALWAYS_INLINE void mem_write16_in(Context *ctx, uint8_t *const *pages, uint32_t address, uint16_t value) {
    uint8_t *page = pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFE)) memcpy(page + offset, &value, 2);
    else ctx->host->write16(ctx, address, value);
}

static ALWAYS_INLINE void mem_write32_in(Context *ctx, uint8_t *const *pages, uint32_t address, uint32_t value) {
    uint8_t *page = pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    if (LIKELY(page && offset <= 0xFFC)) memcpy(page + offset, &value, 4);
    else ctx->host->write32(ctx, address, value);
}

/* where the bytes from address are, when they all lie on one page the code
   reaches directly, or null, for loads and stores of several words. */
static ALWAYS_INLINE uint8_t *mem_span_in(uint8_t *const *pages, uint32_t address, uint32_t bytes) {
    uint8_t *page = pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    /* two tests rather than one with &&, which gcc and clang turn into a
       setcc and a test in big functions */
    if (UNLIKELY(offset > 0x1000 - bytes)) return 0;
    if (UNLIKELY(!page)) return 0;
    return page + offset;
}

#define mem_read8(c, address) mem_read8_in((c), READ_PAGES(c), (address))
#define mem_read16(c, address) mem_read16_in((c), READ_PAGES(c), (address))
#define mem_read32(c, address) mem_read32_in((c), READ_PAGES(c), (address))
#define mem_write8(c, address, value) mem_write8_in((c), WRITE_PAGES(c), (address), (value))
#define mem_write16(c, address, value) mem_write16_in((c), WRITE_PAGES(c), (address), (value))
#define mem_write32(c, address, value) mem_write32_in((c), WRITE_PAGES(c), (address), (value))
#define mem_read_span(c, address, bytes) ((const uint8_t *)mem_span_in(READ_PAGES(c), (address), (bytes)))
#define mem_write_span(c, address, bytes) mem_span_in(WRITE_PAGES(c), (address), (bytes))

static ALWAYS_INLINE uint32_t load32(const uint8_t *at) {
    uint32_t value;
    memcpy(&value, at, 4);
    return value;
}

static ALWAYS_INLINE void store32(uint8_t *at, uint32_t value) {
    memcpy(at, &value, 4);
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

/* saturates to 32 bits, setting q when it has to. */
static inline uint32_t saturate(Context *ctx, int64_t value) {
    if (value > INT32_MAX) { ctx->q = 1; return 0x7FFFFFFFu; }
    if (value < INT32_MIN) { ctx->q = 1; return 0x80000000u; }
    return (uint32_t)(int32_t)value;
}

/* keeps the low 32 bits of a sum, setting q when that loses some. */
static inline uint32_t accumulate(Context *ctx, int64_t value) {
    if (value != (int32_t)value) ctx->q = 1;
    return (uint32_t)value;
}

/* the bottom or top halfword, signed. */
#define HALF(value, top) ((int64_t)(int16_t)((top) ? (value) >> 16 : (value)))

/* saturates value to a signed or unsigned number of bits, noting when it
   had to. */
static inline int64_t saturate_signed(int64_t value, int bits, int *saturated) {
    int64_t max = ((int64_t)1 << (bits - 1)) - 1, min = -((int64_t)1 << (bits - 1));
    if (value > max) { *saturated = 1; return max; }
    if (value < min) { *saturated = 1; return min; }
    return value;
}

static inline int64_t saturate_unsigned(int64_t value, int bits, int *saturated) {
    int64_t max = bits >= 32 ? 0xFFFFFFFFll : ((int64_t)1 << bits) - 1;
    if (value > max) { *saturated = 1; return max; }
    if (value < 0) { *saturated = 1; return 0; }
    return value;
}

/* ssat and usat, setting q when the value did not fit. */
static inline uint32_t media_saturate(Context *ctx, int64_t value, int bits, int is_unsigned) {
    int saturated = 0;
    int64_t result = is_unsigned ? saturate_unsigned(value, bits, &saturated) : saturate_signed(value, bits, &saturated);
    if (saturated) ctx->q = 1;
    return (uint32_t)result;
}

/* ssat16 and usat16. */
static inline uint32_t media_saturate16(Context *ctx, uint32_t value, int bits, int is_unsigned) {
    int saturated = 0;
    uint32_t out = 0;
    for (int i = 0; i < 2; i++) {
        int64_t lane = (int16_t)(value >> (16 * i));
        int64_t result = is_unsigned ? saturate_unsigned(lane, bits, &saturated) : saturate_signed(lane, bits, &saturated);
        out |= ((uint32_t)result & 0xFFFF) << (16 * i);
    }
    if (saturated) ctx->q = 1;
    return out;
}

/* one lane of a parallel add or subtract, 8 or 16 bits wide. */
static inline uint32_t media_lane(uint32_t a, uint32_t b, int width, int sub, int is_signed, int saturating,
                                  int halving, int *ge) {
    uint32_t mask = width == 16 ? 0xFFFFu : 0xFFu;
    int32_t wide;
    if (is_signed) {
        int32_t x = width == 16 ? (int16_t)a : (int8_t)a, y = width == 16 ? (int16_t)b : (int8_t)b;
        wide = sub ? x - y : x + y;
        *ge = wide >= 0;
    } else {
        int32_t x = a & mask, y = b & mask;
        wide = sub ? x - y : x + y;
        /* no borrow for a subtract, a carry out for an add */
        *ge = sub ? wide >= 0 : wide > (int32_t)mask;
    }
    int unused = 0;
    int64_t value = wide;
    if (halving) value = wide >> 1;
    else if (saturating) value = is_signed ? saturate_signed(wide, width, &unused) : saturate_unsigned(wide, width, &unused);
    return (uint32_t)value & mask;
}

/* sadd16, uqsub8, shasx and the rest. op1 picks signed or unsigned and
   plain, saturating or halving, op2 the lanes. only the plain forms set
   ge. */
static inline uint32_t media_parallel(Context *ctx, int op1, int op2, uint32_t a, uint32_t b) {
    int is_signed = !(op1 & 4), saturating = (op1 & 3) == 2, halving = (op1 & 3) == 3;
    uint32_t result = 0;
    int ge = 0, g;
    if (op2 <= 3) {
        /* asx and sax cross the halves of b */
        int cross = op2 == 1 || op2 == 2;
        uint32_t b_lo = cross ? b >> 16 : b & 0xFFFF, b_hi = cross ? b & 0xFFFF : b >> 16;
        result = media_lane(a & 0xFFFF, b_lo, 16, op2 == 1 || op2 == 3, is_signed, saturating, halving, &g);
        if (g) ge |= 3;
        result |= media_lane(a >> 16, b_hi, 16, op2 == 2 || op2 == 3, is_signed, saturating, halving, &g) << 16;
        if (g) ge |= 12;
    } else {
        for (int i = 0; i < 4; i++) {
            result |= media_lane(a >> (8 * i), b >> (8 * i), 8, op2 == 7, is_signed, saturating, halving, &g) << (8 * i);
            if (g) ge |= 1 << i;
        }
    }
    if (!saturating && !halving) ctx->ge = ge;
    return result;
}

/* sel, each byte from a where its ge bit is set and from b where not. */
static inline uint32_t media_select(Context *ctx, uint32_t a, uint32_t b) {
    uint32_t out = 0;
    for (int i = 0; i < 4; i++) out |= ((ctx->ge >> i) & 1 ? a : b) & (0xFFu << (8 * i));
    return out;
}

/* adds the halves of a and b apart, for the accumulating packed extends. */
static inline uint32_t add_halves(uint32_t a, uint32_t b) {
    return ((a + b) & 0xFFFF) | (((a >> 16) + (b >> 16)) << 16);
}

/* usad8, the sum of the absolute differences of the bytes. */
static inline uint32_t media_usad8(uint32_t a, uint32_t b) {
    uint32_t sum = 0;
    for (int i = 0; i < 4; i++) {
        int32_t x = (a >> (8 * i)) & 0xFF, y = (b >> (8 * i)) & 0xFF;
        sum += (uint32_t)(x > y ? x - y : y - x);
    }
    return sum;
}

static inline uint32_t reverse_bits(uint32_t value) {
    value = ((value >> 1) & 0x55555555u) | ((value & 0x55555555u) << 1);
    value = ((value >> 2) & 0x33333333u) | ((value & 0x33333333u) << 2);
    value = ((value >> 4) & 0x0F0F0F0Fu) | ((value & 0x0F0F0F0Fu) << 4);
    return __builtin_bswap32(value);
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

/* fpscr, which a generated function keeps in a local, along with the VFP
   registers it uses. */
#define FPSCR(c) (*(c)->fpscr)

/* the bits of a single, and of a double held in two singles, as numbers. */
static ALWAYS_INLINE float vfp_from_s(uint32_t bits) {
    float value;
    memcpy(&value, &bits, 4);
    return value;
}

static ALWAYS_INLINE double vfp_from_d(uint32_t low, uint32_t high) {
    uint64_t bits = low | (uint64_t)high << 32;
    double value;
    memcpy(&value, &bits, 8);
    return value;
}

/* a result's bits, a subnormal flushed to zero when the guest asked. a
   zero keeps its sign either way, so the exponent alone decides. */
#if defined(__GNUC__) && !defined(__clang__)
/* gcc turns a flush written inline into conditional moves on an integer
   copy of every result, which keeps the results out of the float registers.
   out of line it stays a branch, taken only for a zero or a subnormal. clang
   does better with the plain form. */
static __attribute__((noinline, cold)) uint32_t vfp_flushed_s(uint32_t bits) {
    return bits & 0x80000000u;
}

static __attribute__((noinline, cold)) uint64_t vfp_flushed_d(uint64_t bits) {
    return bits & 0x8000000000000000ull;
}

static ALWAYS_INLINE uint32_t vfp_to_s_in(uint32_t fpscr, float value) {
    uint32_t bits;
    memcpy(&bits, &value, 4);
    if ((fpscr & FPSCR_FZ) && UNLIKELY(!(bits & 0x7F800000u))) bits = vfp_flushed_s(bits);
    return bits;
}

static ALWAYS_INLINE uint64_t vfp_to_d_in(uint32_t fpscr, double value) {
    uint64_t bits;
    memcpy(&bits, &value, 8);
    if ((fpscr & FPSCR_FZ) && UNLIKELY(!(bits & 0x7FF0000000000000ull))) bits = vfp_flushed_d(bits);
    return bits;
}
#else
static ALWAYS_INLINE uint32_t vfp_to_s_in(uint32_t fpscr, float value) {
    uint32_t bits;
    memcpy(&bits, &value, 4);
    if ((fpscr & FPSCR_FZ) && !(bits & 0x7F800000u)) bits &= 0x80000000u;
    return bits;
}

static ALWAYS_INLINE uint64_t vfp_to_d_in(uint32_t fpscr, double value) {
    uint64_t bits;
    memcpy(&bits, &value, 8);
    if ((fpscr & FPSCR_FZ) && !(bits & 0x7FF0000000000000ull)) bits &= 0x8000000000000000ull;
    return bits;
}
#endif

#define vfp_to_s(c, value) vfp_to_s_in(FPSCR(c), (value))
#define vfp_to_d(c, value) vfp_to_d_in(FPSCR(c), (value))

/* a double's result into the two singles that hold it. */
#define VFP_SET_D(low, high, value) do { \
    uint64_t bits_ = vfp_to_d(ctx, (value)); \
    low = (uint32_t)bits_; \
    high = (uint32_t)(bits_ >> 32); \
} while (0)

/* the registers in the context, for code written by hand. */
static ALWAYS_INLINE float vfp_s(Context *ctx, int r) {
    return vfp_from_s(ctx->vfp[r]);
}

static ALWAYS_INLINE double vfp_d(Context *ctx, int d) {
    return vfp_from_d(ctx->vfp[2 * d], ctx->vfp[2 * d + 1]);
}

static ALWAYS_INLINE void vfp_set_s(Context *ctx, int r, float value) {
    ctx->vfp[r] = vfp_to_s_in(*ctx->fpscr, value);
}

static ALWAYS_INLINE void vfp_set_d(Context *ctx, int d, double value) {
    uint64_t bits = vfp_to_d_in(*ctx->fpscr, value);
    ctx->vfp[2 * d] = (uint32_t)bits;
    ctx->vfp[2 * d + 1] = (uint32_t)(bits >> 32);
}

/* fpscr with the comparison result in its top bits, the nzcv encoding. */
static inline uint32_t vfp_compared(uint32_t fpscr, double a, double b) {
    uint32_t flags = (a != a || b != b) ? 0x3 : a == b ? 0x6 : a < b ? 0x8 : 0x2;
    return (fpscr & 0x0FFFFFFFu) | flags << 28;
}

#define vfp_compare(c, a, b) (FPSCR(c) = vfp_compared(FPSCR(c), (a), (b)))

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
        if (wide && op >= 9 && op <= 11) {
            /* the same for doubles, whose bits can be two singles that read
               as a subnormal double and would be flushed */
            uint32_t low = ctx->vfp[2 * (mm & 15)], high = ctx->vfp[2 * (mm & 15) + 1];
            ctx->vfp[2 * (dd & 15)] = low;
            ctx->vfp[2 * (dd & 15) + 1] = op == 9 ? high : op == 10 ? high & 0x7FFFFFFFu : high ^ 0x80000000u;
        } else if (wide) {
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

/* a generated function keeps the registers and flags it uses in locals,
   which the compiler can hold in host registers. SYNC_OUT puts them back in
   the context before anything else can look at it, and SYNC_IN takes them
   again after. each function defines both for what it uses, these are for
   everything else, overrides included. */
#define SYNC_OUT() do { } while (0)
#define SYNC_IN() do { } while (0)

/* leaving the function, with the registers where the caller finds them. */
#define RETURN() do { SYNC_OUT(); return; } while (0)

/* a short vector works on the VFP registers in the context. */
#define VFP_VECTOR(c, ...) do { SYNC_OUT(); vfp_vector((c), __VA_ARGS__); SYNC_IN(); } while (0)

/* a guest call, leaving the caller too when the host has to take over. */
#define CALL(code) do { \
    SYNC_OUT(); \
    if (UNLIKELY(++ctx->depth > RECOMP_DEPTH_LIMIT)) { ctx->depth--; ctx->exit = EXIT_UNWIND; return; } \
    code(ctx); \
    ctx->depth--; \
    if (UNLIKELY(ctx->exit)) return; \
    SYNC_IN(); \
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
    SYNC_OUT(); \
    ctx->thumb = v_ & 1; \
    ctx->r[15] = v_ & (ctx->thumb ? ~1u : ~3u); \
    return; \
} while (0)

/* the same from ARM code, where thumb is 0 already, and from Thumb code,
   where it is 1, so only a switch of state has to write it. */
#define RETURN_TO_A(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    if (UNLIKELY(v_ & 1)) { ctx->thumb = 1; ctx->r[15] = v_ & ~1u; } \
    else ctx->r[15] = v_ & ~3u; \
    return; \
} while (0)

#define RETURN_TO_T(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    if (UNLIKELY(!(v_ & 1))) { ctx->thumb = 0; ctx->r[15] = v_ & ~3u; } \
    else ctx->r[15] = v_ & ~1u; \
    return; \
} while (0)

/* a jump that may switch to Thumb. dispatch can lead anywhere, so the
   context is complete first. */
#define JUMP_TO(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    ctx->thumb = v_ & 1; \
    target = v_ & (ctx->thumb ? ~1u : ~3u); \
    goto dispatch; \
} while (0)

/* what BUDGET counts down, which a generated function keeps in a local
   with the registers. */
#define BUDGET_LEFT ctx->budget

/* charges count instructions to the budget, and when they do not fit,
   leaves for the host to come back at address. code written by hand can use
   it as it is. */
#define BUDGET(address, count) \
    if (UNLIKELY((BUDGET_LEFT -= (count)) < 0)) { \
        BUDGET_LEFT += (count); \
        SYNC_OUT(); \
        ctx->r[15] = (address); \
        ctx->exit = EXIT_BUDGET; \
        return; \
    }

/* the same at the start of each block of generated code, where the blocks
   that stop share ways out at the end of the function, with resume where
   to go on from. each way out stores what its blocks need, and BLOCK goes
   to the one that stores everything. */
#define BLOCK_TO(address, count, way) \
    if (UNLIKELY((BUDGET_LEFT -= (count)) < 0)) { \
        BUDGET_LEFT += (count); \
        resume = (address); \
        goto way; \
    }

#define BLOCK(address, count) BLOCK_TO(address, count, out_of_budget)

#define OUT_OF_BUDGET_AT(way) \
    way: \
    SYNC_OUT(); \
    ctx->r[15] = resume; \
    ctx->exit = EXIT_BUDGET; \
    return

#define OUT_OF_BUDGET() OUT_OF_BUDGET_AT(out_of_budget)

#define SVC(next, number) do { \
    SYNC_OUT(); \
    ctx->r[15] = (next); \
    ctx->svc = (number); \
    ctx->exit = EXIT_SVC; \
    return; \
} while (0)

#define INTERPRET(address, opcode) do { \
    SYNC_OUT(); \
    ctx->host->interpret(ctx, (address), (opcode)); \
    if (UNLIKELY(ctx->exit)) return; \
    SYNC_IN(); \
} while (0)

/* where a generated function goes when r15 is not its start, which a stale
   function's never is: one whose code changed gives the host the address it
   was entered at, which r15 holds, for the host to run some other way. its
   registers only went into locals, nothing has to be put back. */
#define STALE_CHECK(flag) \
    if (UNLIKELY(flag)) { ctx->exit = EXIT_UNWIND; return; }

/* a function written by hand to run instead of the one at address, odd for
   Thumb, or at an offset in a module. see docs/overrides.md. */
#define RECOMP_OVERRIDE(address) void override_##address(Context *ctx)
#define RECOMP_OVERRIDE_IN(module, offset) void override_##module##_##offset(Context *ctx)

/* the generated function an override replaces, to run with CALL. */
#define RECOMP_ORIGINAL(address) original_##address
#define RECOMP_ORIGINAL_IN(module, offset) original_##module##_##offset

#endif
