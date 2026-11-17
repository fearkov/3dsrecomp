/* the contract between recompiled code and the emu running it */

#ifndef RECOMP_H
#define RECOMP_H

#include <math.h>
#include <stdint.h>
#include <string.h>

#define RECOMP_ABI 8

typedef struct Context Context;
/* runs the guest from r15, gives back where it went on return
   (the value written to pc, Thumb in bit 0) or RECOMP_STOPPED when the host takes over, exit says why */
typedef uint32_t (*Code)(Context *);

/* how many self answered svc addrs the code keeps, see Context */
#define RECOMP_TRAIL 64

/* what code returns when it stopped for the host, an addr no code returns to (odd and past everything) */
#define RECOMP_STOPPED 0xFFFFFFFFu

typedef struct Host {
    uint8_t (*read8)(Context *, uint32_t);
    uint16_t (*read16)(Context *, uint32_t);
    uint32_t (*read32)(Context *, uint32_t);
    void (*write8)(Context *, uint32_t, uint8_t);
    void (*write16)(Context *, uint32_t, uint16_t);
    void (*write32)(Context *, uint32_t, uint32_t);
    /* runs one instruction the recompiler punted to the interpreter
       when it branches or fails the host sets exit and r15 */
    void (*interpret)(Context *, uint32_t address, uint32_t opcode);
    /* code for an addr (bit 0 means Thumb) or null */
    Code (*lookup)(Context *, uint32_t address);
    /* runs an svc w/ r15 after it, code goes on from there
       a host w/ more to do first (switching threads say) sets exit to EXIT_UNWIND
       one that runs it in its own loop sets exit to EXIT_SVC and svc to the number */
    void (*svc)(Context *, uint32_t number);
} Host;

/* why the code handed control back */
enum {
    EXIT_NONE,
    /* an svc left for later, number in svc, r15 after it */
    EXIT_SVC,
    /* budget ran out, r15 says where to resume */
    EXIT_BUDGET,
    /* anything else, host carries on from r15 */
    EXIT_UNWIND,
};

struct Context {
    uint32_t r[16];
    uint8_t n, z, c, v, q, thumb, ge;
    /* did ldrex mark exclusive_address */
    uint8_t exclusive;
    int32_t budget;
    uint32_t exit;
    uint32_t svc;
    /* what pre v6 code counted calls in, host zeroes it b4 each call */
    uint32_t depth;
    uint32_t exclusive_address;
    /* the readonly thread id reg, holds the thread's TLS addr */
    uint32_t tls;
    /* host ptr per 4 KiB page, null when the host has to handle the access */
    uint8_t *const *read_pages;
    uint8_t *const *write_pages;
    /* VFP regs s0 to s31 (dN lives in s2N and s2N+1) plus fpscr, the interpreter uses these too */
    uint32_t *vfp;
    uint32_t *fpscr;
    const Host *host;
    void *user;
    /* lowest addr the C stack may reach, funcs check it on the way in and unwind past it */
    uintptr_t stack_limit;
    /* from v7 the code answers GetSystemTick itself (SVC_TICK)
       tick is tick_end minus the budget and costs tick_cost of it
       only at tick_at (addr after the svc, bit 0 for Thumb) while budget > tick_floor, counting in ticks, last one in tick_last
       a host that never sets tick_at gets every one thru svc */
    uint64_t tick_end;
    uint64_t tick_last;
    int32_t tick_floor;
    int32_t tick_cost;
    uint32_t tick_at;
    uint32_t ticks;
    /* from v8 the code also takes and drops the one mutex the host lends it (SVC_WAIT, SVC_RELEASE)
       WaitSynchronizationN on held alone at wait_at takes it once more, ReleaseMutex on held at release_at drops it once
       holding counts how many times the thread has it, all while budget > held_floor (INT32_MAX when nothing's lent)
       each svc the code answers itself (ticks too) logs the addr after it in trail
       latest at (done minus 1) mod RECOMP_TRAIL, done counts them, its tick b4 the cost goes in tick_last */
    uint32_t wait_at;
    uint32_t release_at;
    uint32_t held;
    uint32_t holding;
    int32_t held_floor;
    uint32_t done;
    uint32_t trail[RECOMP_TRAIL];
};

typedef struct Entry {
    uint32_t address;
    Code code;
} Entry;

/* a module's code, entries are offsets from its load addr */
typedef struct Module {
    const char *name;
    /* where the host loaded it, the code reads this */
    uint32_t *base;
    /* end of its code as an offset */
    uint32_t size;
    uint32_t count;
    const Entry *entries;
} Module;

/* a chunk of guest code from start to end (addrs or module offsets) plus its 64 bit FNV1a hash
   a unit's pieces are in order and never overlap, cut wherever a func starts or ends
   so each func is a few runs of whole pieces and every byte gets hashed once, however many funcs share it */
typedef struct Piece {
    uint32_t start;
    uint32_t end;
    uint64_t hash;
} Piece;

/* a run of a unit's pieces, first to end, as indices */
typedef struct Run {
    uint32_t first;
    uint32_t end;
} Run;

/* a func's code, count runs from the unit's runs[first], plus where it starts (addr or module offset) */
typedef struct Origin {
    uint32_t first;
    uint32_t count;
    uint32_t start;
} Origin;

/* code of the exe or a module, its funcs, the entry each entry runs, and a flag per func
   the host sets a func's flag when the code in memory changed (a mod say)
   from then on entering it hands the host its addr instead of running it */
typedef struct Origins {
    uint32_t count;
    uint32_t piece_count;
    const Piece *pieces;
    const Origin *functions;
    const Run *runs;
    /* per entry, the func that runs it, or NO_ORIGIN for handwritten code */
    const uint32_t *owners;
    uint8_t *stale;
    /* the start each func compares r15 with on the way in, a host sets NO_START (and the flag) for a stale one */
    uint32_t *starts;
} Origins;

#define NO_ORIGIN 0xFFFFFFFFu
/* an addr no code starts at, odd and past everything */
#define NO_START 0xFFFFFFFFu

#ifdef _WIN32
#define RECOMP_EXPORT __declspec(dllexport)
#define RECOMP_HIDDEN
#else
#define RECOMP_EXPORT __attribute__((visibility("default")))
/* shared by the generated files and nobody else, so reading it is a single instruction */
#define RECOMP_HIDDEN __attribute__((visibility("hidden")))
#endif
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
/* helpers every load, store and VFP reg access goes thru
   force inlined bc big generated funcs make the compiler give up, and a call per access costs as much as the access */
#define ALWAYS_INLINE inline __attribute__((always_inline))

/* page tables for loads and stores, generated funcs keep them in locals
   a store to guest memory thru a byte ptr that could point anywhere won't make the compiler reload them */
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

/* where the bytes from address are when they all sit on one directly reachable page, or null
   for loads and stores of several words */
static ALWAYS_INLINE uint8_t *mem_span_in(uint8_t *const *pages, uint32_t address, uint32_t bytes) {
    uint8_t *page = pages[address >> 12];
    uint32_t offset = address & 0xFFF;
    /* two tests, not one with &&, gcc and clang turn that into setcc plus test in big funcs */
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

static ALWAYS_INLINE uint16_t load16(const uint8_t *at) {
    uint16_t value;
    memcpy(&value, at, 2);
    return value;
}

static ALWAYS_INLINE void store16(uint8_t *at, uint16_t value) {
    memcpy(at, &value, 2);
}

/* a load or store at reg plus const thru a span one page table look gave for it (and others off the same reg), delta bytes in
   or the usual way when the look found no reachable page
   the code does the look where the reg holds their shared value, in a stretch the host takes no pages from, see docs/interface.md */
#define SPAN_READ8(span, delta, address) (LIKELY(span) ? (span)[delta] : mem_read8(ctx, (address)))
#define SPAN_READ16(span, delta, address) (LIKELY(span) ? load16((span) + (delta)) : mem_read16(ctx, (address)))
#define SPAN_READ32(span, delta, address) (LIKELY(span) ? load32((span) + (delta)) : mem_read32(ctx, (address)))
#define SPAN_WRITE8(span, delta, address, value) do { \
    if (LIKELY(span)) (span)[delta] = (value); else mem_write8(ctx, (address), (value)); } while (0)
#define SPAN_WRITE16(span, delta, address, value) do { \
    if (LIKELY(span)) store16((span) + (delta), (value)); else mem_write16(ctx, (address), (value)); } while (0)
#define SPAN_WRITE32(span, delta, address, value) do { \
    if (LIKELY(span)) store32((span) + (delta), (value)); else mem_write32(ctx, (address), (value)); } while (0)

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

/* saturates to 32 bits, sets q if it had to */
static inline uint32_t saturate(Context *ctx, int64_t value) {
    if (value > INT32_MAX) { ctx->q = 1; return 0x7FFFFFFFu; }
    if (value < INT32_MIN) { ctx->q = 1; return 0x80000000u; }
    return (uint32_t)(int32_t)value;
}

/* keeps the low 32 bits of a sum, sets q if that loses some */
static inline uint32_t accumulate(Context *ctx, int64_t value) {
    if (value != (int32_t)value) ctx->q = 1;
    return (uint32_t)value;
}

/* bottom or top halfword, signed */
#define HALF(value, top) ((int64_t)(int16_t)((top) ? (value) >> 16 : (value)))

/* saturates to a signed or unsigned bit count, notes when it had to */
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

/* ssat and usat, q when it didn't fit */
static inline uint32_t media_saturate(Context *ctx, int64_t value, int bits, int is_unsigned) {
    int saturated = 0;
    int64_t result = is_unsigned ? saturate_unsigned(value, bits, &saturated) : saturate_signed(value, bits, &saturated);
    if (saturated) ctx->q = 1;
    return (uint32_t)result;
}

/* ssat16 and usat16 */
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

/* one lane of a parallel add or sub, 8 or 16 bits wide */
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
        /* no borrow for a sub, carry out for an add */
        *ge = sub ? wide >= 0 : wide > (int32_t)mask;
    }
    int unused = 0;
    int64_t value = wide;
    if (halving) value = wide >> 1;
    else if (saturating) value = is_signed ? saturate_signed(wide, width, &unused) : saturate_unsigned(wide, width, &unused);
    return (uint32_t)value & mask;
}

/* sadd16, uqsub8, shasx and friends
   op1 picks signed or unsigned and plain, saturating or halving, op2 the lanes, only plain forms set ge */
static inline uint32_t media_parallel(Context *ctx, int op1, int op2, uint32_t a, uint32_t b) {
    int is_signed = !(op1 & 4), saturating = (op1 & 3) == 2, halving = (op1 & 3) == 3;
    uint32_t result = 0;
    int ge = 0, g;
    if (op2 <= 3) {
        /* asx and sax cross b's halves */
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

/* sel, each byte from a where its ge bit is set, else from b */
static inline uint32_t media_select(Context *ctx, uint32_t a, uint32_t b) {
    uint32_t out = 0;
    for (int i = 0; i < 4; i++) out |= ((ctx->ge >> i) & 1 ? a : b) & (0xFFu << (8 * i));
    return out;
}

/* adds a's and b's halves separately, for the accumulating packed extends */
static inline uint32_t add_halves(uint32_t a, uint32_t b) {
    return ((a + b) & 0xFFFF) | (((a >> 16) + (b >> 16)) << 16);
}

/* usad8, sum of the absolute byte differences */
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

/* shifts by a reg, amount is its bottom byte */
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
/* short vector length, 0 when an instruction works on one reg */
#define FPSCR_LEN (7u << 16)

/* fpscr, generated funcs keep it in a local along w/ the VFP regs they use */
#define FPSCR(c) (*(c)->fpscr)

/* a single's bits, and a double's in two singles, as numbers */
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

/* a result's bits w/ subnormals flushed to zero when the guest asked
   zero keeps its sign either way so the exponent alone decides */
#if defined(__GNUC__) && !defined(__clang__)
/* gcc turns an inline flush into cmovs on an int copy of every result, keeping results out of float regs
   out of line it stays a branch only taken for zero or subnormal, clang does fine w/ the plain form */
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

/* a double's result into the two singles holding it */
#define VFP_SET_D(low, high, value) do { \
    uint64_t bits_ = vfp_to_d(ctx, (value)); \
    low = (uint32_t)bits_; \
    high = (uint32_t)(bits_ >> 32); \
} while (0)

/* the regs in the context, for handwritten code */
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

/* fpscr w/ the compare result in its top bits, nzcv style */
static inline uint32_t vfp_compared(uint32_t fpscr, double a, double b) {
    uint32_t flags = (a != a || b != b) ? 0x3 : a == b ? 0x6 : a < b ? 0x8 : 0x2;
    return (fpscr & 0x0FFFFFFFu) | flags << 28;
}

#define vfp_compare(c, a, b) (FPSCR(c) = vfp_compared(FPSCR(c), (a), (b)))

/* to int conversions, round toward zero and saturate */
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

/* the math ops, numbered like codegen passes them, from the multiply accumulates to vsqrt (operand b) */
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

/* where reg is on step i of a short vector, wrapping around its bank */
static inline int vfp_step(int reg, int bank, int i, int stride) {
    return (reg & ~(bank - 1)) | ((reg + i * stride) & (bank - 1));
}

/* an op on a short vector shaped by fpscr's len and stride, m stays put in the first bank */
static void vfp_vector(Context *ctx, int op, int wide, int d, int n, int m) {
    uint32_t fpscr = *ctx->fpscr;
    int length = ((fpscr >> 16) & 7) + 1;
    int stride = ((fpscr >> 20) & 3) == 3 ? 2 : 1;
    int bank = wide ? 4 : 8;
    for (int i = 0; i < length; i++) {
        int dd = vfp_step(d, bank, i, stride), nn = vfp_step(n, bank, i, stride);
        int mm = m < bank ? m : vfp_step(m, bank, i, stride);
        if (wide && op >= 9 && op <= 11) {
            /* same for doubles, whose bits can be two singles that read as a subnormal double and would get flushed */
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

/* where the C stack is, generated funcs compare it w/ stack_limit on the way in */
#if defined(__x86_64__)
static ALWAYS_INLINE uintptr_t recomp_stack(void) {
    uintptr_t sp;
    __asm__("movq %%rsp, %0" : "=r"(sp));
    return sp;
}
#elif defined(__aarch64__)
static ALWAYS_INLINE uintptr_t recomp_stack(void) {
    uintptr_t sp;
    __asm__("mov %0, sp" : "=r"(sp));
    return sp;
}
#else
#define recomp_stack() ((uintptr_t)__builtin_frame_address(0))
#endif

/* first thing a generated func does, past the host's stack limit it unwinds
   every way in can, w/ r15 where it entered and the context complete, then the host restarts there w/ all its stack */
#define STACK_CHECK() \
    if (UNLIKELY(recomp_stack() < ctx->stack_limit)) { ctx->exit = EXIT_UNWIND; return RECOMP_STOPPED; }

/* generated funcs keep the regs and flags they use in locals so they can live in host regs
   SYNC_OUT puts them back in the context b4 anyone else looks, SYNC_IN takes them again after
   each func defines both for what it uses, these are for everything else (overrides too) */
#define SYNC_OUT() do { } while (0)
#define SYNC_IN() do { } while (0)

/* leaving the func w/ the regs where the caller finds them, and where to go as the caller checks it */
#define RETURN() do { SYNC_OUT(); return ctx->r[15] | ctx->thumb; } while (0)

/* short vectors work on the VFP regs in the context */
#define VFP_VECTOR(c, ...) do { SYNC_OUT(); vfp_vector((c), __VA_ARGS__); SYNC_IN(); } while (0)

/* a guest call from handwritten code, also leaves the caller when the host takes over, and goes on wherever the callee returned to */
#define CALL(code) do { \
    SYNC_OUT(); \
    if (UNLIKELY((code)(ctx) == RECOMP_STOPPED)) return RECOMP_STOPPED; \
    SYNC_IN(); \
} while (0)

/* a guest call in generated code, goes on after it when the callee comes back to link (lr's return addr, Thumb in bit 0)
   anything else, host takeover included, goes to the func's one RETURNED_ELSEWHERE, so a call is just the compare */
#define CALL_RETURNING(code, link) do { \
    SYNC_OUT(); \
    if (UNLIKELY((code)(ctx) != (link))) goto returned_elsewhere; \
    SYNC_IN(); \
} while (0)

/* where a call that came back anywhere but its link lands
   up to the host if it stopped, else on from wherever the guest is via dispatch, locals reloaded */
#define RETURNED_ELSEWHERE() \
    returned_elsewhere: \
    if (ctx->exit) return RECOMP_STOPPED; \
    SYNC_IN(); \
    target = ctx->r[15]; \
    goto dispatch

/* a jump into other code, returns where that code does */
#define TAIL_CALL(code) do { SYNC_OUT(); return (code)(ctx); } while (0)

/* runs whatever code the host has for r15 */
static inline uint32_t recomp_call(Context *ctx) {
    Code code = ctx->host->lookup(ctx, ctx->r[15] | ctx->thumb);
    if (LIKELY(code)) return code(ctx);
    ctx->exit = EXIT_UNWIND;
    return RECOMP_STOPPED;
}

/* a return that may switch to Thumb, gives back the value written to pc, which says where and in what state */
#define RETURN_TO(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    ctx->thumb = v_ & 1; \
    ctx->r[15] = v_ & (ctx->thumb ? ~1u : ~3u); \
    return v_; \
} while (0)

/* same for ARM code (thumb is 0 already) and Thumb code (it's 1), so only a state switch writes it */
#define RETURN_TO_A(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    if (UNLIKELY(v_ & 1)) { ctx->thumb = 1; ctx->r[15] = v_ & ~1u; } \
    else ctx->r[15] = v_ & ~3u; \
    return v_; \
} while (0)

#define RETURN_TO_T(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    if (UNLIKELY(!(v_ & 1))) { ctx->thumb = 0; ctx->r[15] = v_ & ~3u; } \
    else ctx->r[15] = v_ & ~1u; \
    return v_; \
} while (0)

/* a jump that may switch to Thumb, dispatch can go anywhere so the context gets completed first */
#define JUMP_TO(value) do { \
    uint32_t v_ = (value); \
    SYNC_OUT(); \
    ctx->thumb = v_ & 1; \
    target = v_ & (ctx->thumb ? ~1u : ~3u); \
    goto dispatch; \
} while (0)

/* what BUDGET counts down, generated funcs keep it in a local w/ the regs */
#define BUDGET_LEFT ctx->budget

/* charges count instrs to the budget, if they don't fit it leaves for the host to come back at address
   handwritten code can use it as is */
#define BUDGET(address, count) \
    if (UNLIKELY((BUDGET_LEFT -= (count)) < 0)) { \
        BUDGET_LEFT += (count); \
        SYNC_OUT(); \
        ctx->r[15] = (address); \
        ctx->exit = EXIT_BUDGET; \
        return RECOMP_STOPPED; \
    }

/* same at the start of each generated block, blocks that stop share exits at the end of the func, resume says where to continue
   each exit stores what its blocks need, BLOCK goes to the one that stores everything */
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
    return RECOMP_STOPPED

#define OUT_OF_BUDGET() OUT_OF_BUDGET_AT(out_of_budget)

/* an svc the host runs right there, like the interpreter runs an instruction */
#define SVC(next, number) do { \
    SYNC_OUT(); \
    ctx->r[15] = (next); \
    ctx->host->svc(ctx, (number)); \
    if (UNLIKELY(ctx->exit)) return RECOMP_STOPPED; \
    SYNC_IN(); \
} while (0)

/* an svc the code answered itself at at (addr after it, bit 0 for Thumb) at the budget's tick, see Context */
#define ANSWERED(at) do { \
    ctx->tick_last = ctx->tick_end - (uint64_t)(int64_t)ctx->budget; \
    ctx->trail[ctx->done++ & (RECOMP_TRAIL - 1)] = (at); \
} while (0)

/* svc 0x28 GetSystemTick, answered by the code itself where the host allows, thumb 1 for Thumb, see Context
   anywhere else it's a normal svc */
#define SVC_TICK(next, thumb) do { \
    SYNC_OUT(); \
    ctx->r[15] = (next); \
    if (LIKELY(ctx->tick_at == ((next) | (thumb))) && LIKELY(ctx->budget > ctx->tick_floor)) { \
        uint64_t tick_ = ctx->tick_end - (uint64_t)(int64_t)ctx->budget; \
        ANSWERED((next) | (thumb)); \
        ctx->budget -= ctx->tick_cost; \
        ctx->ticks += 1; \
        ctx->r[0] = (uint32_t)tick_; \
        ctx->r[1] = (uint32_t)(tick_ >> 32); \
    } else { \
        ctx->host->svc(ctx, 0x28u); \
        if (UNLIKELY(ctx->exit)) return RECOMP_STOPPED; \
    } \
    SYNC_IN(); \
} while (0)

/* is the word at address (on a directly reachable page) the handle of the mutex the host lent us */
static ALWAYS_INLINE int recomp_held_at(Context *ctx, uint32_t address) {
    const uint8_t *at = mem_read_span(ctx, address, 4);
    return at && load32(at) == ctx->held;
}

/* svc 0x25 WaitSynchronizationN, answered by the code where the host allows when it waits on the lent mutex alone, takes it once more, see Context
   anything else is a normal svc */
#define SVC_WAIT(next, thumb) do { \
    SYNC_OUT(); \
    ctx->r[15] = (next); \
    if (LIKELY(ctx->wait_at == ((next) | (thumb))) && LIKELY(ctx->budget > ctx->held_floor) \
        && LIKELY(ctx->r[2] == 1) && LIKELY(recomp_held_at(ctx, ctx->r[1]))) { \
        ANSWERED((next) | (thumb)); \
        ctx->holding += 1; \
        ctx->r[0] = 0; \
        ctx->r[1] = 0; \
    } else { \
        ctx->host->svc(ctx, 0x25u); \
        if (UNLIKELY(ctx->exit)) return RECOMP_STOPPED; \
    } \
    SYNC_IN(); \
} while (0)

/* svc 0x14 ReleaseMutex, answered by the code where the host allows for the lent mutex while it holds it, see Context
   anything else is a normal svc */
#define SVC_RELEASE(next, thumb) do { \
    SYNC_OUT(); \
    ctx->r[15] = (next); \
    if (LIKELY(ctx->release_at == ((next) | (thumb))) && LIKELY(ctx->budget > ctx->held_floor) \
        && LIKELY(ctx->r[0] == ctx->held) && LIKELY(ctx->holding != 0)) { \
        ANSWERED((next) | (thumb)); \
        ctx->holding -= 1; \
        ctx->r[0] = 0; \
    } else { \
        ctx->host->svc(ctx, 0x14u); \
        if (UNLIKELY(ctx->exit)) return RECOMP_STOPPED; \
    } \
    SYNC_IN(); \
} while (0)

#define INTERPRET(address, opcode) do { \
    SYNC_OUT(); \
    ctx->host->interpret(ctx, (address), (opcode)); \
    if (UNLIKELY(ctx->exit)) return RECOMP_STOPPED; \
    SYNC_IN(); \
} while (0)

/* where a generated func goes when r15 isn't its start (a stale func's never is)
   one whose code changed hands the host its entry addr (in r15) to run some other way
   its regs only went into locals, nothing to put back */
#define STALE_CHECK(flag) \
    if (UNLIKELY(flag)) { ctx->exit = EXIT_UNWIND; return RECOMP_STOPPED; }

/* the C lib's int divisions, natives.c runs them on the host instead of the title's copies (src/natives.rs)
   each checks it can first, div by zero or the one overflowing quotient go to the lib's own code
   and so does a division the remaining budget can't fully pay, that code charges a block at a time
   then it charges what the lib would, leaves quotient and remainder where it does, and what it pushes below sp
   (a func reading a local it never set would see it lol)
   scratch regs r12, lr and the flags, which no caller reads after a call, stay untouched
   set recomp_natives to 0 to always run the lib's code */
extern uint8_t recomp_natives;

static ALWAYS_INLINE int native_uidivmod_fits(const Context *ctx) {
    return ctx->r[1] != 0;
}

static ALWAYS_INLINE void native_uidivmod(Context *ctx, uint32_t address) {
    (void)address;
    uint32_t n = ctx->r[0], d = ctx->r[1];
    ctx->r[0] = n / d;
    ctx->r[1] = n % d;
}

static ALWAYS_INLINE int native_idivmod_fits(const Context *ctx) {
    return ctx->r[1] != 0 && !(ctx->r[0] == 0x80000000u && ctx->r[1] == 0xFFFFFFFFu);
}

static ALWAYS_INLINE void native_idivmod(Context *ctx, uint32_t address) {
    (void)address;
    int32_t n = (int32_t)ctx->r[0], d = (int32_t)ctx->r[1];
    ctx->r[0] = (uint32_t)(n / d);
    ctx->r[1] = (uint32_t)(n % d);
}

/* a reg pair as 64 bits, low first, read as two words
   compilers make one load otherwise, which waits for the caller's two stores to reach the cache
   with two loads each one just grabs what one store holds */
static ALWAYS_INLINE uint64_t native_pair(const Context *ctx, int low) {
    uint32_t lo = ctx->r[low], hi = ctx->r[low + 1];
#if defined(__GNUC__)
    __asm__("" : "+r"(lo), "+r"(hi));
#endif
    return lo | (uint64_t)hi << 32;
}

static ALWAYS_INLINE void native_set_pair(Context *ctx, int low, uint64_t value) {
    ctx->r[low] = (uint32_t)value;
    ctx->r[low + 1] = (uint32_t)(value >> 32);
}

static ALWAYS_INLINE int native_uldivmod_fits(const Context *ctx) {
    return native_pair(ctx, 2) != 0;
}

/* what _ll_udiv pushes on the way in, push {r4, r5, r6, lr} w/ r4 as given, one page look for all four */
static ALWAYS_INLINE void native_push_ll_udiv(Context *ctx, uint32_t sp, uint32_t r4, uint32_t lr) {
    uint8_t *span = mem_write_span(ctx, sp - 16, 16);
    SPAN_WRITE32(span, 0, sp - 16, r4);
    SPAN_WRITE32(span, 4, sp - 12, ctx->r[5]);
    SPAN_WRITE32(span, 8, sp - 8, ctx->r[6]);
    SPAN_WRITE32(span, 12, sp - 4, lr);
}

static ALWAYS_INLINE void native_uldivmod(Context *ctx, uint32_t address) {
    (void)address;
    native_push_ll_udiv(ctx, ctx->r[13], ctx->r[4], ctx->r[14]);
    uint64_t n = native_pair(ctx, 0), d = native_pair(ctx, 2);
    native_set_pair(ctx, 0, n / d);
    native_set_pair(ctx, 2, n % d);
}

static ALWAYS_INLINE int native_ldivmod_fits(const Context *ctx) {
    return native_pair(ctx, 2) != 0 && !(native_pair(ctx, 0) == 0x8000000000000000ull && native_pair(ctx, 2) == ~0ull);
}

/* _ll_sdiv pushes {r4, lr} and calls _ll_udiv w/ the signs in r4, the call sits at 0x28 */
static ALWAYS_INLINE void native_ldivmod(Context *ctx, uint32_t address) {
    uint32_t sp = ctx->r[13];
    uint32_t signs = (uint32_t)((int32_t)ctx->r[1] >> 1) ^ (ctx->r[3] >> 1);
    mem_write32(ctx, sp - 8, ctx->r[4]);
    mem_write32(ctx, sp - 4, ctx->r[14]);
    native_push_ll_udiv(ctx, sp - 8, signs, address + 0x2C);
    int64_t n = (int64_t)native_pair(ctx, 0), d = (int64_t)native_pair(ctx, 2);
    native_set_pair(ctx, 0, (uint64_t)(n / d));
    native_set_pair(ctx, 2, (uint64_t)(n % d));
}

/* quotient bits, the lib's loops take a few at a time */
static ALWAYS_INLINE int native_bits(uint64_t n, uint64_t d) {
    uint64_t q = n / d;
    return q ? 64 - __builtin_clzll(q) : 0;
}

/* what the lib's recompiled code charges for a division, exactly
   32 bit ones by quotient bits, 64 bit ones by how much longer n is than d (below)
   the signed 64 bit one charges 20 more whatever the signs */
static const uint8_t native_uidivmod_costs[33] = {19, 19, 19, 28, 28, 28, 37, 37, 37, 50, 50, 50, 50, 62, 62, 62, 62,
                                                  85, 85, 85, 85, 98, 98, 98, 98, 111, 111, 111, 111, 124, 124, 124, 124};
static const uint8_t native_idivmod_costs[33] = {29, 26, 35, 35, 35, 47, 47, 47, 47, 60, 60, 60, 60, 72, 72, 72, 72,
                                                 86, 86, 86, 86, 99, 99, 99, 99, 112, 112, 112, 112, 125, 125, 125, 125};
/* same w/ a sign set, either one */
static const uint8_t native_idivmod_signed_costs[33] = {62, 62, 62, 62, 62, 74, 74, 74, 74, 104, 104, 104, 104, 104, 104, 134, 134,
                                                        134, 134, 134, 134, 165, 165, 165, 165, 165, 165, 195, 195, 195, 195, 195, 195};

static ALWAYS_INLINE int32_t native_uidivmod_cost(const Context *ctx) {
    return native_uidivmod_costs[native_bits(ctx->r[0], ctx->r[1])];
}

static ALWAYS_INLINE int32_t native_idivmod_cost(const Context *ctx) {
    int32_t n = (int32_t)ctx->r[0], d = (int32_t)ctx->r[1];
    if (n >= 0 && d >= 0) return native_idivmod_costs[native_bits((uint32_t)n, (uint32_t)d)];
    uint32_t un = n < 0 ? 0u - (uint32_t)n : (uint32_t)n, ud = d < 0 ? 0u - (uint32_t)d : (uint32_t)d;
    return native_idivmod_signed_costs[native_bits(un, ud)];
}

/* the 64 bit division gives 0 when n is shorter than d, goes bit by bit when n is up to 4 bits longer
   and uses a reciprocal after that, w/ one extra step for d over 32 bits */
static ALWAYS_INLINE int32_t native_uldivmod_cost_of(uint64_t n, uint64_t d) {
    int longer = __builtin_clzll(d) - (n ? __builtin_clzll(n) : 64);
    if (longer < 0) return 62;
    if (longer <= 4) return 75 + 10 * longer;
    return d >> 32 ? 109 : 98;
}

static ALWAYS_INLINE int32_t native_uldivmod_cost(const Context *ctx) {
    return native_uldivmod_cost_of(native_pair(ctx, 0), native_pair(ctx, 2));
}

static ALWAYS_INLINE int32_t native_ldivmod_cost(const Context *ctx) {
    int64_t n = (int64_t)native_pair(ctx, 0), d = (int64_t)native_pair(ctx, 2);
    uint64_t un = n < 0 ? 0ull - (uint64_t)n : (uint64_t)n, ud = d < 0 ? 0ull - (uint64_t)d : (uint64_t)d;
    return 20 + native_uldivmod_cost_of(un, ud);
}

/* an override running a native, falls back on the original and returns its result */
#define RECOMP_NATIVE(address, name, original) do { \
    if (LIKELY(recomp_natives) && native_##name##_fits(ctx)) { \
        int32_t cost_ = native_##name##_cost(ctx); \
        if (LIKELY(BUDGET_LEFT >= cost_)) { \
            BUDGET_LEFT -= cost_; \
            native_##name(ctx, (address)); \
            RETURN_TO(ctx->r[14]); \
        } \
    } \
    return (original)(ctx); \
} while (0)

/* a handwritten func that runs instead of the one at address (odd for Thumb) or at a module offset, see docs/overrides.md */
#define RECOMP_OVERRIDE(address) uint32_t override_##address(Context *ctx)
#define RECOMP_OVERRIDE_IN(module, offset) uint32_t override_##module##_##offset(Context *ctx)

/* the generated func an override replaces, run it w/ CALL or TAIL_CALL */
#define RECOMP_ORIGINAL(address) original_##address
#define RECOMP_ORIGINAL_IN(module, offset) original_##module##_##offset

#endif
