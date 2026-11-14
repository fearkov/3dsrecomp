# The interface

`3dsrecomp build` turns a title into a shared library. Nothing in the library
depends on a particular emulator. It runs against a small interface, declared
in [`recomp.h`](../abi/recomp.h). Any program that implements that
interface can run the code. This document calls that program the host.

This page describes version 8 of the interface. Version 7 had no fields
after `ticks`: its code asked the host for every WaitSynchronizationN and
ReleaseMutex, where version 8 code can take and let go of a mutex the host
lends it, see [A mutex lent](#a-mutex-lent), and its ticks left no
`trail`. Version 6 had no `tick_` fields: its code asked the host for every
GetSystemTick, where version 7 code can read the clock itself, see
[Ticks](#ticks). Version 5 differed in
how the code makes calls: its functions returned nothing and counted how
deep they were in `depth`, where version 6 gives back where the guest went
and checks the C stack against `stack_limit`. Version 4 also had no `svc`
callback: its code left every `svc` to the host's loop with `EXIT_SVC`. Code
made for 4, 5, 6 and 7 still runs on a host written for 8, which
`recomp_abi` accepts, as long as the host also sets `depth` to 0. Code made
before 7 never reads the `tick_` fields, and code made before 8 never reads
or writes the fields after `ticks`.

## What build writes

`3dsrecomp build <rom> <dir>` writes these files to `<dir>`:

- `recomp.h`, a copy of the interface;
- `entries.c`, which holds the tables described below;
- one header per program, with the prototypes of its functions;
- `code000.c`, `code001.c` and so on, which hold the functions;
- `<program id>.so`, all of the above compiled. The name is 16 uppercase hex
  digits, for example `000400000011C500.so`. On Windows it is a `.dll`, and
  on macOS a `.dylib`.

The compiler comes from `CC`. When `CC` is not set, the first of `cc`, `gcc`
and `clang` that runs is used. On Windows, `gcc` from MinGW-w64 is tried
first, then `clang`. To compile the sources yourself, keep
`-ffp-contract=off`. Without it, the compiler can fuse a multiply and an
add, which rounds differently from the guest.

Without a directory, `3dsrecomp build <rom>` works in the cache
(`~/.cache/3dsrecomp/<title id>`) and then installs the library at
`~/.local/share/3dsrecomp/<title id>.so`, or the system's equivalent,
`%APPDATA%\3dsrecomp\<title id>.dll` on Windows. A
host that looks there finds the code for a title without being told where
it is. In Rust, `recomp_abi::installed(title_id)` does the looking, and
Zakuro does it on its own.

## Exported symbols

| Symbol | Type | Meaning |
| --- | --- | --- |
| `recomp_abi` | `const uint32_t` | The interface version, `RECOMP_ABI` |
| `recomp_generation` | `const uint32_t` | The code generator's version, missing before it was added |
| `recomp_entry_count` | `const uint32_t` | Number of entries in the executable |
| `recomp_entries` | `const Entry[]` | The executable's entries |
| `recomp_module_count` | `const uint32_t` | Number of modules |
| `recomp_modules` | `const Module[]` | One per CRO module |
| `recomp_origins` | `const Origins[]` | What the code was made from, the executable's and then one per module, read from generation 3 on |
| `recomp_natives` | `uint8_t` | 1 while the C library functions the code runs on the host do, see [natives](overrides.md#natives). Set it to 0 to have the title's own code run for them. Missing when there are none |

Check `recomp_abi` first, and refuse to run the library when it is not a
version you were written for. The version goes up whenever the layout of any
structure or the meaning of any field changes. A host written for version 8
can also run code made for 7, which asks for every wait and release and
leaves no trail, for 6, 5 and 4, which ask for every tick too, and for 5
and 4 give nothing back and count calls in `depth`, and for 4 never call
`svc`.

`recomp_generation` goes up when the generated code gets much faster or does
more. Generation 3 added `recomp_origins`, generation 4, made for version 5
of the interface, runs svcs in place, and generation 5 divides on the host.
A library of an older generation, or one without the symbol, still runs.
Building it again brings the improvements, which a host can suggest. In Rust,
`Library::generation` reads it, 0 when it is missing, and
`recomp_abi::GENERATION` is the current one.

### Entries

```c
typedef struct Entry {
    uint32_t address;
    Code code;          /* uint32_t (*)(Context *) */
} Entry;
```

An entry is a place the host can start running code from. `address` has bit 0
set for Thumb. The table is sorted by `address`, so a binary search finds an
entry.

There is an entry for every place execution can come back to, not only for
function starts:

- the start of every basic block;
- the instruction after every call;
- the instruction after every `svc`.

This matters because the host sometimes returns to an address whose C frame is
already gone, after an unwind or an svc it stopped the code for (see below).
Several entries can share
one `code`, because a function dispatches internally to the right place from
`r[15]`.

### Modules

```c
typedef struct Module {
    const char *name;
    uint32_t *base;
    uint32_t size;
    uint32_t count;
    const Entry *entries;
} Module;
```

A title loads CRO modules at runtime, and the address of a module is only known
once it is loaded. For that reason, a module's entries are offsets from the
start of the CRO file.

- `name` is the module name from the CRO header.
- `size` is where the module's code ends, as an offset. An address belongs to
  the module when `address - load_address < size`.
- `base` points to a variable inside the library. When the title loads the
  module, write its load address there. When the title unloads it, write
  zero. Set it before any of the module's code runs. Each function reads it
  once, on entry.

To look up an address in a module, subtract the load address and search the
module's `entries` for the offset, keeping bit 0 for Thumb.

### Origins

```c
typedef struct Piece {
    uint32_t start, end;
    uint64_t hash;
} Piece;

typedef struct Run {
    uint32_t first, end;
} Run;

typedef struct Origin {
    uint32_t first;
    uint32_t count;
    uint32_t start;
} Origin;

typedef struct Origins {
    uint32_t count;
    uint32_t piece_count;
    const Piece *pieces;
    const Origin *functions;
    const Run *runs;
    const uint32_t *owners;
    uint8_t *stale;
    uint32_t *starts;
} Origins;
```

The code in memory can differ from the code a library was made from: a mod
can patch the executable or replace a module, or the title can be another
version than the one recompiled. `recomp_origins` lets a host find the
functions that no longer match and keep them from running.

There is one `Origins` for the executable, then one for each module, in the
order of `recomp_modules`.

- `pieces` cut the unit's code, the instructions its functions were made from,
  into `piece_count` pieces, in order and without overlaps. A piece is cut
  wherever any function's code starts or ends, so each function's code is
  made of whole pieces, and a byte several functions hold is in one piece.
  `start` and `end` are addresses, or offsets in a module like the entries,
  and `hash` is the 64-bit FNV-1a hash of the piece's bytes.
- `functions[i]` is function `i`'s code, `count` runs from `runs[first]`, and
  `start`, where it starts. A run covers the pieces from index `first` up to
  `end`.
- `stale[i]` is function `i`'s flag. It starts at zero.
- `starts[i]` is the start function `i` compares `r[15]` with on the way in.
  It starts as `functions[i].start`.
- `owners` has one value for each of the unit's entries, in the same order:
  the function that runs the entry, or `NO_ORIGIN` for an override.

To check a unit, hash each piece's bytes now in memory, adding the load
address for a module. For every function with a run that holds a piece whose
hash differs, set `stale[i]` to 1 and `starts[i]` to `NO_START`, and for the
others set them back to 0 and `functions[i].start`. Do it once the executable's code is in
memory, and for a module each time it is loaded, after its relocations are
applied. Those only change data, never the pieces. From then on:

- every generated function compares `r[15]` with `starts[i]` on the way in, a
  compare it makes anyway to go straight to its start, and checks its flag
  only when they differ. A stale one leaves with `EXIT_UNWIND` without doing
  anything, `r[15]` still holding the address it was entered at. Calls between
  functions are C calls, which is why the check has to be in the function and
  not in the host's lookups alone;
- the host's own lookups have to skip entries whose owner is stale, or it would
  enter the function again right away. It runs that code some other way
  instead, with an interpreter.

In Rust, `Library::check` does the hashing and sets the flags, and
`Library::lookup` skips the stale entries. Generation 2 had another layout for
these tables, which no host reads.

## The context

The code works on one `Context`, which the host fills in before calling the
code and reads back afterwards. The code keeps no state of its own besides the
module bases, so switching guest threads only means switching what is in the
context. The context does not need to live between two runs.

| Field | Meaning |
| --- | --- |
| `r[16]` | The general registers. `r[15]` is the address of the next instruction to run, not that address plus 8. |
| `n`, `z`, `c`, `v`, `q` | The flags, each one byte holding 0 or 1. |
| `thumb` | 1 in Thumb state, 0 in ARM state. |
| `ge` | The four GE bits, in the low nibble. |
| `exclusive`, `exclusive_address` | The exclusive monitor. `ldrex` sets both, and a successful `strex` or a `clrex` clears `exclusive`. |
| `budget` | How many instructions may still run. See [Budget](#budget). |
| `exit` | Why the code returned. The host sets it to `EXIT_NONE` before each call. |
| `svc` | The svc number, when `exit` is `EXIT_SVC`. |
| `depth` | Where code made before version 6 counted how many guest calls deep the C stack is. A host that runs such code sets it to 0 before each call. |
| `tls` | The read-only thread ID register, which `mrc p15, 0, rX, c13, c0, 3` reads. On the 3DS it holds the thread's TLS address. |
| `read_pages`, `write_pages` | The page tables. See [Memory](#memory). |
| `vfp` | 32 words, `s0` to `s31`. `dN` is `s2N` (low word) followed by `s2N+1`. |
| `fpscr` | A pointer to FPSCR. |
| `host` | The host's callbacks. |
| `user` | Belongs to the host. The code never touches it. |
| `stack_limit` | The lowest address the code's C stack may reach. The host sets it before each call, see [Calls](#calls). |
| `tick_end`, `tick_floor`, `tick_cost`, `tick_at` | Where and how the code may answer GetSystemTick itself, see [Ticks](#ticks). A host that never sets `tick_at` gets every one through `svc`. |
| `ticks`, `tick_last` | How many ticks the code answered, and the tick of the last svc it answered itself. |
| `wait_at`, `release_at`, `held`, `holding`, `held_floor` | Where and how the code may take and let go of a mutex itself, see [A mutex lent](#a-mutex-lent). `held_floor` at `INT32_MAX`, `NOTHING_HELD` in Rust, has every wait and release go through `svc`. |
| `done`, `trail` | How many svcs the code answered itself, ticks too, and the addresses after the last `RECOMP_TRAIL` of them. |

`vfp` and `fpscr` are pointers so that the code and an interpreter can work on
the same registers without copying them back and forth.

The code keeps the registers, the flags, the VFP registers, `fpscr` and the
budget in locals while it runs, and puts them back in the context wherever
something else can look at them: when it returns, and before it calls
`lookup`, `interpret`, `svc` or another function. After `interpret` and `svc`
it takes them all back, so whatever the host changed there is what the code
goes on with. Inside the memory callbacks they are not current, only the
arguments, `host`, `user` and the page tables are. `r[15]` is set when the
code returns and before it calls `lookup` or `svc`. The `interpret` callback
receives the address it needs as an argument.

## Memory

`read_pages` and `write_pages` each hold 2^20 pointers, one for every 4 KiB
page of the 32-bit address space.

- A non-null entry points to the page's bytes, in guest (little-endian)
  order. The code reads or writes that page directly.
- A null entry sends every access to that page through the host's
  `read8`/`read16`/`read32` or `write8`/`write16`/`write32` callbacks.

An access that crosses a page boundary also goes to the host.

The two tables are separate so that one page can have a direct read path and
still send its writes to the host. Leave a page's entry null in any table
where the host has to see the access:

- I/O;
- memory the host watches for changes, such as textures or command lists;
- memory that is not mapped.

The code looks a page up once for several loads or stores at the same
register plus a constant. It keeps what it found until the register
changes, the code reaches a label, or it calls the host for anything but
memory. Inside the memory callbacks the host may fill entries in, such as a
page it watched that has just been written, but it must not empty an entry
or point it elsewhere. That waits until `interpret`, `lookup` or `svc`, or
until the code returns.

## Host callbacks

```c
typedef struct Host {
    uint8_t (*read8)(Context *, uint32_t);
    uint16_t (*read16)(Context *, uint32_t);
    uint32_t (*read32)(Context *, uint32_t);
    void (*write8)(Context *, uint32_t, uint8_t);
    void (*write16)(Context *, uint32_t, uint16_t);
    void (*write32)(Context *, uint32_t, uint32_t);
    void (*interpret)(Context *, uint32_t address, uint32_t opcode);
    Code (*lookup)(Context *, uint32_t address);
    void (*svc)(Context *, uint32_t number);
} Host;
```

- **Memory callbacks.** These handle every access the page tables do not.
  The address may be unaligned.
- **`interpret`.** It runs one instruction that the recompiler left alone,
  such as an unusual coprocessor access. `address` is the instruction's
  address. `opcode` is the instruction as the recompiler saw it. The host:
  1. copies the context into its interpreter, with the program counter at
     `address`;
  2. runs the instruction;
  3. copies the state back.

  If execution simply goes on to the next instruction, leave `exit` alone.
  Otherwise set `r[15]` (and `thumb`) to where execution goes and set `exit`
  to `EXIT_UNWIND`. That covers a branch, an exception, or anything the host
  wants to handle outside the code. The code then returns to the host.
  Instructions run this way are already counted in the budget.
- **`lookup`.** It returns the code for an address, with bit 0 set for Thumb,
  or null when there is no code for it. The code calls it when it jumps
  somewhere it does not know about:
  - an indirect branch out of the function;
  - a return into a function whose frame is gone;
  - a call across modules.

  It is usually the same search the host's own run loop does. When it returns
  null, the code sets `exit` to `EXIT_UNWIND`, with `r[15]` holding the
  target.
- **`svc`.** The guest ran an `svc`. `number` is its number, and `r[15]`
  already points at the instruction after it. The host can do one of three
  things:
  - run it right there, writing its results into the context, and leave
    `exit` alone. The code then goes on after the `svc`, with the C stack and
    every guest call it is in intact. Set `budget` to what the code may run
    from there. Leave `r[15]` and `thumb` as they are: the code goes on
    after the `svc` whatever they say, and to send it anywhere else, set
    `exit` to `EXIT_UNWIND`.
  - run it, then set `exit` to `EXIT_UNWIND` when it has more to do before
    the guest goes on, such as switching to another thread or ending a frame.
    The code returns, and the host picks up from `r[15]` later.
  - leave it for its own loop: set `svc` to `number` and `exit` to
    `EXIT_SVC`. That is what code made for version 4 always did.

  Running it in place saves the code from returning all the way out and
  being entered again, which titles that read the clock or take a lock
  thousands of times a frame pay for each time.

## Ticks

Titles read the clock with `svc 0x28`, GetSystemTick, more than they make any
other svc. From version 7 the code can answer it without calling the host,
as long as the clock goes up with the budget, the way it does in a host
that counts the budget in cycles. The code answers one when both hold:

- `tick_at` is the address after the `svc`, with bit 0 set for Thumb. The
  host names one place at a time, 0 naming none;
- `budget` is greater than `tick_floor`, before the tick is paid for.

Then the tick is `tick_end - budget`, as 64 bits, in `r0` (low) and `r1`
(high). The code takes `tick_cost` from `budget`, adds one to `ticks` and
leaves the tick in `tick_last`. It sets `r[15]` past the `svc` and goes on
without calling anything. The host finds out from `ticks` when the code
next calls `svc` or `interpret`, or returns, and sets it back to 0 then.
Anywhere else, or with the budget at the floor, the code calls `svc` with
`0x28` as for any svc.

A host that runs GetSystemTick in place can work the fields out from what
it would do there:

- `tick_end` is the cycle count at which the budget runs out, so that
  `tick_end - budget` is the cycle count now;
- `tick_floor` keeps the code off ticks after which the host would do
  more than read the clock, an event coming due, say. If the host's next
  such point is at cycle `due`, a tick at cycle `t` stays clear of it when
  `t + tick_cost < due`, which is `budget > tick_end + tick_cost - due`;
- `tick_at` is a place the host has seen GetSystemTick at and answered
  itself, the one the code goes back to over and over. Naming only one at
  a time lets the host account for the ticks the code answered: they all
  came from there, in a row;
- a host with anything to do for a tick, a history of where the guest
  was say, does it for `ticks` of them before it handles the callback the
  code made, or what the code returned for.

The host sets `tick_end` and `tick_floor` again whenever it changes
`budget` or what the floor depends on, as it does after an svc it ran in
place, and `tick_at` whenever that stops being a place it would answer at.
Setting `tick_at` to 0 is always enough.

From version 8 each tick the code answers also goes in the trail, see
below.

## A mutex lent

After the clock, titles mostly take a mutex with `svc 0x25`,
WaitSynchronizationN, on its handle alone, and let it go with `svc 0x14`,
ReleaseMutex, often the same mutex from the same two places. From version 8
the host can lend the code one mutex, which the code then takes and lets go
of itself, without calling anything, while nothing but its thread could
touch it. The code answers a WaitSynchronizationN when all of these hold:

- `wait_at` is the address after the `svc`, with bit 0 set for Thumb;
- `budget` is greater than `held_floor`;
- `r2`, the count, is 1, and the word `r1` points at is `held`, read
  where the page tables reach it directly, in one page.

Then it adds one to `holding` and gives 0 in `r0` and `r1`, the result and
the index. It answers a ReleaseMutex when `release_at` is the address after
the `svc`, `budget` is greater than `held_floor`, `r0` is `held` and
`holding` is not 0. Then it takes one from `holding` and gives 0 in `r0`.
Neither costs any budget. Anywhere else, or otherwise, the code calls `svc`
as for any svc.

Every svc the code answers itself, a tick too, leaves the address after it,
with bit 0 set for Thumb, in `trail[done % RECOMP_TRAIL]`, adds one to
`done`, and leaves its tick, `tick_end - budget` before anything is taken
for it, in `tick_last`. So the host can tell what the code answered and in
which order, the last `RECOMP_TRAIL` of them at least, and whether the last
was a tick, from where it was.

A host lends a mutex the way it decides it can run a wait or a release in
place:

- `held` is the mutex's handle and `holding` how many times the current
  thread holds it, 0 when it is free. The host lends it only when it is
  free or the current thread's, and nothing else waits on it, no thread
  that would run in its place is ready, and so on, whatever has to hold
  for a wait or release in place to do no more than count;
- `held_floor` keeps the code off waits and releases after which that may
  stop being so, a timer coming due, say, the way `tick_floor` does for
  ticks, but with nothing to pay: a wait or release at cycle `t` is clear
  of the host's next such point `due` when `t < due`, which is
  `budget > tick_end - due`;
- `wait_at` and `release_at` are places the host has seen the wait and the
  release at and ran in place, 0 naming none, so a context of zeros lends
  nothing;
- when the code next calls `svc` or `interpret`, or returns, the host first
  makes the mutex what `holding` says, held that many times by the thread
  or free, then does for the svcs in the trail what it does around one it
  runs in place, then sets `done` and `ticks` back to 0. Setting
  `held_floor` to `INT32_MAX` then ends the loan, which is always enough.

## Exits

When the code returns, `exit` says why, and `r[15]` and `thumb` say where
execution continues. What the code gives back is for other code, see
[Calls](#calls), and a host can leave it alone.

| `exit` | Meaning | `r[15]` |
| --- | --- | --- |
| `EXIT_NONE` | The guest function returned. | The return address. |
| `EXIT_SVC` | The `svc` callback left the `svc` for the host's loop. The number is in `svc`. | The instruction after the `svc`. |
| `EXIT_BUDGET` | The budget ran out. | The first instruction that did not run. |
| `EXIT_UNWIND` | Anything else: an `interpret` that branched, an `svc` the host stopped the code after, a failed `lookup`, or a C stack past `stack_limit`. | Where to continue. |

In every case the host can go on from `r[15]`: with the code when `lookup`
finds any, and with its interpreter otherwise, and the guest runs exactly as
it would have. The guest state in the context is complete, with one
exception. After `EXIT_BUDGET`, a register or flag that the code at `r[15]`
sets before it reads it can still hold an older value, since nothing will
ever read that one.

## Calls

A guest call to a function the recompiler knows becomes a C call, and a guest
return becomes a C return. As a result, the C stack grows with the guest's call
depth. Every function compares the C stack with `stack_limit` on its way in,
and once the stack is past it, the code unwinds back to the host with
`EXIT_UNWIND`, `r[15]` pointing at where the function was entered. The host
starts again from `r[15]` with all of its stack. Nothing is lost, because
every return point is an entry. Set `stack_limit` to the lowest address the
code may take the stack to, far enough above the end of the stack that
whatever the host's callbacks do below the code's frames still fits. In
Rust, `recomp_abi::stack_limit()` gives the code `recomp_abi::STACK`, 1 MiB,
below the caller's frame. A function's frame takes a few hundred bytes at
most, so that is thousands of calls deep.

A function gives back where the guest went when it returned, the value it
wrote to `pc`, with bit 0 set for Thumb, or `RECOMP_STOPPED` when it left
something to the host, which `exit` then says. A call compares that with the
return address it put in `lr`, and goes on after the call when they are the
same. Anything else, for example a callee that changed its return address,
switched state or stopped, sends the caller through one place in it that
returns too when `exit` is set, and otherwise dispatches to wherever `r[15]`
points, through the function's own labels or through `lookup`. A jump into
another function returns whatever that function gives back.

## Budget

`budget` counts instructions. The code subtracts at the start of each basic
block, taking the whole block at once. A block that does not fit in what is
left does not run. The code restores the budget, points `r[15]` at the block,
and returns `EXIT_BUDGET`. As a result:

- the code stops at a block boundary, possibly with some budget left;
- the budget can run out on the very first block, so a run can end without
  any progress. Give each run more budget than the longest block, or let the
  interpreter take over when that happens. The longest block depends on the
  title, in Alpha Sapphire it is 1,603 instructions.
- each C function cuts its code into blocks of its own, and a block that a
  branch leaves early is still charged in full. So the same instructions
  can cost a little more or less depending on which function runs them:
  the caller, going on after a call or an svc run in place, or the
  function an entry names, when the host comes back in after a stop.

## A minimal host

The run loop of a host looks like this. `find_module_code` and
`interpret_one` stand in for the host's own module search and interpreter.

```c
#include <dlfcn.h>
#include "recomp.h"

static const Entry *entries;
static uint32_t entry_count;

static Code find(const Entry *table, uint32_t count, uint32_t address) {
    uint32_t low = 0, high = count;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2;
        if (table[middle].address == address) return table[middle].code;
        if (table[middle].address < address) low = middle + 1;
        else high = middle;
    }
    return NULL;
}

/* the host's own, the module search and one step of its interpreter */
Code find_module_code(uint32_t address);
void interpret_one(Context *ctx);

static Code lookup(Context *ctx, uint32_t address) {
    Code code = find(entries, entry_count, address);
    return code ? code : find_module_code(address);
}

/* the simplest svc callback, which leaves every svc to run below. */
static void svc(Context *ctx, uint32_t number) {
    ctx->svc = number;
    ctx->exit = EXIT_SVC;
}

int open_library(const char *path) {
    void *library = dlopen(path, RTLD_NOW);
    if (!library) return 0;
    const uint32_t *abi = dlsym(library, "recomp_abi");
    if (!abi || *abi != RECOMP_ABI) return 0;
    entry_count = *(const uint32_t *)dlsym(library, "recomp_entry_count");
    entries = dlsym(library, "recomp_entries");
    return 1;
}

/* runs the guest from ctx->r[15] until the budget is spent or an svc needs
   the host. */
int run(Context *ctx, int32_t budget) {
    ctx->budget = budget;
    while (ctx->budget > 0) {
        Code code = lookup(ctx, ctx->r[15] | ctx->thumb);
        if (!code) {
            /* the interpreter runs one instruction and counts it */
            interpret_one(ctx);
            continue;
        }
        char here;
        ctx->exit = EXIT_NONE;
        /* 1 MiB of C stack for the code, below this frame */
        ctx->stack_limit = (uintptr_t)&here - (1 << 20);
        code(ctx);
        if (ctx->exit == EXIT_SVC) return 1;
        if (ctx->exit == EXIT_BUDGET) break;
    }
    return 0;
}
```

A working host also fills in the page tables, `vfp`, `fpscr`, `tls` and
`host`, and implements the memory callbacks and `interpret`. A host that runs
svcs in place does in its `svc` callback what its loop would do with an
`EXIT_SVC`, and lets the code go on whenever the guest would simply carry on.
Zakuro's does that for every svc that only touches the kernel.

## Overrides and programs

Functions written by hand can take the place of generated ones, see
[overrides](overrides.md). The same tables can also be linked straight
into a program instead of loaded from a library, see
[a program of its own](port.md).

## Reference hosts

- [`abi/`](../abi) is the interface in Rust, the `recomp-abi` crate, with
  `recomp.h` beside it and a test that holds the two to the same layout.
  It loads a library or takes code linked in, does the lookups and places
  the modules. A Rust host only needs this crate, which is what Zakuro
  uses.
- [`src/verify.rs`](../src/verify.rs) is a complete host built on Zakuro's
  interpreter. It runs each recompiled function against the interpreter and
  compares the results (`--features verify`).
- [Zakuro](https://github.com/fearkov/zakuro)'s
  [`recompiled.rs`](https://github.com/fearkov/zakuro/blob/main/crates/zakuro-core/src/recompiled.rs)
  runs the library inside the emulator. It falls back to the interpreter
  wherever there is no code, and places modules as the title loads them.
