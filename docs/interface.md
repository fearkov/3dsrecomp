# The interface

`3dsrecomp build` turns a title into a shared library. Nothing in the library
depends on a particular emulator. It runs against a small interface, declared
in [`recomp.h`](../src/codegen/recomp.h). Any program that implements that
interface can run the code. This document calls that program the host.

This page describes version 4 of the interface.

## What build writes

`3dsrecomp build <rom> <dir>` writes these files to `<dir>`:

- `recomp.h`, a copy of the interface;
- `entries.c`, which holds the tables described below;
- one header per program, with the prototypes of its functions;
- `code000.c`, `code001.c` and so on, which hold the functions;
- `<program id>.so`, all of the above compiled. The name is 16 uppercase hex
  digits, for example `000400000011C500.so`.

The compiler comes from `CC`, and `cc` is used when `CC` is not set. To
compile the sources yourself, keep `-ffp-contract=off`. Without it, the
compiler can fuse a multiply and an add, which rounds differently from the
guest.

## Exported symbols

| Symbol | Type | Meaning |
| --- | --- | --- |
| `recomp_abi` | `const uint32_t` | The interface version, `RECOMP_ABI` |
| `recomp_entry_count` | `const uint32_t` | Number of entries in the executable |
| `recomp_entries` | `const Entry[]` | The executable's entries |
| `recomp_module_count` | `const uint32_t` | Number of modules |
| `recomp_modules` | `const Module[]` | One per CRO module |

Check `recomp_abi` first, and refuse to run the library when it is not the
version you were written for. The version goes up whenever the layout of any
structure or the meaning of any field changes.

### Entries

```c
typedef struct Entry {
    uint32_t address;
    Code code;          /* void (*)(Context *) */
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
already gone, after an unwind or an svc (see below). Several entries can share
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
| `depth` | How many guest calls deep the C stack is. The host sets it to 0 before each call. |
| `tls` | The read-only thread ID register, which `mrc p15, 0, rX, c13, c0, 3` reads. On the 3DS it holds the thread's TLS address. |
| `read_pages`, `write_pages` | The page tables. See [Memory](#memory). |
| `vfp` | 32 words, `s0` to `s31`. `dN` is `s2N` (low word) followed by `s2N+1`. |
| `fpscr` | A pointer to FPSCR. |
| `host` | The host's callbacks. |
| `user` | Belongs to the host. The code never touches it. |

`vfp` and `fpscr` are pointers so that the code and an interpreter can work on
the same registers without copying them back and forth.

`r[15]` is only kept up to date at the points where the code hands control
back: when it returns, and when it calls `lookup`. It is not current inside
the memory callbacks. The `interpret` callback receives the address it needs
as an argument.

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

## Exits

When the code returns, `exit` says why, and `r[15]` and `thumb` say where
execution continues.

| `exit` | Meaning | `r[15]` |
| --- | --- | --- |
| `EXIT_NONE` | The guest function returned. | The return address. |
| `EXIT_SVC` | The guest ran an `svc`. The number is in `svc`. | The instruction after the `svc`. |
| `EXIT_BUDGET` | The budget ran out. | The first instruction that did not run. |
| `EXIT_UNWIND` | Anything else: an `interpret` that branched, a failed `lookup`, or calls nested too deep. | Where to continue. |

In every case the guest state in the context is complete. The host can go on
from `r[15]`: with the code when `lookup` finds any, and with its interpreter
otherwise.

## Calls

A guest call to a function the recompiler knows becomes a C call, and a guest
return becomes a C return. As a result, the C stack grows with the guest's call
depth. When the depth passes `RECOMP_DEPTH_LIMIT` (2048), the code unwinds
back to the host with `EXIT_UNWIND`. The host starts again from `r[15]` with
`depth` at 0. Nothing is lost, because every return point is an entry.

After a call returns, the code checks that `r[15]` is the instruction after
the call. If it is not, for example because the callee changed the return
address or switched state, the code dispatches to wherever `r[15]` points,
through the function's own labels or through `lookup`.

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
        ctx->exit = EXIT_NONE;
        ctx->depth = 0;
        code(ctx);
        if (ctx->exit == EXIT_SVC) return 1;
        if (ctx->exit == EXIT_BUDGET) break;
    }
    return 0;
}
```

A working host also fills in the page tables, `vfp`, `fpscr`, `tls` and
`host`, and implements the memory callbacks and `interpret`.

## Reference hosts

- [`src/abi.rs`](../src/abi.rs) is the interface in Rust. It loads the
  library, does the lookups and places the modules.
- [`src/verify.rs`](../src/verify.rs) is a complete host built on Zakuro's
  interpreter. It runs each recompiled function against the interpreter and
  compares the results (`--features verify`).
- [Zakuro](https://github.com/fearkov/zakuro)'s
  [`recompiled.rs`](https://github.com/fearkov/zakuro/blob/main/crates/zakuro-core/src/recompiled.rs)
  runs the library inside the emulator. It falls back to the interpreter
  wherever there is no code, and places modules as the title loads them.
