# Overrides

An override is a function written by hand in C that runs instead of the
function 3dsrecomp would generate for an address. Overrides are for fixes,
mods, and faster native versions of hot functions. Titles that need none
still build without them.

## Writing one

Put the functions in one or more C files and mark each with the address it
replaces:

```c
#include "overrides.h"

/* the title's strlen, done natively */
RECOMP_OVERRIDE(0x0012A4F0) {
    uint32_t start = ctx->r[0], end = start;
    while (mem_read8(ctx, end))
        end++;
    ctx->r[0] = end - start;
    RETURN_TO(ctx->r[14]);
}
```

Then pass the file, or a directory of them, to `build` or `port`:

```
3dsrecomp build <rom> <dir> --overrides overrides/
```

The files are compiled with the generated code, so everything in
[`recomp.h`](../abi/recomp.h) is available: the context, the memory
helpers such as `mem_read32` and `mem_write32`, and the `CALL` and
`RETURN_TO` macros. [The interface](interface.md) describes them.

An override is entered the way the guest enters the function it replaces:

- the arguments are in `r0` to `r3` and on the guest stack;
- `r14` holds the return address.

It returns the way a guest function does:

- the result goes in `r0`;
- it ends with `RETURN_TO(ctx->r[14])`, which also switches between ARM and
  Thumb when the caller needs it.

## Addresses

- **Thumb.** An odd address means a Thumb function, as in
  `RECOMP_OVERRIDE(0x0012A4F1)`.
- **Modules.** A function in a CRO module is named by the module and its
  offset from the start of the module's file:

  ```c
  RECOMP_OVERRIDE_IN(DllField, 0x1A40) {
      ...
  }
  ```

  The offset stays the same wherever the title loads the module.

## Calling the original

The generated function is still there. `RECOMP_ORIGINAL` names it, so an
override can run it before or after doing something of its own:

```c
#include <stdio.h>
#include "overrides.h"

RECOMP_OVERRIDE(0x00112120) {
    fprintf(stderr, "0x00112120 called with r0 = %08X\n", ctx->r[0]);
    CALL(RECOMP_ORIGINAL(0x00112120));
}
```

When the original returns, `r15` already holds the address it returned to,
so the override can simply return too. `build` warns about an override
whose address has no generated code. There is no original to call in that
case.

## Natives

`build` writes overrides of its own for the integer divisions of ARM's C
library, which every title built with armcc links and which the ARM11 does
with a loop, having no divide instruction. It finds them by their bytes,
RVCT 4.1's, and puts their overrides in `natives.c`:

- `__aeabi_uidivmod` and `__aeabi_idivmod`, 32-bit unsigned and signed;
- `__aeabi_uldivmod` and `__aeabi_ldivmod`, 64-bit.

Each divides on the host and leaves the quotient and the remainder where the
library does. A divisor of zero, and the one quotient that overflows, go to
the library's own code, which is still there. Each charges the budget what
that code would have: exactly for the 32-bit ones, and for the 64-bit ones
once the quotient has 6 bits or more.

An override written by hand for the same address takes the place of the
native. A host can turn the natives off by setting the library's
`recomp_natives` to 0, and Zakuro does that when `ZAKURO_NATIVES` is 0.
`verify` compares the generated code with the natives off, and then each
native against the title's own code in the interpreter, on numbers that go
every way through it.

## What changes

- **Calls.** Every call the recompiler can follow to the address goes to the
  override instead.
- **Entries.** The address's entry in the table points at the override, so
  the host also runs the override for indirect calls and for anything it
  looks up there.
- **Resuming.** Code that resumes partway through the replaced function
  still runs the generated code. For example, a return into it after one of
  its own calls. Only entering at the address goes to the override.
- **`verify`.** It compares the generated code against Zakuro's interpreter.
  An override that does something different from the original shows up
  there as a mismatch, by design.
