# A program of its own

`3dsrecomp build` makes a library that an emulator loads, and the emulator
runs any title for which it has one. `3dsrecomp port` makes a title into a
program of its own instead: the recompiled code is linked into one
executable, with [Zakuro](https://github.com/fearkov/zakuro) as the runtime
that does everything else, the kernel, services, GPU and sound.

Both come from the same generated C, and [overrides](overrides.md) work the
same way in each.

## Making one

```
3dsrecomp port <rom> <dir> [--overrides <file or dir>] [--name <name>] [--zakuro <checkout>]
cd <dir>
cargo build --release
```

`port` writes the following to `<dir>`:

- `code/`: the generated C and `librecomp.a`, the code compiled into a
  static library;
- `Cargo.toml`, `build.rs` and `src/main.rs`: a Cargo project whose program
  links that library and hands it to Zakuro.

The program is called after the title unless `--name` says otherwise. By
default the project builds against Zakuro from GitHub. `--zakuro` points it
at a local checkout instead.

You need Rust, a C compiler and `ar`. Linking pulls in hundreds of megabytes
of objects, so the first build takes a while.

On Windows, the C compiler has to match the Rust toolchain. With Rust's
MSVC toolchain, the default, use LLVM's `clang` and `llvm-ar`, set in `CC`
and `AR`. With the GNU toolchain, use MinGW-w64's `gcc` and `ar`.

## Running it

```
target/release/<name> <rom>
```

The program still reads the game's files, save and everything but the code
from your copy. So it takes the same path, and the same options, that
Zakuro does. If it is given a different title, it notices from the title
ID and interprets the code instead of running code meant for another game.
When a mod or an update next to the game changed the code it was
recompiled from, the functions that changed run in the interpreter and the
rest stay recompiled. A program made before ports said what their code was
made from can't tell those apart, so it interprets everything then.

## Sharing

The project holds the game's code, translated into C and compiled. It is
for your own copy of the game, like the library `build` makes, and is not
something to share.
