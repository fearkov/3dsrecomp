# 3dsrecomp

This is a static recompiler for Nintendo 3DS games, made to run with [Zakuro](https://github.com/fearkov/zakuro). It's a WIP.

It reads a game's code, finds the functions in it and turns them into C, which compiles into a library the emulator loads. Anything it can't handle or didn't find still runs in Zakuro's interpreter, so a game doesn't have to be fully recompiled to work.

So far it has been tested with Pokémon Alpha Sapphire, which runs through its intro and into Littleroot Town on recompiled code, with more than 99% of the instructions it runs coming from the library. With Zakuro now drawing on the GPU, the game runs about twice as fast as it did on the interpreter.

## Features

- finding the code in the main executable and in the CRO modules, from the entry point, calls, exports, relocations, pointers in data and what the modules import from each other, then looking for where functions begin in whatever is left
- generating C for ARM, Thumb and VFP code, with the less common instructions going through the interpreter
- modules get code that works wherever the game loads them
- checking every recompiled function against Zakuro's interpreter, running both from the same state and comparing registers, flags and memory
- running it in Zakuro with --recompiled

## How to use

You need Rust, a C compiler and Zakuro cloned next to this repository, since 3dsrecomp uses its crates. I've only tested on Linux so far.

```
cargo build --release
./target/release/3dsrecomp analyze game.3ds
./target/release/3dsrecomp build game.3ds out
./target/release/3dsrecomp verify game.3ds out/<title id>.so
```

analyze - shows how much of the code was found; 
build - writes the C to out and compiles it; 
verify - runs the recompiled functions against the interpreter. 

The build takes a while, so don't worry. Then point Zakuro at the library, or at the directory holding it:

```
zakuro game.3ds --recompiled out
```

## Notes

This repository doesn't contain any game code. You need your own dump of a game you own, and since the generated C and libraries come from the game, don't share them.

I do not condone piracy, and I will not help you with that. So, don't ask me about that.

Contributions are welcome. Using AI is fine sometimes, but the code must always be reviewed by a human. Code that is entirely vibecoded will be discarded.


