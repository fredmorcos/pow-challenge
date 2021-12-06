# `pow-challenge`: A multi-threaded CPU implementation of a proof-of-work challenge

[Github Repository](https://github.com/fredmorcos/pow-challenge)

## Licensing

This software is licensed under [the GPLv3
license](https://choosealicense.com/licenses/gpl-3.0/) (see the LICENSE
file). Dependencies of this software are licensed under [the MIT
license](https://choosealicense.com/licenses/mit/) (see the LICENSE.dependencies file).

## Building

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

To build with stats output and extra checks (slower runtime):

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release --features stats
```

## Running

```sh
RUSTFLAGS="-C target-cpu=native" cargo run --release
```

## Parameters

Parameters are hard-coded and cannot be passed on the command-line, they can be found in
the `main()` function under `src/main.rs`:

```rust
let authdata = "kHtMDdVrTKHhUaNusVyBaJybfNMWjfxnaIiAYqgfmCTkNKFvYGloeHDHdsksfFla";
let difficulty = 8;
```
