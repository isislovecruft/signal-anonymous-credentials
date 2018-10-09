
 wasm
======

Web Assembly and Javascript/Typescript bindings for the `signal-credential`
library, for use in the Signal desktop client.


 Producing Updated Bindings
----------------------------

Install `rustup` either via brew or via the rustup shell script:

```sh
brew install rustup-init
curl https://sh.rustup.rs -sSf | sh
```

Install a nightly Rust compiler and Cargo (Rust's package manager):

```sh
rustup install nightly
```

Probably, you can just run `make` at this point.  The `.wasm` and
`.js` module should end up in `src/`.  Details of what the `Makefile`
is doing are as follows.

 Details
---------

Add wasm32 as a build target platform:

```sh
rustup target add wasm32-unknown-unknown --toolchain nightly
cargo +nightly build --target wasm32-unknown-unknown --release
```

This gives us a wasm file at `target/wasm32-unknown-unknown/release/electron.wasm`:

```sh
cp target/wasm32-unknown-unknown/release/electron.wasm ./
```

Now run the `wasm-bindgen` tool on it to generate a new wasm file and
a set of Javascript bindings:

```sh
cargo install wasm-bindgen-cli
wasm-bindgen src/credential.wasm --out-dir src
```

That should create a `src/credential.js` module which exports a
Javascript FFI to the `signal-credential` Rust crate.


Notes
-----

I followed roughly
[this post](https://hacks.mozilla.org/2018/04/javascript-to-rust-and-back-again-a-wasm-bindgen-tale/),
but it even though it's only 3 months old it was pretty out of date
and required me digging around in the proc-macro2 crate and some
compiler internals.

[This book](https://rustwasm.github.io/wasm-bindgen/introduction.html)
was more helpful, but I ended up looking at both and cross-referencing.

The most important part of the above book is likely the
[documentation](https://rustwasm.github.io/wasm-bindgen/reference/arbitrary-data-with-serde.html)
on the `JsValue` type, which I've used liberally here.
