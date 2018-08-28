
 Electron
==========

This is test code for determining the complexity of building/running
cryptographic Rust code for Electron clients.


 Usage
-------

Install `rustup` either via brew or via the rustup shell script:

```sh
brew install rustup-init
curl https://sh.rustup.rs -sSf | sh
```

Install a nightly Rust compiler and Cargo (Rust's package manager),
and add wasm32 as a build target platform:

```sh
rustup install nightly
rustup default nightly
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
wasm-bindgen electron.wasm --out-dir site
```

That should create an `electron.js` module in the `site` directory which exports
a Javascript FFI to the `do_things_with_maths()` Rust function in the `maths`
crate, which will call the Javascript `alert()` function with the result of some
cryptographic computations (it should display 32 random-ish looking bytes).


Notes
-----

I followed roughly
[this post](https://hacks.mozilla.org/2018/04/javascript-to-rust-and-back-again-a-wasm-bindgen-tale/),
but it even though it's only 3 months old it was pretty out of date
and required me digging around in the proc-macro2 crate and some
compiler internals.

[This book](https://rustwasm.github.io/wasm-bindgen/introduction.html)
was more helpful, but I ended up looking at both and cross-referencing.
