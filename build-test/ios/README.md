
 iOS
=====

This is test code for determining the complexity of building/running
cryptographic Rust code for iOS clients.


 Usage
-------

Install Xcode build tools:

```sh
xcode-select --install
```

Install `rustup` either via brew or via the rustup shell script:

```sh
brew install rustup-init && rustup-init
curl https://sh.rustup.rs -sSf | sh
```

Add the iOS architectures to rustup so we can use them during cross
compilation:

```sh
rustup target add aarch64-apple-ios armv7-apple-ios armv7s-apple-ios x86_64-apple-ios i386-apple-ios
```

Use cargo (Rust's package manager) to install `cargo-lipo`. This is a
cargo subcommand which automatically creates a universal library for
use with iOS. Without this crate, cross compiling Rust to work on iOS
is infinitely harder.

```sh
cargo install cargo-lipo
```

Now build with lipo:

```sh
cargo lipo --release
```

There should now be a universal iOS library at `target/universal/release/libbuildtest.a`.



Notes
-----

I followed roughly
[this post](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html).
