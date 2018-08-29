
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

Now build with lipo (the `DEVELOPER_DIR` setting is a
[workaround for a known rustc issue](https://github.com/rust-lang/rust/issues/36156#issuecomment-373201676),
and the `env` part is specific to fish so if using bash or sh leave
the `env` part out):

```sh
env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer cargo lipo --release
```

(The other workaround, which permanently changes Xcode's active developer
directory, is `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
I'm not an iOS developer so maybe that's normal, but it seemed rude to permanently
change a setting just to build some measly Rust code.)

There should now be a universal iOS library at `target/universal/release/libbuildtest.a`.

This can be linked into an existing Xcode project by navigating the project
settings to `General > Linked Frameworks and Libraries` and clicking the `+`
button.  You'll also need to link in the `libresolv.tbd` framework (search for
it in the list of libraries/frameworks which appear after clicking the `+`).

I did somewhat crazy things with raw pointers and allocators on the Rust side
(cf. `allocate_buffer_for_bytes`) to be able to pass an actual pointer to Swift
in a manner that Swift's garbage collector should be able to safely `free()` it
later, but we should probably check for memory leaks to ensure it's actually
getting freed (and hopefully not getting freed early and/or twice).

See the `xcode` directory for an example iOS app which calls Rust from Swift code.

Notes
-----

I followed roughly
[this post](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html).

There's currently
[a bug](https://github.com/rust-lang/rust/issues/36156#issuecomment-330971277)
in rustc that prevents building for iOS from anything but macOS.  This
should be too much of an issue since we also need to use Xcode, which
only works on macOS anyway.
