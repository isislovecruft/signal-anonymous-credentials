
 C-like FFI for signal-credential
==================================

 iOS
-----

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
[workaround for a known rustc issue](https://github.com/rust-lang/rust/issues/36156#issuecomment-373201676)):

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    SIGNAL_CREDENTIAL_IOS_DIR=.../path/to/signal-credential-ios/Credential/libcredential/ \
    make ios
```

(The other workaround, which permanently changes Xcode's active developer
directory, is `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
I'm not an iOS developer so maybe that's normal, but it seemed rude to permanently
change a setting just to build some measly Rust code.)

There should now be a universal iOS library at
`$SIGNAL_CREDENTIAL_IOS_DIR/libcredential-ios.a` and a header at
`$SIGNAL_CREDENTIAL_IOS_DIR/credential.h`.
