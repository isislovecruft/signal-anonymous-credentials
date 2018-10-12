
 AOS
=====

This is test code for determining the complexity of building/running
cryptographic Rust code for AOS clients.


 Usage
-------

**NOTE**: I haven't actually done any of the following steps, but I
  believe the following *should* work.  Ping me if you run into
  trouble. —isis

Install `rustup` either via the rustup shell script:

```sh
curl https://sh.rustup.rs -sSf | sh
```

Add the Android architectures to rustup so we can use them during cross
compilation:

```sh
rustup target add aarch64-linux-android arm-linux-androideabi armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Get Android NDK and set up our Cargo (Rust's package manager) config:

```sh
sdkmanager --verbose ndk-bundle
./create-ndk-standalone.sh
```

Build for Android architectures:

```sh
cargo build --target armv7-linux-androideabi --release
cargo build --target arm-linux-androideabi --release
cargo build --target x86_64-linux-android --release
```

Copy or link the `*.so` into the corresponding `Signal-Android/libs` directory:

  Copy from Rust | Copy to Android
  ---|---
  `target/armv7-linux-androideabi/release/lib???.so` | `libs/armeabi-v7a/lib???.so`
  `target/arm-linux-androideabi/release/lib???.so` | `libs/armeabi/lib???.so`
  `target/x86_64-linux-android/release/lib???.so` | `libs/x86/lib???.so`

TODO
----

* Are all AOS targets 64 bit? Should we build with the 32-bit code
  just in case? (The 64 bit code is roughly twice as fast.)

Notes
-----

I followed roughly the Android portion of
[these directions](https://github.com/kennytm/rust-ios-android).
