# groupzk

Components:

* `aeonflux`: A generic library implementing algebraic message authentication
  codes, (currently single-attribute) composable anonymous credentials, and
  various zero-knowledge proofs regarding statements on the credential attributes.

* `build-test`: Various crates expirimenting with FFI in various
  languages and for testing cross-compilation and linkage on various platforms.

* `ffi`: An FFI API for C-like languages to use the functionality of the
  `signal-credential` library.

* `java`: An FFI API for JNI Java code. **Work in progress.**

* `signal-credential`: Signal-specfic library for creating anonymous credentials
  using phone numbers as blinded attributes and zero-knowledge proofs for
  demonstrating anonymously whether a user has certain privileges
  (i.e. owner/admin/member) within a Signal group conversation.

* `swift`: A FFI API for Swift to use the functionality of the
  `signal-credential` library, its xcode project settings, and cocoapods specs.

* `wasm`: A FFI API for Javascript to use the functionality of the
  `signal-credential` library.

* `zkp-expand`: A small utitily to expand and clean up the `*_macros.rs` files
  containing pseudo-Camenisch-Stadler notated non-interactive zero-knowledge
  proofs from `aeonflux` and `signal-credential`.


 Build Artefacts
-----------------

* C/C++: A copy of the copiled C/C++ FFI is at `ffi/target/release/libcredential.{a,so}`.
* C Headers: The headers are at `ffi/src/include/credential.h`.
* Java/JNI: The compiled AAR is at `jni/Credential/rust/build/outputs/aar/rust-debug.aar`.
* Swift: A copy of the compiled Swift library is at `swift/Products/libCredential.a`.
* Wasm/JS: A copy of the compiled Wasm is at
  `wasm/src/credential{_bg}.wasm` and its JS wrapper module is at `wasm/src/credential.js`.


 TODO
------

* The podspec for the Swift CocoaPod (`credential.podspec`) isn't working,
  however as noted above in the "Build Artefacts" section, the code does compile
  in Xcode.  It might be that there is a build/linker setting somewhere in the
  `.xcodeproj` settings that isn't replicated in the podspec.

* The Android/Java AAR is just a repackaging into an AAR of the C API, compiled for
  `arm64-v8a`, `armeabi-v7a`, and `x86` ABIs.  There is no JNI interface to the
  C yet, as I wasn't sure whether Android clients and/or the server could just
  directly call the C.

* Unittests and benchmarks should be written in C, Java, Swift, and JS. (There
  are currently only tests in Rust and C-like Rust).


 Useful resources
------------------

Java/JNI:

* https://www.codepool.biz/build-so-aar-android-studio.html
* https://dominoc925.blogspot.com/2015/09/how-to-create-and-use-android-archive.html
* https://github.com/tomaka/android-rs-glue
* https://hub.docker.com/r/tomaka/cargo-apk/
* https://github.com/signalapp/curve25519-java/blob/master/java/src/main/java/org/whispersystems/curve25519/NativeCurve25519Provider.java
* https://github.com/signalapp/curve25519-java/blob/master/android/jni/curve25519-jni.c
* https://docs.rs/jni/0.10.2/src/jni/wrapper/jnienv.rs.html#1063-1079
* https://github.com/jni-rs/jni-rs/blob/master/example/mylib/src/lib.rs
* https://docs.rs/jni/0.10.2/jni/
* https://github.com/signalapp/ContactDiscoveryService/blob/41ea6e87fa5410aee1891e9a83c46afe8aaf58c5/service/src/main/java/org/whispersystems/contactdiscovery/util/NativeUtils.java


