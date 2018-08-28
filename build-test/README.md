
 build-test
============

A test for building cryptographic Rust code across iOS, Android, Electron,
and the Signal backend server.

 Usage
=======

Install a rust compiler on the build machine which can target the selected platform.


 Android
---------

 iOS
-----

 Electron
----------

    rustup target add wasm32-unknown-unknown
    cargo build --target wasm32-unknown-unknown

 AWS
-----

