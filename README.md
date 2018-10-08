# groupzk

Components:

* `aeonflux`: A generic library implementing algebraic message authentication
  codes, (currently single-attribute) composable anonymous credentials, and
  various zero-knowledge proofs regarding statements on the credential attributes.

* `build-test`: Various crates expirimenting with FFI in various
  languages and for testing cross-compilation and linkage on various platforms.

* `ffi`: An FFI API for C-like languages to use the functionality of the
  `signal-credential` library.

* `signal-credential`: Signal-specfic library for creating anonymous credentials
  using phone numbers as blinded attributes and zero-knowledge proofs for
  demonstrating anonymously whether a user has certain privileges
  (i.e. owner/admin/member) within a Signal group conversation.

* `wasm`: A FFI API for Javascript to use the functionality of the
  `signal-credential` library.
