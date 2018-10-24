
 Things We Want in (Or Stabilised in) Rust
===========================================

1. It seems that Apple forked LLVM before Rust did, and then Apple's
   LLVM IR outputs differently formatted bitcode, but then also Apple
   didn't contribute the patches back to upstream LLVM before Rust
   ended up forking it:

   https://github.com/Geal/rust_on_mobile#how-can-we-generate-a-static-library-with-apples-bitcode-format
   
   It seems like this might be impossible (or an otherwise enormous
   amount of effort) to upgrade Rust's LLVM version, but it would be
   nice if iOS applications written in Rust could take advantage of
   the smaller library/binary sizes provided by bitcode.

2. Stabilise #![feature(asm)].

   This is currently used in the `subtle`
   [crate](https://github.com/dalek-cryptography/subtle) (a library for
   constant-time functions, which is used by curve25519-dalek, which is then
   used by aeonflux, which is then used by signal-credential) to prevent LLVM
   optimising a `u8` which is always guaranteed to be either `0` or `1` to the
   internal one-bit `i1` type.

   It's also used by the `clear_on_drop`
   [crate](https://github.com/cesarb/clear_on_drop) (a library for zeroing out
   secrets from memory when the type's destructor is called) to prevent
   optimisers from eliding memory zeroing code after determining that the
   operand is no longer used, and for preventing optimisers from inlining a
   called function and the zeroing code and using separate stack areas for each.
