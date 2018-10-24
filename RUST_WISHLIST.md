
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
