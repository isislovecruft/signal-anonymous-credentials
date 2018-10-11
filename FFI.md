
 Instructions for Using the FFI code
=====================================

A high level, language agnostic walkthrough of the APIs are as follows.
Function names in each language are more or less the same (the Swift API is
class-oriented, but it still should be hopefully clear which function is which).

 Server Protocol
-----------------

For all APIs¹, the current steps to create a new issuer are:

    system_parameters_create(bytes) -> system_parameters
    issuer_create(system_parameters, seed) -> amacs_keypair
    issuer_new(system_parameters, amacs_keypair)

Next, the current steps to go through the entire protocol on the issuer side are:

    issuer_issue(issuer, seed, credential_request, phone_number) -> credential_issuance
    issuer_verify(issuer, credential_presentation) -> verified_credential

Finally, to see if a user is a member of a certain group, the issuer does:

    issuer_verify_roster_membership_{owner,admin,user}(issuer,
                                                       verified_credential,
                                                       roster)

[Note: the roster code was stubbed out quickly just to enable testing for now
and is likely to change or be entirely rewritten (probably in Java, I'm assuming).
Furthermore, the `issuer_verify_roster_membership_{owner,admin,user}()` function
will likely be simplified into one function which takes as argument the commitment
to the phone number which is stored in the roster.]

¹ This functionality is currently included in the FFI for all languages to
  enable testing clients, even though none of that code will ever run on the
  actual server.

 Client Protocol
-----------------

For the client side APIs, the corresponding steps for the full protocol are:

    user_new(system_parameters, elgamal_keypair², phone_number, issuer_parameters, seed) -> user
    user_obtain(user) -> credential_request
    user_obtain_finish(user, credential_issuance) -> user_with_credential
    user_show(user_with_credential, seed) -> credential_presentation

² The `elgamal_keypair` may be `NULL`, `nil`, `undefined`, `null` to signify
that it doesn't exist.  (It doesn't yet because we don't need blinded credential
issuance for anything yet.)

 Javascript/Wasm API for Electron Client
-----------------------------------------

The Javascript API is contained in wasm/src/credential.js (or credential.d.ts if
Typescript is preferred).

 Swift/Objective-C API for iOS Client
--------------------------------------

The Swift API is in swift/Credential.  It's a Cocoa Framework³.  It builds as an
Xcode project into a `libCredential.a` file (*not* the `libcredential.a` file in
the `swift` directory, the lowercased one is the Rust library that Swift is
calling).

³ See question #4.

 Java/C API for Android
------------------------

See questions #1-3.

 Java JNI API for Server
-------------------------

See questions #2.

 Questions
===========

1. Can Android clients simply call the C API defined in ffi/src/c.rs and
   ffi/src/include/credential.h?

2. Is it preferable to write JNI C code for the server to interface with the
   signal-credential code, or is it okay to use https://docs.rs/jni ?

3. If I write JNI code for the server, does that also work as NDK code for the
   Android client?

4. I understand we need a cocoaPods Framework, and I began trying to make one
   (hence the podspec and podfiles strewn about), but I can't get it to build
   and I've no idea why.  I had to fiddle with a bunch of things in Xcode to get
   the linker to behave itself… could it be that I'm simply not replicating
   those settings in the podspec?
