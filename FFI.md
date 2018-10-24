
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

    issuer_verify_roster_membership(issuer, verified_credential)

¹ This functionality is currently included in the FFI for all languages to
  enable testing clients, even though none of that code will ever run on the
  actual server.

 Client Protocol
-----------------

For the client side APIs, the corresponding steps for the full protocol are:

    user_obtain_finish(phone_number, system_parameters, issuer_parameters, credential_issuance) -> user
    user_show(user, roster_entry_commitment, seed) -> credential_presentation

² The `elgamal_keypair` may be `NULL`, `nil`, `undefined`, `null` to signify
that it doesn't exist.  (It doesn't yet because we don't need blinded credential
issuance for anything yet.)

 Cryptographic Utility Functions
---------------------------------

To create a commitment and its opening to some phone number, do:

    roster_entry_commitment_create(phone_number, system_parameters, seed) -> roster_entry_commitment

Note that `roster_entry_commitment` contains the opening, the latter
of which should not be given directly to the server/issuer.

To remove the opening, do:

    roster_entry_commitment_remove_opening(roster_entry_commitment) -> roster_entry_commitment_sans_opening

To verify that a commitment (and its opening) is a commitment to a
phone number, do:

    roster_entry_commitment_open(roster_entry_commitment, phone_number, system_parameters) -> bool

 Javascript/Wasm API for Electron Client
-----------------------------------------

The Javascript API is contained in wasm/src/credential.js (or credential.d.ts if
Typescript is preferred).

 Swift/Objective-C API for iOS Client
--------------------------------------

The Swift API is in swift/Credential.
