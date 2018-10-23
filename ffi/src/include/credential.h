// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#include <stdint.h>

const uint LENGTH_SEED = 32;
const uint LENGTH_SYSTEM_PARAMETERS = 64;
const uint LENGTH_ISSUER = 160;
const uint LENGTH_ISSUER_PARAMETERS = 32;
const uint LENGTH_ISSUER_KEYPAIR = 96;
const uint LENGTH_USER = 288;
const uint LENGTH_CREDENTIAL_ISSUANCE = 328;
const uint LENGTH_CREDENTIAL_PRESENTATION = 448;
const uint LENGTH_VERIFIED_CREDENTIAL = 448;
const uint LENGTH_ROSTER_ENTRY_COMMITMENT = 64;

/**
 * Contains a pointer to some data and a length.
 */
// RUST_C_COUPLED: ffi/src/c.rs buf_t
typedef struct buf_s {
  const uint64_t len; /**< The length of the data stored in `ptr`. */
  const uint8_t* ptr; /**< The `ptr` to some `uint8_t`s. */
} buf_t;

/**
 * Create some globally-agreed upon `SystemParameters` by seeding a CSPRNG.
 *
 * **Inputs**
 *
 * - `seed` an array of `LENGTH_SEED` bytes, which will be used to seed an CSPRNG.
 *
 * **Returns**
 *
 * If successful, returns a `buf_t` containing the
 * `aeonflux::parameters::SystemParameters` as a pointer to
 * `LENGTH_SYSTEM_PARAMETERS` bytes.  Otherwise, the `buf_t` will have a length
 * of `0` and a NULL pointer.
 */
buf_t system_parameters_create(const uint8_t* seed);

/**
 * Create a new credential issuer.
 *
 * **Inputs**
 *
 * - `system_parameters` are a globally agreed upon set of
 *   `aeonflux::parameters::SystemParameters`, which may be obtained via
 *   `system_parameters_create()`.
 * - `system_parameters_length` is the length of the `system_parameters`.  (Note
 *   that this *should* be `LENGTH_SYSTEM_PARAMETERS` however the `buf_t.len`
 *   value returned from system_parameters_create()` is what must be used in
 *   order to avoid buffer overflow.
 * - `seed` an array of `LENGTH_SEED` bytes, which will be used to seed an RNG.
 *
 * **Returns**
 *
 * If successful, returns a `buf_t` containing an `aeonflux::amacs::Keypair` as
 * a pointer to `LENGTH_ISSUER_KEYPAIR` bytes.  Otherwise, the `buf_t` will have
 * a length of `0` and a NULL pointer.
 */
buf_t issuer_create(const uint8_t* system_parameters,
                    const uint64_t system_parameters_length,
                    const uint8_t* seed);

/**
 * Initialise a credential issuer.
 *
 * **Note**
 *
 * This function is for initialising a credential issuer from some
 * `issuer_keypair` (previously produced with `system_parameters_create()`).
 *
 * **Inputs**
 *
 * - `system_parameters` are a globally agreed upon set of
 *   `aeonflux::parameters::SystemParameters`, which may be obtained via
 *   `system_parameters_create()`.
 * - `system_parameters_length` is the length of the `system_parameters`.  (Note
 *   that this *should* be `LENGTH_SYSTEM_PARAMETERS` however the `buf_t.len`
 *   value returned from `system_parameters_create()` is what must be used in
 *   order to avoid buffer overflow.
 * - `keypair` is an `aeonflux::amacs::Keypair` as a pointer to some bytes.
 * - `keypair_length` is the length of the `keypair`.  (Note that this *should*
 *   be `LENGTH_ISSUER_KEYPAIR` however the `buf_t.len` value returned from
 *   `issuer_create()` is what must be used in order to avoid buffer overflow.
 *
 * **Returns**
 *
 * If successful, returns a `buf_t` containing a
 * `signal_credential::issuer::SignalIssuer` as a pointer to `LENGTH_ISSUER`
 * bytes.  Otherwise, the `buf_t` will have a length of `0` and a NULL pointer.
 */
buf_t issuer_new(const uint8_t* system_parameters,
                 const uint64_t system_parameters_length,
                 const uint8_t* keypair,
                 const uint64_t keypair_length);

/**
 * Get this credential issuer's parameters (a.k.a their public key material).
 *
 * **Inputs**
 *
 * - `issuer` is a `signal_credential::issuer::SignalIssuer` as a pointer to
 *   some bytes.
 * - `issuer_length` is the length of the `issuer`.  (Note that this *should* be
 *   `LENGTH_ISSUER` however the `buf_t.len` value returned from
 *   `issuer_create()` is what must be used in order to avoid buffer overflow.
 *
 * **Returns**
 *
 * If successful, returns a `buf_t` containing an `aeonflux::amacs::PublicKey`
 * as a pointer to `LENGTH_ISSUER_PARAMETERS` bytes.  Otherwise, the `buf_t`
 * will have a length of `0` and a NULL pointer.
 */
buf_t issuer_get_issuer_parameters(const uint8_t* issuer,
                                   const uint64_t issuer_length);

/**
 * Issue a new credential to a user.
 *
 * # Inputs
 *
 * - `issuer` is a `signal_credential::issuer::SignalIssuer` as a pointer to
 *   some bytes.
 * - `issuer_length` is the length of the `issuer`.  (Note that this *should* be
 *   `LENGTH_ISSUER` however the `buf_t.len` value returned from
 *   `issuer_create()` is what must be used in order to avoid buffer overflow.
 * - `phone_number` is a pointer to the `SignalUser`'s phone number as bytes,
 *   e.g. the phone number +1 415 555 1234 might be canonically encoded as
 *   `[0, 0, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.  (Note that it **MUST** be
 *   canonically encoded, such as with libphonenumber¹, **as if it were being
 *   dialed internationally from San Francisco.
 * - `phone_number_length` is the length of the `phone_number`.
 * - `seed` an array of `LENGTH_SEED` bytes, which will be used to seed an CSPRNG.
 *
 * # Returns
 *
 * If successful, returns a `buf_t` containing a
 * `signal_credential::credential::SignalCredentialIssuance` as a pointer to
 * `LENGTH_CREDENTIAL_ISSUANCE` bytes.  Otherwise, the `buf_t` will have a
 * length of `0` and a NULL pointer.
 *
 * ¹ https://github.com/googlei18n/libphonenumber
 */
buf_t issuer_issue(const uint8_t* issuer,
                   const uint64_t issuer_length,
                   const uint8_t* phone_number,
                   const uint64_t phone_number_length,
                   const uint8_t* seed);

/**
 * Have the `issuer` check a `presentation` of a Signal user's credential.
 *
 * **Inputs**
 *
 * - `issuer` is a `signal_credential::issuer::SignalIssuer` as a pointer to
 *   some bytes.
 * - `issuer_length` is the length of the `issuer`.  (Note that this *should* be
 *   `LENGTH_ISSUER` however the `buf_t.len` value returned from
 *   `issuer_create()` is what must be used in order to avoid buffer overflow.
 * - `presentation` is a
 *   `signal_credential::credential::SignalCredentialPresentation` as a
 *   pointer to some bytes.
 * - `presentation_length` is the length of the `presentation`.  (Note that this
 *   *should* be `LENGTH_CREDENTIAL_PRESENTATION`, however the `buf_t.len` value
 *   returned from `user_show()` is what must be used in order to avoid
 *   buffer overflow.
 *
 * **Returns**
 *
 * If successful and the presentation was verifiable, returns a `buf_t`
 * containing a `signal_credential::credential::VerifiedSignalCredential` as a
 * pointer to `LENGTH_VERIFIED_CREDENTIAL` bytes.  Otherwise, the `buf_t` will
 * have a length of `0` and a NULL pointer.
 */
buf_t issuer_verify(const uint8_t* issuer,
                    const uint64_t issuer_length,
                    const uint8_t* presentation,
                    const uint64_t presentation_length);

/**
 * Check if a user in a Signal group roster for some group and permissions level.
 *
 * **Inputs**
 *
 * - `issuer` is a `signal_credential::issuer::SignalIssuer` as a pointer to
 *   some bytes.
 * - `issuer_length` is the length of the `issuer`.  (Note that this *should* be
 *   `LENGTH_ISSUER` however the `buf_t.len` value returned from
 *   `issuer_create()` is what must be used in order to avoid buffer overflow.
 * - `verified_credential` is a
 *   `signal_credential::credential::VerifiedSignalCredential` as a pointer to
 *   some bytes, as may be obtained via `issuer_verify()`.
 * - `verified_credential_length` is the length of the `verified_credential`.
 *   (Note that this *should* be `LENGTH_VERIFIED_CREDENTIAL` however the
 *   `buf_t.len` value returned from `issuer_verify()` is what must be used in
 *   order to avoid buffer overflow.
 *
 * # Returns
 *
 * If the verified credential has a committed phone number which matches the
 * phone number in the credential, then the committed phone number will be
 * returned inside a `buf_t` with its length (which should be
 * `LENGTH_ROSTER_ENTRY_COMMITMENT`).  This returned commitment can be used to
 * look up whether the user is in the specified group with the permissions they
 * are claiming to possess.
 *
 * Otherwise, the returned `buf_t` will have its length set to `0` and contain a
 * NULL pointer.
 */
buf_t issuer_verify_roster_membership(const uint8_t* issuer,
                                      const uint64_t issuer_length,
                                      const uint8_t* verified_credential,
                                      const uint64_t verified_credential_length);

/**
 * Check the proof of correct issuance on a credential issuance and potentially
 * save the credential for later use.
 *
 * **Inputs**
 *
 * - `phone_number` is a pointer to the `SignalUser`'s phone number as bytes,
 *   e.g. the phone number +1 415 555 1234 might be canonically encoded as
 *   `[0, 0, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.  (Note that it **MUST** be
 *   canonically encoded, such as with libphonenumber¹, **as if it were being
 *   dialed internationally from San Francisco.
 * - `phone_number_length` is the length of the `phone_number`.
 * - `system_parameters` are a globally agreed upon set of
 *   `aeonflux::parameters::SystemParameters`, which may be obtained via
 *   `system_parameters_create()`, but in this case should have been obtained
 *   via the issuer publishing/distributing them in some manner.
 * - `system_parameters_length` is the length of the `system_parameters`.  (Note
 *   that this *should* be `LENGTH_SYSTEM_PARAMETERS` however the `buf_t.len`
 *   value returned from `system_parameters_create()` is what must be used in
 *   order to avoid buffer overflow.
 * - `issuer_parameters` is an `aeonflux::amacs::PublicKey` as a pointer to some
 *   bytes, as obtained from `issuer_get_issuer_parameters()` (again, the issuer
 *   should publish/distribute these somehow).
 * - `issuer_parameters_length` is the length of the `issuer_parameters`.  (Note
 *   that this *should* be `LENGTH_ISSUER_PARAMETERS` however the `buf_t.len`
 *   value returned from `issuer_get_issuer_parameters()` is what must be used
 *   in order to avoid buffer overflow.
 * - `issuance` is a `signal_credential::credential::SignalCredentialIssuance`
 *   as a pointer to some bytes, which is obtainable via `issuer_issue()`
 *   (however, again, the issuer should give this to the user).
 * - `issuance_length` is the length of the `issuance`.  (Note
 *   that this *should* be `LENGTH_CREDENTIAL_ISSUANCE` however the `buf_t.len`
 *   value returned from `issuer_issue()` is what must be used in
 *   order to avoid buffer overflow.
 *
 * # Returns
 *
 * If successful and the issuance zero-knowledge proof was verifiable, returns a
 * `buf_t` containing a `signal_credential::user::SignalUser` as a pointer to
 * `LENGTH_USER` bytes.  Otherwise, the returned `buf_t` will have its length
 * set to `0` and contain a NULL pointer.
 */
buf_t user_obtain_finish(const uint8_t* phone_number,
                         const uint64_t phone_number_length,
                         const uint8_t* system_parameters,
                         const uint64_t system_parameters_length,
                         const uint8_t* issuer_parameters,
                         const uint64_t issuer_parameters_length,
                         const uint8_t* issuance,
                         const uint64_t issuance_length);

/**
 * Present a user's credential to the issuer for verification, along with a
 * specific `roster_entry_commitment` for a commited phone number in a Signal
 * group roster entry, for which the user would like to prove membership (in the
 * group) and permissions (e.g. "admin", "owner", "user", etc.).
 *
 * **Inputs**
 *
 * - `user` is a `signal_credential::user::SignalUser` as a pointer to
 *   some bytes.
 * - `user_length` is the length of the `user`.  (Note that this *should* be
 *   `LENGTH_USER` however the `buf_t.len` value returned from
 *   `user_obtain_finish()` is what must be used in order to avoid buffer
 *   overflow.
 * - `roster_entry_commitment` is a commitment to the user's phone number and an
 *   opening, as can be obtained from `roster_entry_commitment_create()`.  This
 *   commitment should have been stored at the appropriate permission level for
 *   some Signal group roster at some point prior, whenever the user joined the
 *   group.
 * - `roster_entry_commitment_length` is the length of the
 *   `roster_entry_commitment`, as can be obtained from
 *   `roster_entry_commitment_create()`.
 * - `seed` an array of `LENGTH_SEED` bytes, which will be used to seed an CSPRNG.
 *
 * **Returns**
 *
 * If successful, returns a `buf_t` containing a
 * `signal_credential::credential::SignalCredentialPresentation` as a pointer to
 * `LENGTH_CREDENTIAL_PRESENTATION` bytes.  Otherwise, the `buf_t` will have a
 * length of `0` and a NULL pointer.
 */
buf_t user_show(const uint8_t* user,
                const uint64_t user_length,
                const uint8_t* roster_entry_commitment,
                const uint64_t roster_entry_commitment_length,
                const uint8_t* seed);

/**
 * Create a commitment to a phone number.
 *
 * **NOTE**
 *
 * The returned value contains the opening to the commitment, and should *not*
 * be given to the issuer or put directly in the roster.
 *
 * **Inputs**
 *
 * - `phone_number` is a pointer to the `SignalUser`'s phone number as bytes,
 *   e.g. the phone number +1 415 555 1234 might be canonically encoded as
 *   `[0, 0, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.  (Note that it **MUST** be
 *   canonically encoded, such as with libphonenumber¹, **as if it were being
 *   dialed internationally from San Francisco.
 * - `phone_number_length` is the length of the `phone_number`.
 * - `system_parameters` are a globally agreed upon set of
 *   `aeonflux::parameters::SystemParameters`, which may be obtained via
 *   `system_parameters_create()`, but in this case should have been obtained
 *   via the issuer publishing/distributing them in some manner.
 * - `system_parameters_length` is the length of the `system_parameters`.  (Note
 *   that this *should* be `LENGTH_SYSTEM_PARAMETERS` however the `buf_t.len`
 *   value returned from `system_parameters_create()` is what must be used in
 *   order to avoid buffer overflow.
 *
 * **Returns**
 *
 * If successful, a `buf_t` containing a
 * `signal_credential::phone_number::RosterEntryCommitment` as a pointer to
 * `LENGTH_ROSTER_ENTRY_COMMITMENT` bytes.  Otherwise, the `buf_t` will have a
 * length of `0` and a NULL pointer.
 */
buf_t roster_entry_commitment_create(const uint8_t* phone_number,
                                     const uint64_t phone_number_length,
                                     const uint8_t* system_parameters,
                                     const uint64_t system_parameters_length,
                                     const uint8_t* seed);

// XXX We probably want a roster_entry_commitment_remove_opening()?

/**
 * Open a commitment, `roster_entry_commitment`, to a `phone_number`.
 *
 * **Inputs**
 *
 * - `roster_entry_commitment` is a commitment to the user's phone number and an
 *   opening, as can be obtained from `roster_entry_commitment_create()`.  This
 *   commitment should have been stored at the appropriate permission level for
 *   some Signal group roster at some point prior, whenever the user joined the
 *   group.
 * - `roster_entry_commitment_length` is the length of the
 *   `roster_entry_commitment`, as can be obtained from
 *   `roster_entry_commitment_create()`.
 * - `phone_number` is a pointer to the `SignalUser`'s phone number as bytes,
 *   e.g. the phone number +1 415 555 1234 might be canonically encoded as
 *   `[0, 0, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.  (Note that it **MUST** be
 *   canonically encoded, such as with libphonenumber¹, **as if it were being
 *   dialed internationally from San Francisco.
 * - `phone_number_length` is the length of the `phone_number`.
 * - `system_parameters` are a globally agreed upon set of
 *   `aeonflux::parameters::SystemParameters`, which may be obtained via
 *   `system_parameters_create()`, but in this case should have been obtained
 *   via the issuer publishing/distributing them in some manner.
 * - `system_parameters_length` is the length of the `system_parameters`.  (Note
 *   that this *should* be `LENGTH_SYSTEM_PARAMETERS` however the `buf_t.len`
 *   value returned from `system_parameters_create()` is what must be used in
 *   order to avoid buffer overflow.
 *
 * **Returns**
 *
 * A `buf_t` containing a NULL pointer and, if successful, its length set to
 * `1`.  Otherwise, the length is set to `0`.
 */
buf_t roster_entry_commitment_open(const uint8_t* roster_entry_commitment, // also contains the opening
                                     const uint64_t roster_entry_commitment_length,
                                     const uint8_t* phone_number,
                                     const uint64_t phone_number_length,
                                     const uint8_t* system_parameters,
                                     const uint64_t system_parameters_length);
