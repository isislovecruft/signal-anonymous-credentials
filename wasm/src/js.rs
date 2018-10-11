// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

pub use rand::ChaChaRng;
pub use rand::SeedableRng;

use signal_credential::amacs::{self};
use signal_credential::credential::SignalCredentialIssuance;
use signal_credential::credential::SignalCredentialPresentation;
use signal_credential::credential::SignalCredentialRequest;
use signal_credential::credential::VerifiedSignalCredential;
use signal_credential::elgamal::{self};
use signal_credential::issuer::IssuerParameters;
use signal_credential::issuer::SignalIssuer;
use signal_credential::parameters::SystemParameters;
use signal_credential::roster::GroupMembershipLevel;
use signal_credential::roster::GroupMembershipRoster;
use signal_credential::user::SignalUser;

pub type SignalRng = ChaChaRng;

#[macro_export]
macro_rules! slice_to_array {
    ($slice:ident, $length:expr) => {{
        if $slice.len() != $length {
            Err(())
        } else {
            let mut array: [u8; $length] = [0u8; $length];

            // This will panic if the bytes.len() isn't equal to the array_length,
            // hence the explicit double-checks on the lengths above.
            array.copy_from_slice($slice);

            Ok(array)
        }
    }}
}

#[macro_export]
macro_rules! ok_or_return {
    ($expr:expr) => {
        match $expr {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("{:?}", _x);
                return JsValue::from(0);
            }
        }
    }
}

#[macro_export]
macro_rules! ok_or_false {
    ($expr:expr) => {
        match $expr {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("{:?}", _x);
                return false;
            }
        }
    }
}

#[macro_export]
macro_rules! csprng_from_seed {
    ($seed:ident) => {{
        let mut seed_array: [u8; 32] = ok_or_return!(slice_to_array!($seed, 32));

        SignalRng::from_seed(seed_array)
    }}
}

/// Create some globally-agreed upon `SystemParameters` from a distinguished
/// basepoint, `H`.
///
/// # Inputs
///
/// * `seed` an array of 32 bytes, which will be used to seed an RNG.
///
/// # Returns
///
/// The `aeonflux::parameters::SystemParameters` as a `JsValue`¹.
///
/// ¹ Which, by the way, you won't be able to do much of anything with since
///   it's internally serialised to literal bytes, so best don't touch it.
///
#[wasm_bindgen]
pub fn system_parameters_create(
    seed: &[u8],
) -> JsValue
{
    if H.len() != 32 {
        return JsValue::from(0);
    }
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let system_parameters: SystemParameters = SystemParameters::hunt_and_peck(&mut csprng);

    ok_or_return!(JsValue::from_serde(&system_parameters))
}

/// Create a new credential issuer.
///
/// # Inputs
///
/// * `system_parameters` are a globally agreed upon set of
///   `aeonflux::parameters::SystemParameters`, which may be obtained via
///   `system_parameters_create()`.
/// * `seed` must be a byte array with length 32, containing random
///   bytes for seeding a CSPRNG.
///
/// # Returns
///
/// A `signal_credential::issuer::SignalIssuer` as a `JsValue`¹.
///
/// ¹ Which, by the way, you won't be able to do much of anything with since
///   it's internally serialised to literal bytes, so best don't touch it.
///
/// # Note
///
/// After calling this function, you probably **really** want to call
/// `issuer_get_keypair()` with the result, in order to retain the necessary
/// data for re-instantiating this credential issuer with `issuer_new()` later.
///
#[wasm_bindgen]
pub fn issuer_create(
    system_parameters: JsValue,
    seed: &[u8],
) -> JsValue
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let system_params: SystemParameters = ok_or_return!(system_parameters.into_serde());
    let issuer: SignalIssuer = SignalIssuer::create(system_params, &mut csprng);

    ok_or_return!(JsValue::from_serde(&issuer))
}

/// Get an instantiated credential issuer's aMACs keypair.
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
///
/// # Returns
///
/// * An `aeonflux::amacs::Keypair` as a `JsValue`¹.
///
/// ¹ Which, by the way, you won't be able to do much of anything with since
///   it's internally serialised to literal bytes, so best don't touch it.
///
#[wasm_bindgen]
pub fn issuer_get_keypair(
    issuer: JsValue,
) -> JsValue
{
    let issuer: SignalIssuer = ok_or_return!(issuer.into_serde());
    
    ok_or_return!(JsValue::from_serde(&issuer.issuer.keypair))
}

/// Get this credential issuer's parameters (a.k.a their public key material).
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
/// 
/// # Returns
///
/// * An `aeonflux::amacs::PublicKey` as a `JsValue`¹.
///
/// ¹ Which, by the way, you won't be able to do much of anything with since
///   it's internally serialised to literal bytes, so best don't touch it.
///
#[wasm_bindgen]
pub fn issuer_get_issuer_parameters(
    issuer: JsValue,
) -> JsValue
{
    let issuer: SignalIssuer = ok_or_return!(issuer.into_serde());
    
    ok_or_return!(JsValue::from_serde(&issuer.issuer.keypair.public))
}

/// Instantiate a previously generated credential issuer.
///
/// # Inputs
///
/// * `system_parameters` are a globally agreed upon set of
///   `aeonflux::parameters::SystemParameters`, which may be obtained via
///   `system_parameters_create()`.
/// * `keypair` is an `aeonflux::amacs::Keypair` as a `JsValue`, as can be
///   obtained from `issuer_get_keypair()`.
///
/// # Returns
///
/// A `signal_credential::issuer::SignalIssuer` as a `JsValue`¹ if successful,
/// otherwise a single byte set to `0`.
///
/// ¹ Which, by the way, you won't be able to do much of anything with since
///   it's internally serialised to literal bytes, so best don't touch it.
///
/// # Note
///
/// This is merely an instantiation function.  If you'd like to create a
/// brand-new issuer (which generally should only be done on the Signal server),
/// use `issuer_create()`.
///
#[wasm_bindgen]
pub fn issuer_new(
    system_parameters: JsValue,
    keypair: JsValue,
) -> JsValue
{
    let system_params: SystemParameters = ok_or_return!(system_parameters.into_serde());
    let keys: amacs::Keypair = ok_or_return!(keypair.into_serde());
    let issuer: SignalIssuer = SignalIssuer::new(system_params, keys);

    ok_or_return!(JsValue::from_serde(&issuer))
}

/// Issue a new credential to a user.
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
/// * `seed` must be a byte array with length 32, containing random bytes for
///   seeding a CSPRNG.
/// * `request` is a `SignalCredentialRequest` as a `JsValue`, from a `SignalUser`.
/// * `phone_number` is the `SignalUser`'s phone number as bytes, e.g.
///   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
///
/// # Returns
///
/// A `SignalCredentialIssuance` as a `JsValue` if the credential issuance was
/// successful, otherwise a single byte set to `0`.
///
#[wasm_bindgen]
pub fn issuer_issue(
    issuer: JsValue,
    seed: &[u8],
    request: JsValue,
    phone_number: &[u8],
) -> JsValue
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let issuer: SignalIssuer = ok_or_return!(issuer.into_serde());
    let req: SignalCredentialRequest = ok_or_return!(request.into_serde());
    let issuance: SignalCredentialIssuance = ok_or_return!(issuer.issue(&req, &phone_number, &mut csprng));

    ok_or_return!(JsValue::from_serde(&issuance))
}

/// Check a `presentation` of a `SignalUser`'s credential.
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
/// * `presentation` is a `SignalCredentialPresentation` as a `JsValue`.
///
/// # Returns
///
/// If successfullly verified, returns a `VerifiedSignalCredential` as a
/// `JsValue`.  Otherwise, returns a single byte set to `0`.
///
#[wasm_bindgen]
pub fn issuer_verify(
    issuer: JsValue,
    presentation: JsValue,
) -> JsValue
{
    let issuer: SignalIssuer = ok_or_return!(issuer.into_serde());
    let presentation: SignalCredentialPresentation = ok_or_return!(presentation.into_serde());
    let verified: VerifiedSignalCredential = ok_or_return!(issuer.verify(presentation));

    ok_or_return!(JsValue::from_serde(&verified))
}

/// Check if a user is an owner in a Signal group.
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
/// * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
///   may be obtained via `issuer_verify()`.
/// * `roster` is a `GroupMembershipRoster` as a `JsValue`.
///
/// # Returns
///
/// `true` if the user is an owner in the group, `false` otherwise.
#[wasm_bindgen]
pub fn issuer_verify_roster_membership_owner(
    issuer: JsValue,
    verified_credential: JsValue,
    roster: JsValue,
) -> bool
{
    let issuer: SignalIssuer = ok_or_false!(issuer.into_serde());
    let verified: VerifiedSignalCredential = ok_or_false!(verified_credential.into_serde());
    let roster: GroupMembershipRoster = ok_or_false!(roster.into_serde());

    ok_or_false!(issuer.verify_roster_membership(&verified, &roster, &GroupMembershipLevel::Owner));

    true
}

/// Check if a user is an admin in a Signal group.
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
/// * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
///   may be obtained via `issuer_verify()`.
/// * `roster` is a `GroupMembershipRoster` as a `JsValue`.
///
/// # Returns
///
/// `true` if the user is an admin in the group, `false` otherwise.
#[wasm_bindgen]
pub fn issuer_verify_roster_membership_admin(
    issuer: JsValue,
    verified_credential: JsValue,
    roster: JsValue,
) -> bool
{
    let issuer: SignalIssuer = ok_or_false!(issuer.into_serde());
    let verified: VerifiedSignalCredential = ok_or_false!(verified_credential.into_serde());
    let roster: GroupMembershipRoster = ok_or_false!(roster.into_serde());

    ok_or_false!(issuer.verify_roster_membership(&verified, &roster, &GroupMembershipLevel::Admin));

    true
}

/// Check if a user is a user-level member in a Signal group.
///
/// # Inputs
///
/// * `issuer` is a `SignalIssuer` as a `JsValue`.
/// * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
///   may be obtained via `issuer_verify()`.
/// * `roster` is a `GroupMembershipRoster` as a `JsValue`.
///
/// # Returns
///
/// `true` if the user is an user in the group, `false` otherwise.
#[wasm_bindgen]
pub fn issuer_verify_roster_membership_user(
    issuer: JsValue,
    verified_credential: JsValue,
    roster: JsValue,
) -> bool
{
    let issuer: SignalIssuer = ok_or_false!(issuer.into_serde());
    let verified: VerifiedSignalCredential = ok_or_false!(verified_credential.into_serde());
    let roster: GroupMembershipRoster = ok_or_false!(roster.into_serde());

    ok_or_false!(issuer.verify_roster_membership(&verified, &roster, &GroupMembershipLevel::User));

    true
}

/// Create a new `SignalUser`.
///
/// # Inputs
///
/// * `system_parameters` are a globally agreed upon set of
///   `aeonflux::parameters::SystemParameters`, which may be obtained via
///   `system_parameters_create()`.
/// * `keypair` is optionally an `aeonflux::elgamal::Keypair` as a `JsValue` if
///   the credential issuer supports blinded issuance, otherwise it may be
///   `JsValue::from(0)` in order to signify that the user has no keypair.
/// * `phone_number` is the `SignalUser`'s phone number as bytes, e.g.
///   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
/// * `issuer_parameters` is an `aeonflux::amacs::PublicKey` as a `JsValue`,
///   which can be obtained by calling `issuer_get_issuer_parameters()`.
/// * `seed` must be a byte array with length 32, containing random bytes for
///   seeding a CSPRNG.
///
/// # Returns
///
/// A `SignalUser` as a `JsValue` if successful, otherwise a single byte set to `0`.
///
#[wasm_bindgen]
pub fn user_new(
    system_parameters: JsValue,
    keypair: JsValue,  // may optionally be JsValue::from(0) in order to signify NULL
    phone_number: &[u8],
    issuer_parameters: JsValue,
    seed: &[u8],
) -> JsValue
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let system_params: SystemParameters = ok_or_return!(system_parameters.into_serde());
    let issuer_params: IssuerParameters = ok_or_return!(issuer_parameters.into_serde());

    // The key is optional so we have to handle it more manually:
    let key: Option<elgamal::Keypair>;

    if keypair == JsValue::from(0) {
        key = None;
    } else {
        key = Some(ok_or_return!(keypair.into_serde()))
    }

    let user: SignalUser = ok_or_return!(SignalUser::new(system_params, issuer_params, key,
                                                         phone_number, &mut csprng));

    ok_or_return!(JsValue::from_serde(&user))
}

/// Create a request for a new credential from the issuer.
///
/// # Inputs
///
/// * `user` a `SignalUser` as a `JsValue`.
///
/// # Returns
///
/// A `SignalCredentialRequest` as a `JsValue`.
///
#[wasm_bindgen]
pub fn user_obtain(
    user: JsValue,
) -> JsValue
{
    let user: SignalUser = ok_or_return!(user.into_serde());
    let request: SignalCredentialRequest = user.obtain();

    ok_or_return!(JsValue::from_serde(&request))
}

/// Check the proof of correct issuance on a credential issuance and potentially
/// save the credential for later use.
///
/// # Inputs
///
/// * `user` a `SignalUser` as a `JsValue`.
/// * `issuance` is a `SignalCredentialIssuance` as a `JsValue`, which is
///   obtainable via `issuer_issue()`.
///
/// # Returns
///
/// The updated `SignalUser` as a `JsValue` if successful, otherwise a single
/// byte set to `0`.  (This new `SignalUser` should be used later, since it has
/// the ability to present its credential.)
///
#[wasm_bindgen]
pub fn user_obtain_finish(
    user: JsValue,
    issuance: JsValue,
) -> JsValue
{
    let mut user: SignalUser = ok_or_return!(user.into_serde());
    let issuance: SignalCredentialIssuance = ok_or_return!(issuance.into_serde());

    ok_or_return!(user.obtain_finish(Some(&issuance)));

    ok_or_return!(JsValue::from_serde(&user))
}

/// Present a user's credential to the issuer for verification.
///
/// # Inputs
///
/// * `user` a `SignalUser` as a `JsValue`.
/// * `seed` must be a byte array with length 32, containing random bytes for
///   seeding a CSPRNG.
///
/// # Returns
///
/// A `SignalCredentialPresentation` as a `JsValue`.
///
#[wasm_bindgen]
pub fn user_show(
    user: JsValue,
    seed: &[u8],
) -> JsValue
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let user: SignalUser = ok_or_return!(user.into_serde());
    let presentation: SignalCredentialPresentation = ok_or_return!(user.show(&mut csprng));

    ok_or_return!(JsValue::from_serde(&presentation))
}
