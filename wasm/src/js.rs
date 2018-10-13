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
use signal_credential::credential::VerifiedSignalCredential;
use signal_credential::issuer::IssuerParameters;
use signal_credential::issuer::SignalIssuer;
use signal_credential::parameters::SystemParameters;
use signal_credential::phone_number::RosterEntryCommitment;
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
    if seed.len() != 32 {
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
/// An `aeonflux::amacs::Keypair` as a `JsValue`¹.
///
/// ¹ Which, by the way, you won't be able to do much of anything with since
///   it's internally serialised to literal bytes, so best don't touch it.
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
/// * `phone_number` is the `SignalUser`'s phone number as bytes, e.g.
///   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
/// * `seed` must be a byte array with length 32, containing random
///   bytes for seeding a CSPRNG.
///
/// # Returns
///
/// A `SignalCredentialIssuance` as a `JsValue` if the credential issuance was
/// successful, otherwise a single byte set to `0`.
///
#[wasm_bindgen]
pub fn issuer_issue(
    issuer: JsValue,
    phone_number: &[u8],
    seed: &[u8],
) -> JsValue
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let issuer: SignalIssuer = ok_or_return!(issuer.into_serde());
    let issuance: SignalCredentialIssuance = ok_or_return!(issuer.issue(&phone_number, &mut csprng));

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
///
/// # Returns
///
/// The roster entry commitment, if the user's credential has a committed value
/// which matches the value in the roster entry commitment, `false` otherwise.
///
#[wasm_bindgen]
pub fn issuer_verify_roster_membership(
    issuer: JsValue,
    verified_credential: JsValue,
) -> JsValue
{
    let issuer: SignalIssuer = ok_or_return!(issuer.into_serde());
    let verified: VerifiedSignalCredential = ok_or_return!(verified_credential.into_serde());
    let roster_entry_commitment = ok_or_return!(issuer.verify_roster_membership(&verified));

    ok_or_return!(JsValue::from_serde(&roster_entry_commitment))
}

/// Check the proof of correct issuance on a credential issuance and potentially
/// save the credential for later use.
///
/// # Inputs
///
/// * `phone_number` is the `SignalUser`'s phone number as bytes, e.g.
///   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
/// * `system_parameters` are a globally agreed upon set of
///   `aeonflux::parameters::SystemParameters`, which may be obtained via
///   `system_parameters_create()`.
/// * `issuer_parameters` is an `aeonflux::amacs::PublicKey` as a `JsValue`,
///   which can be obtained by calling `issuer_get_issuer_parameters()`.
/// * `issuance` is a `SignalCredentialIssuance` as a `JsValue`, which is
///   obtainable via `issuer_issue()`.
///
/// # Returns
///
/// The `SignalUser` as a `JsValue` if successful, otherwise a single byte set
/// to `0`.
///
#[wasm_bindgen]
pub fn user_obtain_finish(
    phone_number: &[u8],
    system_parameters: JsValue,
    issuer_parameters: JsValue,
    issuance: JsValue,
) -> JsValue
{
    let system_params: SystemParameters = ok_or_return!(system_parameters.into_serde());
    let issuer_params: IssuerParameters = ok_or_return!(issuer_parameters.into_serde());
    let mut user: SignalUser = ok_or_return!(SignalUser::new(system_params, issuer_params,
                                                             None, phone_number));
    let issuance: SignalCredentialIssuance = ok_or_return!(issuance.into_serde());

    ok_or_return!(user.obtain_finish(Some(&issuance)));

    ok_or_return!(JsValue::from_serde(&user))
}

/// Present a user's credential to the issuer for verification.
///
/// # Inputs
///
/// * `user` a `SignalUser` as a `JsValue`.
/// * `roster_entry_commitment` is a commitment to the user's phone number and
///   an opening.
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
    roster_entry_commitment: JsValue,
    seed: &[u8],
) -> JsValue
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let user: SignalUser = ok_or_return!(user.into_serde());
    let entry: RosterEntryCommitment = ok_or_return!(roster_entry_commitment.into_serde());
    let presentation: SignalCredentialPresentation = ok_or_return!(user.show(&mut csprng, &entry));

    ok_or_return!(JsValue::from_serde(&presentation))
}
