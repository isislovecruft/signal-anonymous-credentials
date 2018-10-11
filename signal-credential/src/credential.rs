// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of CMZ'13 MAC_GGM based anonymous credentials for Signal.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use aeonflux::credential::SIZEOF_CREDENTIAL_PRESENTATION;
use aeonflux::credential::Credential;
use aeonflux::credential::CredentialBlindRequest;
use aeonflux::credential::CredentialBlindIssuance;
use aeonflux::credential::CredentialIssuance;
use aeonflux::credential::CredentialPresentation;
use aeonflux::credential::CredentialRequest;
use aeonflux::credential::VerifiedCredential;
use aeonflux::errors::CredentialError;
use aeonflux::proofs::committed_values_equal;
use aeonflux::proofs::valid_credential;

use bincode::{deserialize, serialize};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use proofs::revealed_attributes;

use roster::SIZEOF_ROSTER_ENTRY;
use roster::RosterEntry;

/// The number of revealed attributes on a `SignalCredential` during issuance.
pub const ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES: usize = 1;

/// The number of encrypted attributes on a `SignalCredential` during issuance.
pub const ISSUANCE_NUMBER_OF_BLINDED_ATTRIBUTES: usize = 0;

/// The number of revealed attributes on a `SignalCredential` during presentation.
pub const PRESENTATION_NUMBER_OF_REVEALED_ATTRIBUTES: usize = 0;

/// The number of encrypted attributes on a `SignalCredential` during presentation.
pub const PRESENTATION_NUMBER_OF_BLINDED_ATTRIBUTES: usize = 1;

/// The total number of attributes on a `SignalCredentia`.
pub const NUMBER_OF_ATTRIBUTES: usize =
    ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES +
    ISSUANCE_NUMBER_OF_BLINDED_ATTRIBUTES;

/// A request from a `SignalUser` for a `SignalCredential`, optionally
/// containing revealed and encrypted attributes.  If there are encrypted
/// attributes, they must be accompanied by a proof that they are correctly
/// formed with respect to the `SignalUser`'s `public_key, an elGamal encryption
/// public key.
#[derive(Debug, Eq, PartialEq)]
pub struct SignalCredentialBlindRequest {
    /// If the `request` has `encrypted_attributes` it must also contain a
    /// zero-knowledge proof showing that:
    ///
    /// 1. the `encrypted_attributes` were created with the user's public key,
    /// 2. the user knows the corresponding secret key, and
    /// 3. the commitment in the user's `roster_entry` opens to the same plaintext
    ///    attribute as in the encryption.
    ///
    /// The `blind_attributes_proof` is required if there are `encrypted_attributes`.
    pub request: CredentialBlindRequest,
    pub roster_entry: RosterEntry,
}

pub struct SignalCredentialBlindIssuance {
    pub issuance: CredentialBlindIssuance,
}

#[derive(Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SignalCredentialRequest {
    pub roster_entry: RosterEntry,
    pub request: CredentialRequest,
    pub proof: revealed_attributes::Proof,
}

impl SignalCredentialRequest {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignalCredentialRequest, CredentialError> {
        const RE: usize = SIZEOF_ROSTER_ENTRY;

        let roster_entry = RosterEntry::from_bytes(&bytes[00..RE])?;
        let request = CredentialRequest::from_bytes(&bytes[RE..RE + NUMBER_OF_ATTRIBUTES * 32])?;

        let proof: revealed_attributes::Proof = match deserialize(&bytes[RE + NUMBER_OF_ATTRIBUTES * 32..]) {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("Error while deserializing SignalCredentialRequest: {}", _x);
                return Err(CredentialError::MissingData);
            },
        };

        Ok(SignalCredentialRequest { roster_entry, request, proof })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // XXX What is the sizeof the proof?
        let mut v: Vec<u8> = Vec::with_capacity(SIZEOF_ROSTER_ENTRY + NUMBER_OF_ATTRIBUTES * 32);

        v.extend(self.roster_entry.to_bytes());
        v.extend(self.request.to_bytes());

        let serialized = match serialize(&self.proof) {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("Error while serializing SignalCredentialRequest: {}", _x);
                panic!();  // XXX clean this up
            },
        };

        v.extend(serialized);
        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SignalCredentialRequest,
                                         "A valid byte sequence representing a SignalCredentialRequest");

pub type SignalCredentialIssuance = CredentialIssuance;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalCredentialPresentation {
    /// The user's corresponding `RosterEntry` in the `GroupMembershipRoster`.
    pub roster_entry: RosterEntry,
    /// A `CredentialPresentation` showing that this credential is valid.
    pub presentation: CredentialPresentation,
    /// Create a zero-knowledge proof showing that if the aMAC on our
    /// credential verifies successfully, that the underlying value in the
    /// commitment to our credential attribute is the same as the underlying
    /// committed value in a `GroupMembershipRoster`.
    pub roster_membership_proof: committed_values_equal::Proof,
}

impl SignalCredentialPresentation {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignalCredentialPresentation, CredentialError> {
        const RE: usize = SIZEOF_ROSTER_ENTRY;

        if bytes.len() < RE + SIZEOF_CREDENTIAL_PRESENTATION {
            #[cfg(feature = "std")]
            println!("The SignalCredentialPresentation bytes were not long enough, got {} bytes", bytes.len());
            return Err(CredentialError::MissingData);
        }

        let roster_entry = RosterEntry::from_bytes(&bytes[00..RE])?;
        let presentation = CredentialPresentation::from_bytes(&bytes[RE..RE+SIZEOF_CREDENTIAL_PRESENTATION])?;

        let roster_membership_proof: committed_values_equal::Proof =
            match deserialize(&bytes[RE+SIZEOF_CREDENTIAL_PRESENTATION..])
        {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("Error while deserializing SignalCredentialPresentation: {}", _x);
                return Err(CredentialError::MissingData);
            },
        };

        Ok(SignalCredentialPresentation { roster_entry, presentation, roster_membership_proof })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(1000); // XXX

        v.extend(self.roster_entry.to_bytes());
        v.extend(self.presentation.to_bytes());

        let serialized = match serialize(&self.roster_membership_proof) {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("Error while serializing SignalCredentialPresentation: {}", _x);
                panic!();  // XXX clean this up
            },
        };

        v.extend(serialized);
        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SignalCredentialPresentation,
                                         "A valid byte sequence representing a SignalCredentialPresentation");

/// An anonymous credential belonging to a `SignalUser` and issued and verified
/// by a `SignalIssuer`.
pub type SignalCredential = Credential;

/// A `SignalCredential` which has already been verified.
///
/// # Note
///
/// This type is used to cause the additional proof methods called by the issuer
/// to only be callable if the issuer has previously successfully called
/// `SignalIssuer.verify()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignalCredential(pub(crate) SignalCredentialPresentation);

impl VerifiedSignalCredential {
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifiedSignalCredential, CredentialError> {
        Ok(VerifiedSignalCredential(SignalCredentialPresentation::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl_serde_with_to_bytes_and_from_bytes!(VerifiedSignalCredential,
                                         "A valid byte sequence representing a VerifiedSignalCredential");

#[cfg(test)]
mod test {
    use super::*;

    use aeonflux::credential::RevealedAttribute;
    use aeonflux::nonces::Nonces;

    use issuer::SignalIssuer;
    use issuer::IssuerParameters;
    use parameters::SystemParameters;
    use user::SignalUser;

    use rand::thread_rng;

    #[test]
    fn verified_credential_serialize_deserialize() {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::hunt_and_peck(&mut issuer_rng);
        let issuer: SignalIssuer = SignalIssuer::create(system_parameters, &mut issuer_rng);
        let issuer_parameters: IssuerParameters = issuer.get_issuer_parameters();
        let alice_phone_number_input: &[u8] = &[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4];
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no enncrypted attributes so the key isn't needed
                                                    alice_phone_number_input.clone(),
                                                    &mut alice_rng).unwrap();
        let alice_request: SignalCredentialRequest = alice.obtain();
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request,
                                                                    &alice_phone_number_input,
                                                                    &mut issuer_rng).unwrap();

        alice.obtain_finish(Some(&alice_issuance)).unwrap();

        let alice_presentation: SignalCredentialPresentation = alice.show(&mut alice_rng).unwrap();
        let verified: VerifiedSignalCredential = issuer.verify(alice_presentation).unwrap();

        let serialized = verified.to_bytes();
        let deserialized = VerifiedSignalCredential::from_bytes(&serialized);

        assert!(deserialized.is_ok());
        assert!(deserialized.unwrap() == verified);
    }
}
