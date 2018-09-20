// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of CMZ'13 MAC_GGM based anonymous credentials for Signal.

use amacs::Tag;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use elgamal;

use pedersen;

use proofs::blind_attributes;
use proofs::blind_issuance;
use proofs::issuance;
use proofs::revealed_attributes;
use proofs::roster_membership;

use roster::RosterEntry;

/// The number of revealed attributes on a `SignalCredential` during issuance.
pub const ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES: usize = 1;

/// The number of encrypted attributes on a `SignalCredential` during issuance.
pub const ISSUANCE_NUMBER_OF_HIDDEN_ATTRIBUTES: usize = 0;

/// The number of revealed attributes on a `SignalCredential` during presentation.
pub const PRESENTATION_NUMBER_OF_REVEALED_ATTRIBUTES: usize = 0;

/// The number of encrypted attributes on a `SignalCredential` during presentation.
pub const PRESENTATION_NUMBER_OF_HIDDEN_ATTRIBUTES: usize = 1;

/// The total number of attributes on a `SignalCredentia`.
pub const NUMBER_OF_ATTRIBUTES: usize =
    ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES +
    ISSUANCE_NUMBER_OF_HIDDEN_ATTRIBUTES;

/// A plaintext attribute that is revealed to the issuer when requesting a
/// credential.
pub type RevealedAttribute = Scalar;

/// An elGamal-encrypted attribute that is hidden to the issuer when requesting
/// a credential.
pub type EncryptedAttribute = elgamal::Encryption;

/// A request from a `SignalUser` for a `SignalCredential`, optionally
/// containing revealed and encrypted attributes.  If there are encrypted
/// attributes, they must be accompanied by a proof that they are correctly
/// formed with respect to the `SignalUser`'s `public_key, an elGamal encryption
/// public key.
pub struct SignalCredentialBlindRequest {
    /// An optional vector of credential attributes which are revealed to the issuer.
    pub revealed_attributes: Option<Vec<RevealedAttribute>>,
    /// An optional vector of credential attributes which are hidden to the issuer.
    pub encrypted_attributes: Option<Vec<EncryptedAttribute>>,
    /// An optional zero-knowledge proof showing that:
    ///
    /// 1. the `encrypted_attributes` were created with the user's public key,
    /// 2. the user knows the corresponding secret key, and
    /// 3. the commitment in the user's `roster_entry` opens to the same plaintext
    ///    attribute as in the encryption.
    ///
    /// The `blind_attributes_proof` is required if there are `encrypted_attributes`.
    pub blind_attributes_proof: Option<blind_attributes::Proof>,
    /// The user's elGamal public key.
    pub public_key: elgamal::PublicKey,
    /// The user's `RosterEntry`.
    pub roster_entry: RosterEntry,
}

pub struct SignalCredentialBlindIssuance {
    pub proof: blind_issuance::Proof,
    pub blinding_commitment: RistrettoPoint,
    pub auxiliary_commitments: Vec<RistrettoPoint>,
    pub encrypted_mac: elgamal::Encryption,
    /// DOCDOC
    pub revealed_attributes: Vec<RevealedAttribute>,
    /// DOCDOC
    pub encrypted_attributes: Vec<EncryptedAttribute>,
}

pub struct SignalCredentialRequest {
    pub proof: revealed_attributes::Proof,
    pub phone_number: String,
    pub roster_entry: RosterEntry,
}

pub struct SignalCredentialIssuance {
    pub proof: issuance::Proof,
    pub credential: SignalCredential,
    pub secret_key_commitment: RistrettoPoint,
}

pub struct SignalCredentialPresentation {
    /// A zero-knowledge proof showing that the user knows a valid rerandomised
    /// algebraic MAC over the `revealed_attributes` and `hidden_attributes`
    /// which was created by the `SignalIssuer`.
    pub proof: roster_membership::Proof,
    /// A Pedersen commitment to the rerandomised `mac` value in the
    /// `amacs::Tag` on a `SignalUser`'s `SignalCredential`.
    pub rerandomized_mac_commitment: pedersen::Commitment,
    /// A rerandomised nonce for an algebraic MAC.
    pub rerandomized_nonce: RistrettoPoint,
    /// A vector of revealed attributes for this credential presentation.
    pub revealed_attributes: Vec<RevealedAttribute>,
    /// A vector of hidden attributes for this credential presentation.
    pub hidden_attributes: Vec<pedersen::Commitment>,
    /// The user's corresponding `RosterEntry` in the `GroupMembershipRoster`.
    pub roster_entry: RosterEntry,
}

/// An anonymous credential belonging to a `SignalUser` and issued and verified
/// by a `SignalIssuer`.
#[derive(Clone, Debug)]
pub struct SignalCredential {
    /// The non-interactive zero knowledge proof that this credential is
    /// well-formed.
    pub mac: Tag,
    /// A vector of unencrypted attributes, which may later be hidden upon
    /// presentation.
    pub attributes: Vec<RevealedAttribute>,
}
