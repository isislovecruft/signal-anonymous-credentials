// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of CMZ'13 MAC_GGM based anonymous credentials for Signal.

use aeonflux::credential::Credential;
use aeonflux::credential::CredentialBlindRequest;
use aeonflux::credential::CredentialBlindIssuance;
use aeonflux::credential::CredentialIssuance;
use aeonflux::credential::CredentialPresentation;
use aeonflux::credential::CredentialRequest;
use aeonflux::proofs::valid_credential;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use proofs::blind_attributes;
use proofs::blind_issuance;
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

/// A request from a `SignalUser` for a `SignalCredential`, optionally
/// containing revealed and encrypted attributes.  If there are encrypted
/// attributes, they must be accompanied by a proof that they are correctly
/// formed with respect to the `SignalUser`'s `public_key, an elGamal encryption
/// public key.
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

pub struct SignalCredentialRequest {
    pub request: CredentialRequest,
    pub proof: revealed_attributes::Proof,
    pub phone_number: String,
    pub roster_entry: RosterEntry,
}

pub type SignalCredentialIssuance = CredentialIssuance;

#[derive(Clone)]
pub struct SignalCredentialPresentation {
    pub presentation: CredentialPresentation,
    /// The user's corresponding `RosterEntry` in the `GroupMembershipRoster`.
    pub roster_entry: RosterEntry,
    /// An `roster_membership::Proof` attesting that the user is in a
    /// `GroupMembershipRoster`.
    pub roster_membership_proof: roster_membership::Proof,
}

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
#[derive(Clone)]
pub struct VerifiedSignalCredential<'a>(pub(crate) &'a SignalCredentialPresentation);
