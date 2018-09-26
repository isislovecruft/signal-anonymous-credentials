// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of CMZ'13 MAC_GGM based anonymous credentials with one attribute.

use amacs::Tag;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use elgamal;

use pedersen;

use proofs::attributes_blinded;
use proofs::issuance_blinded;
use proofs::issuance_revealed;
use proofs::valid_credential;

/// A plaintext attribute that is revealed to the issuer when requesting a
/// credential.
pub type RevealedAttribute = Scalar;

/// An elGamal-encrypted attribute that is hidden to the issuer when requesting
/// a credential.
pub type EncryptedAttribute = elgamal::Encryption;

/// An anonymous credential belonging to a user and issued and verified
/// by an issuer.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(C)]
pub struct Credential {
    /// The non-interactive zero knowledge proof that this credential is
    /// well-formed.
    pub mac: Tag,
    /// A vector of unencrypted attributes, which may later be hidden upon
    /// presentation.
    pub attributes: Vec<RevealedAttribute>,
}

/// A request from a user for a `Credential`, optionally
/// containing revealed and encrypted attributes.  If there are encrypted
/// attributes, they must be accompanied by a proof that they are correctly
/// formed with respect to the `User`'s `public_key, an elGamal encryption
/// public key.
#[derive(Deserialize, Serialize)]
#[repr(C)]
pub struct CredentialBlindRequest {
    /// An optional vector of credential attributes which are revealed to the issuer.
    pub attributes_revealed: Option<Vec<RevealedAttribute>>,
    /// An optional vector of credential attributes which are hidden to the issuer.
    pub attributes_blinded: Option<Vec<EncryptedAttribute>>,
    /// An optional zero-knowledge proof showing that:
    ///
    /// 1. the `encrypted_attributes` were created with the user's public key,
    /// 2. the user knows the corresponding secret key, and
    ///
    /// The `attributes_blinded_proof` is required if there are `encrypted_attributes`.
    pub attributes_blinded_proof: Option<attributes_blinded::Proof>,
    /// The user's elGamal public key.
    pub public_key: elgamal::PublicKey,
}

/// An blinded issuance of a `Credential`.
#[derive(Deserialize, Serialize)]
#[repr(C)]
pub struct CredentialBlindIssuance {
    pub proof: issuance_blinded::Proof,
    pub blinding_commitment: RistrettoPoint,
    pub auxiliary_commitments: Vec<RistrettoPoint>,
    pub encrypted_mac: elgamal::Encryption,
    /// DOCDOC
    pub attributes_revealed: Vec<RevealedAttribute>,
    /// DOCDOC
    pub encrypted_attributes: Vec<EncryptedAttribute>,
}

#[derive(Deserialize, Serialize)]
#[repr(C)]
pub struct CredentialRequest {
    pub attributes_revealed: Vec<RevealedAttribute>,
}

#[derive(Deserialize, Serialize)]
#[repr(C)]
pub struct CredentialIssuance {
    pub proof: issuance_revealed::Proof,
    pub credential: Credential,
    pub secret_key_commitment: RistrettoPoint,
}

#[derive(Clone, Deserialize, Serialize)]
#[repr(C)]
pub struct CredentialPresentation {
    /// A zero-knowledge proof showing that the user knows a valid rerandomised
    /// algebraic MAC over the `attributes_revealed` and `attributes_blinded`
    /// which was created by the `Issuer`.
    pub proof: valid_credential::Proof,
    /// A Pedersen commitment to the rerandomised `mac` value in the
    /// `amacs::Tag` on a `User`'s `Credential`.
    pub rerandomized_mac_commitment: pedersen::Commitment,
    /// A rerandomised nonce for an algebraic MAC.
    pub rerandomized_nonce: RistrettoPoint,
    /// A vector of revealed attributes for this credential presentation.
    pub attributes_revealed: Vec<RevealedAttribute>,
    /// A vector of hidden attributes for this credential presentation.
    pub attributes_blinded: Vec<pedersen::Commitment>,
}

/// A `Credential` which has already been verified.
///
/// # Note
///
/// This type is used to cause the additional proof methods called by the issuer
/// to only be callable if the issuer has previously successfully called
/// `Issuer.verify()`.
#[derive(Clone)]
#[repr(C)]
pub struct VerifiedCredential<'a>(pub &'a CredentialPresentation);
