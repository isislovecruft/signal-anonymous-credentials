// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of CMZ'13 MAC_GGM based anonymous credentials with one attribute.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use amacs::SIZEOF_TAG;
use amacs::Tag;

use bincode::{deserialize, serialize};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;

use elgamal;

use parameters::NUMBER_OF_ATTRIBUTES;

use pedersen;

use errors::CredentialError;

use proofs::attributes_blinded;
use proofs::issuance_blinded;
use proofs::issuance_revealed;
use proofs::valid_credential;

pub const SIZEOF_CREDENTIAL: usize = SIZEOF_TAG + NUMBER_OF_ATTRIBUTES * 32;
pub const SIZEOF_CREDENTIAL_PRESENTATION: usize = 256;

/// The number of revealed attributes on a `Credential` during issuance.
pub const ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES: usize = 1;

/// The number of encrypted attributes on a `Credential` during issuance.
pub const ISSUANCE_NUMBER_OF_HIDDEN_ATTRIBUTES: usize = 0;

/// The number of revealed attributes on a `Credential` during presentation.
pub const PRESENTATION_NUMBER_OF_REVEALED_ATTRIBUTES: usize = 0;

/// The number of encrypted attributes on a `Credential` during presentation.
pub const PRESENTATION_NUMBER_OF_BLINDED_ATTRIBUTES: usize = 1;

/// A plaintext attribute that is revealed to the issuer when requesting a
/// credential.
pub type RevealedAttribute = Scalar;

/// An elGamal-encrypted attribute that is hidden to the issuer when requesting
/// a credential.
pub type EncryptedAttribute = elgamal::Encryption;

/// An anonymous credential belonging to a user and issued and verified
/// by an issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Credential {
    /// The non-interactive zero knowledge proof that this credential is
    /// well-formed.
    pub mac: Tag,
    /// A vector of unencrypted attributes, which may later be hidden upon
    /// presentation.
    pub attributes: Vec<RevealedAttribute>,
}

impl Credential {
    pub fn from_bytes(bytes: &[u8]) -> Result<Credential, CredentialError> {
        let length: usize = bytes.len();

        // The bytes must be a multiple of 32 and at least 96 bytes.
        if length % 32 != 0 || length < 96 || length != SIZEOF_CREDENTIAL {
            return Err(CredentialError::WrongNumberOfBytes);
        }
        let mac: Tag = Tag::from_bytes(&bytes[00..64])?;
        let mut attributes: Vec<RevealedAttribute> = Vec::with_capacity((length - 64) / 32);

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in bytes[64..].chunks(32) {
            let mut tmp: [u8; 32] = [0u8;32];

            tmp.copy_from_slice(chunk);

            match Scalar::from_canonical_bytes(tmp) {
                Some(x) => attributes.push(x),
                None    => return Err(CredentialError::ScalarFormatError),
            }
        }

        Ok(Credential { mac, attributes })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64 + 32 * self.attributes.len());

        v.extend(self.mac.to_bytes());

        for attribute in self.attributes.iter() {
            v.extend(attribute.to_bytes().iter());
        }

        v
    }
}

/// A request from a user for a `Credential`, optionally
/// containing revealed and encrypted attributes.  If there are encrypted
/// attributes, they must be accompanied by a proof that they are correctly
/// formed with respect to the `User`'s `public_key, an elGamal encryption
/// public key.
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

#[derive(Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CredentialRequest {
    pub attributes_revealed: Vec<RevealedAttribute>,
}

impl CredentialRequest {
    pub fn from_bytes(bytes: &[u8]) -> Result<CredentialRequest, CredentialError> {
        let length: usize = bytes.len();

        // The bytes must be a multiple of 32.
        if length % 32 != 0 {
            return Err(CredentialError::WrongNumberOfBytes);
        }

        let mut attributes_revealed: Vec<RevealedAttribute> = Vec::with_capacity(length % 32);

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in bytes.chunks(32) {
            let mut tmp: [u8; 32] = [0u8;32];

            tmp.copy_from_slice(chunk);

            match Scalar::from_canonical_bytes(tmp) {
                Some(x) => attributes_revealed.push(x),
                None    => return Err(CredentialError::ScalarFormatError),
            }
        }

        Ok(CredentialRequest { attributes_revealed })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32 * self.attributes_revealed.len());

        for attribute in self.attributes_revealed.iter() {
            v.extend(attribute.to_bytes().iter());
        }

        v
    }
}

#[derive(Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CredentialIssuance {
    pub secret_key_commitment: pedersen::Commitment,
    pub credential: Credential,
    pub proof: issuance_revealed::Proof,
}

impl CredentialIssuance {
    pub fn from_bytes(bytes: &[u8]) -> Result<CredentialIssuance, CredentialError> {
        let secret_key_commitment = pedersen::Commitment::from_bytes(&bytes[00..32])?;
        let credential = Credential::from_bytes(&bytes[32..32+SIZEOF_CREDENTIAL])?;
        
        let proof: issuance_revealed::Proof = match deserialize(&bytes[32+SIZEOF_CREDENTIAL..]) {
            Ok(x)   => x,
            Err(_x) => {
                // println!("Error while deserializing CredentialIssuance: {}", _x);
                return Err(CredentialError::MissingData);
            },
        };

        Ok(CredentialIssuance { secret_key_commitment, credential, proof })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32 + SIZEOF_CREDENTIAL); // XXX what size is the proof?

        v.extend(self.secret_key_commitment.to_bytes());
        v.extend(self.credential.to_bytes());

        let serialized = match serialize(&self.proof) {
            Ok(x)   => x,
            Err(_x) => {
                // println!("Error while serializing CredentialIssuance: {}", _x);
                panic!();  // XXX clean this up
            },
        };

        v.extend(serialized);
        v
    }
}

#[derive(Clone, Eq, PartialEq)]
#[repr(C)]
pub struct CredentialPresentation {
    /// A Pedersen commitment to the rerandomised `mac` value in the
    /// `amacs::Tag` on a `User`'s `Credential`.
    pub rerandomized_mac_commitment: pedersen::Commitment,
    /// A rerandomised nonce for an algebraic MAC.
    pub rerandomized_nonce: RistrettoPoint,
    /// A vector of revealed attributes for this credential presentation.
    pub attributes_revealed: Vec<RevealedAttribute>,
    /// A vector of hidden attributes for this credential presentation.
    pub attributes_blinded: Vec<pedersen::Commitment>,
    /// A zero-knowledge proof showing that the user knows a valid rerandomised
    /// algebraic MAC over the `attributes_revealed` and `attributes_blinded`
    /// which was created by the `Issuer`.
    pub proof: valid_credential::Proof,
}

impl CredentialPresentation {
    pub fn from_bytes(bytes: &[u8]) -> Result<CredentialPresentation, CredentialError> {
        let length: usize = bytes.len();

        // The bytes must be a multiple of 32.
        if length % 32 != 0 {
            return Err(CredentialError::WrongNumberOfBytes);
        }

        let rerandomized_mac_commitment = pedersen::Commitment::from_bytes(&bytes[00..32])?;

        let mut tmp: [u8; 32] = [0u8; 32];
        tmp.copy_from_slice(&bytes[32..64]);
        let rerandomized_nonce = CompressedRistretto(tmp).decompress()?;

        let attributes_offset: usize = 32 * (PRESENTATION_NUMBER_OF_REVEALED_ATTRIBUTES + PRESENTATION_NUMBER_OF_BLINDED_ATTRIBUTES);
        let mut attributes_revealed: Vec<RevealedAttribute> = Vec::with_capacity(PRESENTATION_NUMBER_OF_REVEALED_ATTRIBUTES);
        let mut attributes_blinded: Vec<pedersen::Commitment> = Vec::with_capacity(PRESENTATION_NUMBER_OF_BLINDED_ATTRIBUTES);
        let mut attributes_processed: usize = 0;

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in (&bytes[64..64 + attributes_offset]).chunks(32) {
            if attributes_processed < PRESENTATION_NUMBER_OF_REVEALED_ATTRIBUTES {
                let mut tmp: [u8; 32] = [0u8;32];

                tmp.copy_from_slice(chunk);

                match Scalar::from_canonical_bytes(tmp) {
                    Some(x) => attributes_revealed.push(x),
                    None    => return Err(CredentialError::ScalarFormatError),
                }
            } else {
                match pedersen::Commitment::from_bytes(chunk) {
                    Ok(x)  => attributes_blinded.push(x),
                    Err(_) => return Err(CredentialError::PointDecompressionError),
                }
            }
            attributes_processed += 1;
        }

        let proof: valid_credential::Proof = match deserialize(&bytes[64+attributes_offset..]) {
            Ok(x)   => x,
            Err(_x) => {
                // println!("Error while deserializing CredentialPresentation: {}", _x);
                return Err(CredentialError::MissingData);
            },
        };

        Ok(CredentialPresentation {
            rerandomized_mac_commitment,
            rerandomized_nonce,
            attributes_revealed,
            attributes_blinded,
            proof,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(1000);

        v.extend(self.rerandomized_mac_commitment.to_bytes());          // 32 bytes
        v.extend(self.rerandomized_nonce.compress().to_bytes().iter()); // 32 bytes

        for attribute in self.attributes_revealed.iter() {              // 32 * 0 bytes
            v.extend(attribute.to_bytes().iter());
        }
        for attribute in self.attributes_blinded.iter() {               // 32 * 1 bytes
            v.extend(attribute.to_bytes());
        }

        let serialized = match serialize(&self.proof) {
            Ok(x)   => x,
            Err(_x) => {
                // println!("Error while serializing CredentialPresentation: {}", _x);
                panic!();  // XXX clean this up
            },
        };

        v.extend(serialized);
        v
    }
}

/// A `Credential` which has already been verified.
///
/// # Note
///
/// This type is used to cause the additional proof methods called by the issuer
/// to only be callable if the issuer has previously successfully called
/// `Issuer.verify()`.
#[derive(Clone, Eq, PartialEq)]
#[repr(C)]
pub struct VerifiedCredential(pub CredentialPresentation);

impl VerifiedCredential {
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifiedCredential, CredentialError> {
        Ok(VerifiedCredential(CredentialPresentation::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use issuer::Issuer;
    use issuer::IssuerParameters;
    use nonces::Nonces;
    use parameters::SystemParameters;
    use user::User;

    use rand::thread_rng;

    const H: [u8; 32] = [ 154, 189, 169, 176, 131,  12,  78, 199,
                          127,   4, 178,  70, 212, 141, 119, 112,
                          153, 154, 135,  11, 227, 132, 247,  47,
                           68, 192,  72, 200,  23,  88,  51,  82, ];

    #[test]
    fn credential_presentation_serialize_deserialize() {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer: Issuer = Issuer::create(system_parameters, &mut issuer_rng);
        let issuer_parameters: IssuerParameters = issuer.get_issuer_parameters();
        let mut alice: User = User::new(system_parameters,
                                        issuer_parameters.clone(),
                                        None); // no encrypted attributes so the key isn't needed
        let mut alice_attributes: Vec<RevealedAttribute> = Vec::new();
        alice_attributes.push(Scalar::random(&mut alice_rng));
        let alice_request: CredentialRequest = alice.obtain(alice_attributes);
        let alice_issuance: CredentialIssuance = issuer.issue(&alice_request, &mut issuer_rng).unwrap();

        alice.obtain_finish(Some(&alice_issuance)).unwrap();

        let alice_nonces: Nonces = Nonces::new(&mut alice_rng, NUMBER_OF_ATTRIBUTES);
        let alice_presentation: CredentialPresentation = alice.show(&alice_nonces, &mut alice_rng).unwrap();

        let serialized = alice_presentation.to_bytes();
        let deserialized = CredentialPresentation::from_bytes(&serialized);

        assert!(deserialized.is_ok());
        assert!(deserialized.unwrap() == alice_presentation);
    }

    #[test]
    fn verified_credential_serialize_deserialize() {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer: Issuer = Issuer::create(system_parameters, &mut issuer_rng);
        let issuer_parameters: IssuerParameters = issuer.get_issuer_parameters();
        let mut alice: User = User::new(system_parameters,
                                        issuer_parameters.clone(),
                                        None); // no encrypted attributes so the key isn't needed
        let mut alice_attributes: Vec<RevealedAttribute> = Vec::new();
        alice_attributes.push(Scalar::random(&mut alice_rng));
        let alice_request: CredentialRequest = alice.obtain(alice_attributes);
        let alice_issuance: CredentialIssuance = issuer.issue(&alice_request, &mut issuer_rng).unwrap();

        alice.obtain_finish(Some(&alice_issuance)).unwrap();

        let alice_nonces: Nonces = Nonces::new(&mut alice_rng, NUMBER_OF_ATTRIBUTES);
        let alice_presentation: CredentialPresentation = alice.show(&alice_nonces, &mut alice_rng).unwrap();

        let verified: VerifiedCredential = issuer.verify(&alice_presentation).unwrap();

        let serialized = verified.to_bytes();
        let deserialized = VerifiedCredential::from_bytes(&serialized);

        assert!(deserialized.is_ok());
        assert!(deserialized.unwrap() == verified);
    }
}
