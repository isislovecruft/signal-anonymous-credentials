// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use aeonflux::amacs::{self};
use aeonflux::credential::CredentialRequest;
use aeonflux::credential::RevealedAttribute;
use aeonflux::errors::CredentialError;
use aeonflux::issuer::Issuer;
pub use aeonflux::issuer::IssuerParameters;
pub use aeonflux::issuer::IssuerSecretKey;
use aeonflux::parameters::SystemParameters;
use aeonflux::proofs::committed_values_equal;

use merlin::Transcript;

use rand_core::RngCore;
use rand_core::CryptoRng;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use credential::NUMBER_OF_ATTRIBUTES;
use credential::SignalCredentialIssuance;
use credential::SignalCredentialPresentation;
use credential::VerifiedSignalCredential;
use phone_number::CommittedPhoneNumber;
use phone_number::PhoneNumber;

/// An issuer and honest verifier of `SignalCredential`s.
#[repr(C)]
pub struct SignalIssuer {
    pub issuer: Issuer,
}

impl SignalIssuer {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignalIssuer, CredentialError> {
        Ok(SignalIssuer {
            issuer: Issuer::from_bytes(bytes)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.issuer.to_bytes()
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SignalIssuer,
                                         "A valid byte sequence representing a SignalIssuer");

impl SignalIssuer {
    /// Create a new `SignalIssuer` with new key material.
    pub fn create<R>(
        system_parameters: SystemParameters,
        csprng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        SignalIssuer {
            issuer: Issuer::create(system_parameters, csprng),
        }
    }

    /// Initialise a new `SignalIssuer` from some agreed upon `system_parameters` and a
    /// `keypair`.
    ///
    /// # Inputs
    ///
    /// * `system_parameters` are a set of `SystemParameters` containing the
    ///   distinguished basepoints, `G` and `H`.
    /// * `keypair` is an `amacs::Keypair`.
    pub fn new(
        system_parameters: SystemParameters,
        keypair: amacs::Keypair,
    ) -> Self
    {
        SignalIssuer {
            issuer: Issuer::new(system_parameters, keypair),
        }
    }

    /// Get an owned copy of this `SignalIssuer`'s public aMAC key material.
    pub fn get_issuer_parameters(&self) -> IssuerParameters {
        self.issuer.get_issuer_parameters()
    }

    /// Unblinded credential issuance.
    ///
    /// # Note
    ///
    /// While the issuer can see all the credential attributes upon issuance if
    /// using this method, it does not necessarily see all attributes upon
    /// presentation.
    ///
    /// # Inputs
    ///
    /// * `phone_number` is the the user's phone number as bytes, e.g. the phone
    ///   number `"+14155551234"` should be given as
    ///   `[0, 0, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
    /// * `rng` is an implementation of `rand::RngCore + rand::CryptoRng`.
    ///
    /// # Errors
    ///
    /// This method may return the following errors:
    ///
    /// * `CredentialError::NoIssuerParameters` if this `SignalIssuer`'s
    ///   `issuer_parameters` didn't contain the correct length of public key.
    /// * `CredentialError::NoIssuerKey` if this `SignalIssuer`'s secret `key`
    ///   was not the correct length.
    /// * `CredentialError::MissingData` if the user's supplied phone number (as
    ///   a `String`) could not be successfully converted into a `PhoneNumber`
    ///   as a `Scalar`.
    /// * `CredentialError::VerificationFailure` if the `request`'s `proof`
    ///   couldn't be verified.
    ///
    /// # Returns
    ///
    /// A `SignalCredentialRequest` upon successful issuance.
    pub fn issue<R>(
        &self,
        phone_number: &[u8],
        rng: &mut R,
    ) -> Result<SignalCredentialIssuance, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        // Construct the phone number and form a credential out of it.
        let number: PhoneNumber = PhoneNumber::try_from_bytes(&phone_number)?;
        let mut attributes_revealed: Vec<RevealedAttribute> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES);

        attributes_revealed.push(number.0);

        let request: CredentialRequest = CredentialRequest { attributes_revealed };

        self.issuer.issue(&request, rng)
    }

    pub fn verify(&self, signal_presentation: SignalCredentialPresentation)
        -> Result<VerifiedSignalCredential, CredentialError>
    {
        self.issuer.verify(&signal_presentation.presentation)?;

        Ok(VerifiedSignalCredential(signal_presentation))
    }

    /// # Note
    ///
    /// If the proof is okay, the issuer MUST still check that the returned
    /// `roster_entry_commitment` is actually in the desired roster at the
    /// correct permissions level.
    pub fn verify_roster_membership(
        &self,
        credential: &VerifiedSignalCredential,
    ) -> Result<CommittedPhoneNumber, CredentialError>
    {
        let publics = committed_values_equal::Publics {
            B: &self.issuer.system_parameters.g,
            A: &self.issuer.system_parameters.h,
            P: &credential.0.presentation.rerandomized_nonce,
            Cm0: &credential.0.presentation.attributes_blinded[0].clone().into(),
            Cm1: &credential.0.roster_entry_commitment.0.into(),
        };
        let mut transcript = Transcript::new(b"SIGNAL GROUP MEMBERSHIP");

        if credential.0.roster_membership_proof.verify(&mut transcript, publics).is_ok() {
            Ok(credential.0.roster_entry_commitment)
        } else {
            Err(CredentialError::VerificationFailure)
        }
    }
}

impl SignalIssuer {
    // /// DOCDOC
    // pub fn blind_issue(&self, request: SignalCredentialBlindRequest)
    //     -> Result<SignalCredentialBlindIssuance, CredentialError>
    // {
    //     // Create a transcript and feed the context into it
    //     let mut transcript = Transcript::new(b"SIGNAL BLIND ISSUANCE");
    //     // XXX Put the revealed_attributes and encrypted_attributes into the transcript here via a
    //     //     transcript extension.
    // 
    //     let blind_attributes_proof: blind_attributes::Proof;
    //     let encrypted_attributes: Vec<EncryptedAttribute> = match request.encrypted_attributes {
    //         Some(x) => x,
    //         None    => vec![],
    //     };
    //     let revealed_attributes: Vec<RevealedAttribute> = match request.revealed_attributes {
    //         Some(x) => x,
    //         None    => vec![],
    //     };
    // 
    //     // Determine if we should verify the proof of correct blind attribute formation first
    //     if encrypted_attributes.len() > 0 {
    //         // Return an error if there were encrypted attributes without a corresponding proof.
    //         blind_attributes_proof = request.blind_attributes_proof?;
    // 
    //         if encrypted_attributes.len() != ISSUANCE_NUMBER_OF_HIDDEN_ATTRIBUTES * 2 {
    //             return Err(CredentialError::WrongNumberOfAttributes);
    //         }
    // 
    //         let publics: blind_attributes::Publics = blind_attributes::Publics {
    //             B: &self.issuer.system_parameters.g,
    //             A: &self.issuer.system_parameters.h,
    //             D: &request.public_key.into(),
    //             // The first two "attributes" are the commitment and encryption for the elGamal
    //             // encryption of the user's phone number.  These form one actual attribute, but
    //             // the zkp macro doesn't currently understand tuples, so we have to break up the
    //             // pieces of the proof.
    //             encrypted_attribute_0_0: &encrypted_attributes[0].commitment,
    //             encrypted_attribute_0_1: &encrypted_attributes[1].encryption,
    //             // The second two are the elGamal commitment and encryption of the length of the
    //             // user's phone number, which is used to ensure that the mapping of scalars to
    //             // users is injective.
    //             encrypted_attribute_1_0: &encrypted_attributes[2].commitment,
    //             encrypted_attribute_1_1: &encrypted_attributes[3].encryption,
    //             roster_entry: &request.roster_entry.into(),
    //         };
    // 
    //         // Check that the ciphertexts were correctly formed and made with the user's public key
    //         if blind_attributes_proof.verify(&mut transcript, publics).is_err() {
    //             return Err(CredentialError::MacVerification);
    //         }
    //     }
    // 
    //     // Choose a blinding factor, \\( b \in ZZ \mod \ell \\).
    //     let mut csprng = transcript.fork_transcript().reseed_from_rng(&mut thread_rng());
    //     let b: Scalar = Scalar::random(&mut csprng);
    // 
    //     // Compute P = b * B (labelled "u" in CMZ'13, but "P" in LdV'17).
    //     let P: RistrettoPoint = &self.issuer.system_parameters.g * &b; // XXX use basepoint table
    // 
    //     // Compute a partial aMAC on the revealed attribute, if any exist.
    //     //
    //     //      Q_{H^{c}} ← ( x0 + \sigma{i \in H}{mi xi}) P
    //     //
    //     // This part isn't ever defined in CMZ'13, but is explicitly detailed in §4.2 of LdV'17,
    //     // so we default to the latter's notation.  (It's vaguely labelled "u'" in CMZ'13 but it's
    //     // never mentioned how to compute a partial aMAC over the revealed attributes before
    //     // moving on to the encrypted attributes.)
    //     let mut QHc: RistrettoPoint = RistrettoPoint::identity();
    // 
    //     // XXX Benchmark to see if the computation speeds up if we keep Q as a scalar until the
    //     //     final basepoint multiplication.  Also, again, tables.
    //     if revealed_attributes.len() > 0 {
    //         if revealed_attributes.len() != ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES {
    //             return Err(CredentialError::WrongNumberOfAttributes);
    //         }
    // 
    //         QHc = &self.key.x0 * &P;
    // 
    //         for (index, attribute) in revealed_attributes.iter().enumerate() {
    //             let key: Scalar = self.keypair.secret.xn[index];
    //             QHc += attribute * &(&P * &key);
    //         }
    //     }
    // 
    //     let mut csprng = transcript.fork_transcript().reseed_from_rng(&mut thread_rng());
    //     // XXX Feed the revealed attributes if there were any into this transcript before forking.
    // 
    //     // Encrypt the partial aMAC on the revealed attributes to the user's public key.
    //     let s: Scalar = Scalar::random(&mut csprng);
    //     let pk: RistrettoPoint = request.public_key.into();
    //     let EQHc: elgamal::Encryption = elgamal::Encryption { commitment: QHc,
    //                                                           encryption: &s * &pk };
    //     // XXX By encrypting regardless of whether a the blind_attributes_proof was present, we're
    //     //     missing the ZKPoK that the user does in fact control the corresponding secret key.
    //     //     Does this matter?
    // 
    //     // Compute the remainder of the aMAC over the encrypted attributes, if any, using the
    //     // randomness used to produce P=b*g.
    //     //
    //     //     Enc_D(QH) ← \sigma{i \in H}{xi b Enc_D(mi B)}
    //     let mut EQH: elgamal::Encryption = elgamal::Encryption {
    //         commitment: P,
    //         encryption: RistrettoPoint::identity(),
    //     };
    // 
    //     // XXX Again, benchmarks needed here, for the same reason as above.
    //     if encrypted_attributes.len() > 0 {
    //         for (index, attribute) in encrypted_attributes.iter().enumerate() {
    //             EQH.encryption += attribute.encryption * &(&self.keypair.secret.xn[index] * &b);
    //         }
    //     }
    // 
    //     // Use the additive homomorphism in elGamal encryption to produce the final aMAC. This is:
    //     //
    //     //     Enc_D(Q) ← Enc_D(QHc) + Enc_D(QH)
    //     //
    //     // where
    //     //
    //     //     Q = (x0 + \sigma(i \in H) xi mi) P
    //     let EQ: elgamal::Encryption = &EQHc + &EQH;
    // 
    //     // Pick some blinding factors for the zero-knowledge proofs:
    //     let x0_tilde: Scalar = Scalar::random(&mut csprng);
    // 
    //     // Form some auxiliary commitments to hide secret products in the proofs:
    //     let t0: Scalar = &b * &self.keypair.secret.xn[0];
    //     let t1: Scalar = &b * &self.keypair.secret.xn[1];
    //     let T0: RistrettoPoint = &t0 * &self.issuer.system_parameters.h;
    //     let T1: RistrettoPoint = &t1 * &self.issuer.system_parameters.h;
    // 
    //     // Form a NIPK showing that we issued the credential correctly, the encrypted aMAC was
    //     // encrypted to the user's public key, the decryption of the encrypted aMAC was produced
    //     // with the secret key corresponding to the issuer's known public key, and the system
    //     // parameters are as expected.
    //     let secrets = blind_issuance::Secrets {
    //         x0_tilde: &x0_tilde,
    //         x0: &self.key.x0,
    //         x1: &self.keypair.secret.xn[0],
    //         x2: &self.keypair.secret.xn[1],
    //         s: &s,
    //         b: &b,
    //         t0: &t0,
    //         t1: &t1,
    //     };
    // 
    //     let publics = blind_issuance::Publics {
    //         B: &self.issuer.system_parameters.g,
    //         A: &self.issuer.system_parameters.h,
    //         X0: &self.issuer.issuer_parameters.Xn[0],
    //         X1: &self.issuer.issuer_parameters.Xn[1],
    //         X2: &self.issuer.issuer_parameters.Xn[2],
    //         D: &request.public_key.into(),
    //         P: &P,
    //         T0_0: &T0,
    //         T0_1: &T0,
    //         T1_0: &T1,
    //         T1_1: &T1,
    //         EQ_commitment: &EQ.commitment,
    //         EQ_encryption: &EQ.encryption,
    //         encrypted_attribute_0_0: &encrypted_attributes[0].commitment,
    //         encrypted_attribute_0_1: &encrypted_attributes[1].encryption,
    //         encrypted_attribute_1_0: &encrypted_attributes[2].commitment,
    //         encrypted_attribute_1_1: &encrypted_attributes[3].encryption,
    //     };
    // 
    //     let proof = blind_issuance::Proof::create(&mut transcript, publics, secrets);
    // 
    //     Ok(SignalCredentialBlindIssuance {
    //         proof: proof,
    //         blinding_commitment: P,
    //         auxiliary_commitments: vec![T0, T1],
    //         encrypted_mac: EQ,
    //         revealed_attributes: revealed_attributes.clone(),
    //         encrypted_attributes: encrypted_attributes.clone(),
    //     })
    // }
}
