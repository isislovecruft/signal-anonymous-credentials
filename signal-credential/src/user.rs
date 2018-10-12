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

use aeonflux::elgamal::{self};
use aeonflux::errors::CredentialError;
use aeonflux::issuer::IssuerParameters;
use aeonflux::nonces::Nonces;
use aeonflux::parameters::NUMBER_OF_ATTRIBUTES;
use aeonflux::parameters::SystemParameters;
use aeonflux::user::User;
use aeonflux::proofs::committed_values_equal;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use merlin::Transcript;

use rand_core::RngCore;
use rand_core::CryptoRng;

use credential::SignalCredentialIssuance;
use credential::SignalCredentialPresentation;
use credential::SignalCredential;
use phone_number::PhoneNumber;
use phone_number::RosterEntryCommitment;

/// DOCDOC
#[derive(Debug, Eq, PartialEq)]
pub struct SignalUser {
    pub phone_number: PhoneNumber,
    pub user: User,
}

impl SignalUser {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignalUser, CredentialError> {
        let phone_number = PhoneNumber::from_bytes(&bytes[00..32])?;
        let user = User::from_bytes(&bytes[32..])?;

        Ok(SignalUser { phone_number, user })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();

        v.extend(self.phone_number.to_bytes());
        v.extend(self.user.to_bytes());

        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SignalUser,
                                         "A valid byte sequence representing a SignalUser");

impl SignalUser {
    /// DOCDOC
    pub fn new(
        system_parameters: SystemParameters,
        issuer_parameters: IssuerParameters,
        key: Option<elgamal::Keypair>,
        phone_number: &[u8],
    ) -> Result<SignalUser, CredentialError>
    {
        let user = User::new(system_parameters, issuer_parameters, key);

        // Map our phone number to a scalar mod ell.
        let number: PhoneNumber = PhoneNumber::try_from_bytes(&phone_number)?;

        Ok(SignalUser {
            user: user,
            phone_number: number,
        })
    }

    /// DOCDOC
    pub fn obtain_finish(
        &mut self,
        issuance: Option<&SignalCredentialIssuance>,
    ) -> Result<(), CredentialError>
    {
        self.user.obtain_finish(issuance)
    }

    /// Prove that this credential is valid and show proof of membership in a
    /// roster of signal group users.
    ///
    /// DOCDOC
    pub fn show<R>(
        &self,
        rng: &mut R,
        roster_entry_commitment: &RosterEntryCommitment,
    ) -> Result<SignalCredentialPresentation, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        let credential: &SignalCredential = match self.user.credential {
            Some(ref x) => x,
            None        => return Err(CredentialError::MissingData),
        };
        let nonces = Nonces::new(rng, NUMBER_OF_ATTRIBUTES);
        let presentation = self.user.show(&nonces, rng)?;

        // Create a zero-knowledge proof showing that if the aMAC on our
        // credential verifies successfully, that the underlying value in the
        // commitment to our credential attribute is the same as the underlying
        // committed value in a group roster entry.
        let mut roster_membership_transcript = Transcript::new(b"SIGNAL GROUP MEMBERSHIP");
        let roster_membership_secrets = committed_values_equal::Secrets {
            m0: &credential.attributes[0],
            z0: (&nonces[0]).into(),
            z1: (&roster_entry_commitment.opening).into(),
        };
        let roster_membership_publics = committed_values_equal::Publics {
            B: &self.user.system_parameters.g,
            A: &self.user.system_parameters.h,
            P: &presentation.rerandomized_nonce.clone(),
            Cm0: &presentation.attributes_blinded[0].into(),
            Cm1: &roster_entry_commitment.commitment.0.into(),
        };
        let roster_membership_proof = committed_values_equal::Proof::create(&mut roster_membership_transcript,
                                                                            roster_membership_publics,
                                                                            roster_membership_secrets);

        Ok(SignalCredentialPresentation {
            presentation: presentation,
            roster_entry_commitment: roster_entry_commitment.commitment.clone(),
            roster_membership_proof: roster_membership_proof,
        })
    }
}

impl SignalUser {
    // /// Create a credential with some encrypted attributes and a non-interactive
    // /// zero-knowledge proof of the correctness of the encrypted attributes, and
    // /// send both along with the `SignalUser`'s `key` to the `SignalIssuer`.
    // fn blind_obtain(
    //     &self
    // ) -> Result<SignalCredentialBlindRequest, CredentialError>
    // {
    //     let mut transcript = Transcript::new(b"SIGNAL BLIND ISSUANCE");
    //     let mut csprng = transcript.fork_transcript().reseed_from_rng(&mut thread_rng());
    // 
    //     let key: elgamal::Keypair = self.key?;
    //     let e0: elgamal::Ephemeral = Scalar::random(&mut csprng).into();
    //     let e1: elgamal::Ephemeral = Scalar::random(&mut csprng).into();
    // 
    //     let phone_number: PhoneNumber = PhoneNumber::try_from_string(&self.phone_number)?;
    //     let encrypted_phone_number: EncryptedPhoneNumber = phone_number.encrypt(&key, &e0, &e1);
    //     let encrypted_attributes: Vec<EncryptedAttribute> = encrypted_phone_number.clone().into();
    // 
    //     // Create our roster entry.
    //     let opening = Scalar::random(&mut csprng);
    //     let commitment = CommittedPhoneNumber::from_phone_number(&phone_number,
    //                                                              &opening,
    //                                                              &self.user.system_parameters.g,
    //                                                              &self.user.system_parameters.h);
    //     let roster_key = GroupRosterKey([1u8; 32]); // XXX
    //     self.roster_entry_opening = Some(roster_entry_opening);
    //     self.roster_entry = Some(RosterEntry::new(&committed_phone_number,
    //                                               &phone_number,
    //                                               &self.roster_entry_opening,
    //                                               &roster_key));
    // 
    //     let secrets: blind_attributes::Secrets = blind_attributes::Secrets {
    //         d: &key.secret.clone().into(),
    //         e0: &e0.0,
    //         e1: &e1.0,
    //         m0: &phone_number.number,
    //         m1: &Scalar::from(phone_number.length as u64),
    //         nonce: &self.roster_entry_opening?,
    //     };
    //     let publics: blind_attributes::Publics = blind_attributes::Publics {
    //         B: &self.user.system_parameters.g,
    //         A: &self.user.system_parameters.h,
    //         D: &key.public.into(),
    //         encrypted_attribute_0_0: &encrypted_phone_number.number.commitment,
    //         encrypted_attribute_0_1: &encrypted_phone_number.number.encryption,
    //         encrypted_attribute_1_0: &encrypted_phone_number.length.commitment,
    //         encrypted_attribute_1_1: &encrypted_phone_number.length.encryption,
    //         roster_entry: &roster_entry.into(),
    //     };
    // 
    //     let proof = blind_attributes::Proof::create(&mut transcript, publics, secrets);
    // 
    //     Ok(SignalCredentialBlindRequest {
    //         revealed_attributes: None,
    //         encrypted_attributes: Some(encrypted_attributes),
    //         blind_attributes_proof: Some(proof),
    //         public_key: key.public,
    //         roster_entry: roster_entry,
    //     })
    // }
    // 
    // /// DOCDOC
    // fn blind_obtain_finish(&mut self, issuance: Option<SignalCredentialBlindIssuance>)
    //     -> Result<(), CredentialError>
    // {
    //     let issue: SignalCredentialBlindIssuance = match issuance {
    //         Some(i) => i,
    //         None    => return Err(CredentialError::CredentialIssuance),
    //     };
    //     let key: elgamal::Keypair = self.key?;
    // 
    //     // Create a transcript.
    //     let mut transcript = Transcript::new(b"SIGNAL BLIND ISSUE");
    // 
    //     let publics = blind_issuance::Publics {
    //         B: &self.user.system_parameters.g,
    //         A: &self.user.system_parameters.h,
    //         X0: &self.user.issuer_parameters.Xn[0],
    //         X1: &self.user.issuer_parameters.Xn[1],
    //         X2: &self.user.issuer_parameters.Xn[2],
    //         D: &key.public.into(),
    //         P: &issue.blinding_commitment,
    //         T0_0: &issue.auxiliary_commitments[0],
    //         T0_1: &issue.auxiliary_commitments[0],
    //         T1_0: &issue.auxiliary_commitments[1],
    //         T1_1: &issue.auxiliary_commitments[1],
    //         EQ_commitment: &issue.encrypted_mac.commitment,
    //         EQ_encryption: &issue.encrypted_mac.encryption,
    //         encrypted_attribute_0_0: &issue.encrypted_attributes[0].commitment,
    //         encrypted_attribute_0_1: &issue.encrypted_attributes[1].encryption,
    //         encrypted_attribute_1_0: &issue.encrypted_attributes[2].commitment,
    //         encrypted_attribute_1_1: &issue.encrypted_attributes[3].encryption,
    //     };
    // 
    //     // Verify that the credential was issued correctly, the encrypted aMAC was
    //     // encrypted to the our's public key, the decryption of the encrypted aMAC was produced
    //     // with the secret key corresponding to the issuer's known public key, and the system
    //     // parameters are as expected.
    //     if issue.proof.verify(&mut transcript, publics).is_err() {
    //         return Err(CredentialError::CredentialIssuance);
    //     }
    // 
    //     // Decrypt the Q part of the encrypted tag (P, Q') to produce the tag.
    //     let decryption: RistrettoPoint = key.secret.decrypt(&issue.encrypted_mac);
    //     let tag: amacs::Tag = amacs::Tag {
    //         nonce: issue.blinding_commitment,
    //         mac: decryption,
    //     };
    // 
    //     unimplemented!()
    // }
}

#[cfg(test)]
mod test {
    use super::*;

    use issuer::SignalIssuer;

    use rand::thread_rng;

    const H: [u8; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                          93, 125, 218,  60,  36, 165, 166, 178,
                          118, 188,  77,  27, 133, 146, 193, 133,
                          234,  95,  69, 227, 213, 197,  84,  98, ];

    #[test]
    fn signal_user_serialize_deserialize() {
        let mut issuer_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer: SignalIssuer = SignalIssuer::create(system_parameters, &mut issuer_rng);
        let issuer_parameters: IssuerParameters = issuer.issuer.keypair.public.clone();
        let alice_phone_number_input: &[u8] = &[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4];
        let alice: SignalUser = SignalUser::new(system_parameters,
                                                issuer_parameters.clone(),
                                                None, // no encrypted attributes so the key isn't needed
                                                alice_phone_number_input.clone()).unwrap();

        let serialized = alice.to_bytes();
        let deserialized = SignalUser::from_bytes(&serialized).unwrap();

        assert!(deserialized == alice);
    }
}
