// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

// We denote group elements with capital and scalars with lowercased names.
#![allow(non_snake_case)]

use aeonflux::amacs::{self, Tag};
use aeonflux::credential::CredentialPresentation;
use aeonflux::credential::CredentialRequest;
use aeonflux::credential::EncryptedAttribute;
use aeonflux::elgamal::{self};
use aeonflux::errors::CredentialError;
use aeonflux::issuer::IssuerParameters;
use aeonflux::nonces::Nonces;
use aeonflux::parameters::NUMBER_OF_ATTRIBUTES;
use aeonflux::parameters::SystemParameters;
use aeonflux::pedersen::{self, Commitment};
use aeonflux::user::User;
use aeonflux::proofs::valid_credential;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand_core::RngCore;
use rand_core::CryptoRng;

use zkp::Transcript;

use credential::PRESENTATION_NUMBER_OF_BLINDED_ATTRIBUTES;
use credential::SignalCredentialBlindIssuance;
use credential::SignalCredentialBlindRequest;
use credential::SignalCredentialIssuance;
use credential::SignalCredentialPresentation;
use credential::SignalCredentialRequest;
use credential::SignalCredential;
use phone_number::CommittedPhoneNumber;
use phone_number::EncryptedPhoneNumber;
use phone_number::PhoneNumber;
use proofs::blind_attributes;
use proofs::blind_issuance;
use proofs::revealed_attributes;
use proofs::roster_membership;
use roster::SIZEOF_ROSTER_ENTRY;
use roster::GroupRosterKey;
use roster::RosterEntry;

/// DOCDOC
#[derive(Debug, Eq, PartialEq)]
pub struct SignalUser {
    pub roster_entry: RosterEntry,
    roster_entry_opening: Scalar,
    phone_number: PhoneNumber,
    pub user: User,
}

impl SignalUser {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignalUser, CredentialError> {
        const RE: usize = SIZEOF_ROSTER_ENTRY;

        let roster_entry = RosterEntry::from_bytes(&bytes[00..RE])?;

        let mut tmp: [u8; 32] = [0u8; 32];

        tmp.copy_from_slice(&bytes[RE..RE+32]);

        let roster_entry_opening = Scalar::from_canonical_bytes(tmp)?;
        let phone_number = PhoneNumber::from_bytes(&bytes[RE+32..RE+64])?;
        let user = User::from_bytes(&bytes[RE+64..])?;

        Ok(SignalUser { roster_entry, roster_entry_opening, phone_number, user })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();

        v.extend(self.roster_entry.to_bytes());
        v.extend(self.roster_entry_opening.to_bytes().iter());
        v.extend(self.phone_number.to_bytes());
        v.extend(self.user.to_bytes());

        v
    }
}

impl SignalUser {
    /// DOCDOC
    pub fn new<R>(
        system_parameters: SystemParameters,
        issuer_parameters: IssuerParameters,
        key: Option<elgamal::Keypair>,
        phone_number: &[u8],
        csprng: &mut R,
    ) -> Result<SignalUser, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        let user = User::new(system_parameters, issuer_parameters, key);

        // Map our phone number to a scalar mod ell.
        let number: PhoneNumber = PhoneNumber::try_from_bytes(&phone_number)?;

        let transcript = Transcript::new(b"SIGNAL USER NEW");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(csprng);

        // Create our roster entry.
        let opening = Scalar::random(&mut csprng);
        let commitment = CommittedPhoneNumber::from_phone_number(&number,
                                                                 &opening,
                                                                 &system_parameters.g,
                                                                 &system_parameters.h);
        // XXX Do actual encryption with a real key here
        let roster_key = GroupRosterKey([0u8; 32]);
        let roster_entry = RosterEntry::new(&commitment, &number, &opening, &roster_key);

        Ok(SignalUser {
            user: user,
            phone_number: number,
            roster_entry: roster_entry,
            roster_entry_opening: opening,
        })
    }

    /// DOCDOC
    ///
    /// # Returns
    ///
    pub fn obtain(
        &self,
    ) -> SignalCredentialRequest
    {
        let mut transcript = Transcript::new(b"SIGNAL ISSUANCE REQUEST");

        // Construct a proof that the roster entry is in fact a commitment to our phone_number.
        let secrets = revealed_attributes::Secrets {
            nonce: &self.roster_entry_opening,
            phone_number: &self.phone_number.0,
        };
        let publics = revealed_attributes::Publics {
            g: &self.user.system_parameters.g,
            h: &self.user.system_parameters.h,
            roster_entry_commitment_number: &self.roster_entry.committed_phone_number.0.into(),
        };
        let proof = revealed_attributes::Proof::create(&mut transcript, publics, secrets);
        let request = self.user.obtain(vec![self.phone_number.0]);

        SignalCredentialRequest {
            request: request,
            proof: proof,
            roster_entry: self.roster_entry,
        }
    }

    /// DOCDOC
    pub fn obtain_finish(
        &mut self,
        // XXX the Option is probably unnecessary, we never call this with None
        //     because the FFI bails before that.
        issuance: Option<&SignalCredentialIssuance>,
    ) -> Result<(), CredentialError>
    {
        self.user.obtain_finish(issuance)
    }

    /// Show proof of membership in a roster of signal group users.
    ///
    /// DOCDOC
    pub fn show<R>(
        &self,
        rng: &mut R,
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

        let mut roster_membership_transcript = Transcript::new(b"SIGNAL GROUP MEMBERSHIP");
        let roster_membership_secrets = roster_membership::Secrets {
            m0: &credential.attributes[0],
            z0: &nonces[0].0,
            nonce: &self.roster_entry_opening,
        };
        let roster_membership_publics = roster_membership::Publics {
            B: &self.user.system_parameters.g,
            A: &self.user.system_parameters.h,
            P: &presentation.rerandomized_nonce.clone(),
            Cm0: &presentation.attributes_blinded[0].into(),
            RosterEntryPhoneNumberCommitment: &self.roster_entry.committed_phone_number.0.into(),
        };
        let roster_membership_proof = roster_membership::Proof::create(&mut roster_membership_transcript,
                                                                       roster_membership_publics,
                                                                       roster_membership_secrets);

        // XXX Should we be rerandomizing the roster_entry commitment?  The
        //     encryptions won't be rerandomisable, so I believe this should be
        //     unnecessary.
        Ok(SignalCredentialPresentation {
            presentation: presentation,
            roster_entry: self.roster_entry.clone(),
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
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer: SignalIssuer = SignalIssuer::create(system_parameters, &mut issuer_rng);
        let issuer_parameters: IssuerParameters = issuer.issuer.keypair.public.clone();
        let alice_phone_number_input: &[u8] = &[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4];
        let alice: SignalUser = SignalUser::new(system_parameters,
                                                issuer_parameters.clone(),
                                                None, // no encrypted attributes so the key isn't needed
                                                alice_phone_number_input.clone(),
                                                &mut alice_rng).unwrap();

        let serialized = alice.to_bytes();
        let deserialized = SignalUser::from_bytes(&serialized).unwrap();

        assert!(deserialized == alice);
    }
}
