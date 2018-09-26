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
use aeonflux::amacs::IssuerParameters;
use aeonflux::credential::CredentialPresentation;
use aeonflux::credential::CredentialRequest;
use aeonflux::credential::EncryptedAttribute;
use aeonflux::elgamal::{self};
use aeonflux::errors::CredentialError;
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

use credential::PRESENTATION_NUMBER_OF_HIDDEN_ATTRIBUTES;
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
use roster::GroupRosterKey;
use roster::RosterEntry;

/// DOCDOC
pub struct SignalUser {
    pub user: User,
    pub roster_entry: Option<RosterEntry>,
    roster_entry_opening: Option<Scalar>,
    phone_number: String,
}

impl SignalUser {
    /// DOCDOC
    pub fn new(
        system_parameters: SystemParameters,
        issuer_parameters: IssuerParameters,
        key: Option<elgamal::Keypair>,
        phone_number: String,
    ) -> SignalUser
    {
        let user = User::new(system_parameters, issuer_parameters, key);

        SignalUser {
            user: user,
            phone_number: phone_number,
            roster_entry: None,
            roster_entry_opening: None,
        }
    }

    /// DOCDOC
    ///
    /// # Returns
    ///
    pub fn obtain<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<SignalCredentialRequest, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        let mut transcript = Transcript::new(b"SIGNAL ISSUANCE REQUEST");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(rng);

        // Map our phone number to a scalar mod ell.
        let number: PhoneNumber = PhoneNumber::try_from_string(&self.phone_number)?;

        // Create our roster entry.
        let opening = Scalar::random(&mut csprng);
        let commitment = CommittedPhoneNumber::from_phone_number(&number, &opening,
                                                                 &self.user.system_parameters.g,
                                                                 &self.user.system_parameters.h);
        let roster_key = GroupRosterKey([1u8; 32]); // XXX
        let roster_entry = RosterEntry::new(&commitment, &number, &opening, &roster_key);

        self.roster_entry_opening = Some(opening);
        self.roster_entry = Some(roster_entry);

        // Construct a proof that the roster entry is in fact a commitment to our phone_number.
        let secrets = revealed_attributes::Secrets {
            nonce: &opening,
            phone_number: &number.0,
        };
        let publics = revealed_attributes::Publics {
            g: &self.user.system_parameters.g,
            h: &self.user.system_parameters.h,
            roster_entry_commitment_number: &roster_entry.committed_phone_number.0.into(),
        };
        let proof = revealed_attributes::Proof::create(&mut transcript, publics, secrets);
        let request = self.user.obtain(vec![number.0]);

        Ok(SignalCredentialRequest {
            request: request,
            proof: proof,
            roster_entry: roster_entry,
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

    /// Show proof of membership in a roster of signal group users.
    ///
    /// DOCDOC
    pub fn show<R>(&self, rng: &mut R) -> Result<SignalCredentialPresentation, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        let credential: &SignalCredential = match self.user.credential {
            Some(ref x) => x,
            None        => return Err(CredentialError::MissingData),
        };
        let (presentation, nonces) = self.user.show(rng)?;

        let roster_entry: RosterEntry = match self.roster_entry {
            None        => return Err(CredentialError::MissingData),
            Some(ref x) => x.clone(),
        };
        let mut roster_membership_transcript = Transcript::new(b"SIGNAL GROUP MEMBERSHIP");
        let roster_membership_secrets = roster_membership::Secrets {
            m0: &credential.attributes[0],
            z0: &nonces[0],
            nonce: &self.roster_entry_opening?,
        };
        let roster_membership_publics = roster_membership::Publics {
            B: &self.user.system_parameters.g,
            A: &self.user.system_parameters.h,
            P: &presentation.rerandomized_nonce.clone(),
            Cm0: &presentation.attributes_blinded[0].into(),
            RosterEntryPhoneNumberCommitment: &roster_entry.committed_phone_number.0.into(),
        };
        let roster_membership_proof = roster_membership::Proof::create(&mut roster_membership_transcript,
                                                                       roster_membership_publics,
                                                                       roster_membership_secrets);

        Ok(SignalCredentialPresentation {
            presentation: presentation,
            roster_entry: roster_entry.clone(),
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
