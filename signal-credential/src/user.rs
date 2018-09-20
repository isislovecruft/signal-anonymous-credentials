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

use amacs;
use amacs::IssuerParameters;
use amacs::SecretKey;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use elgamal;

use pedersen;

use rand::thread_rng;

use zkp::Transcript;

use credential::PRESENTATION_NUMBER_OF_HIDDEN_ATTRIBUTES;
use credential::SignalCredentialBlindIssuance;
use credential::SignalCredentialBlindRequest;
use credential::SignalCredentialIssuance;
use credential::SignalCredentialPresentation;
use credential::SignalCredentialRequest;
use credential::EncryptedAttribute;
use credential::SignalCredential;
use errors::CredentialError;
use parameters::SystemParameters;
use phone_number::CommittedPhoneNumber;
use phone_number::EncryptedPhoneNumber;
use phone_number::PhoneNumber;
use proofs::blind_attributes;
use proofs::blind_issuance;
use proofs::issuance;
use proofs::revealed_attributes;
use proofs::roster_membership;
use roster::GroupRosterKey;
use roster::RosterEntry;

/// DOCDOC
pub struct SignalUser {
    pub system_parameters: SystemParameters,
    pub issuer_parameters: IssuerParameters,
    key: Option<elgamal::Keypair>,
    phone_number: String,
    credential: Option<SignalCredential>,
    pub roster_entry: Option<RosterEntry>,
    roster_entry_opening: Option<Scalar>,
}

// impl CredentialUser for SignalUser {
//     type Issuer = SignalIssuer;
//     type Credential = SignalCredential;

impl SignalUser {
    /// DOCDOC
    pub fn new(
        system_parameters: SystemParameters,
        issuer_parameters: IssuerParameters,
        key: Option<elgamal::Keypair>,
        phone_number: String,
    ) -> SignalUser
    {
        SignalUser{
            system_parameters: system_parameters,
            issuer_parameters: issuer_parameters,
            key: key,
            phone_number: phone_number,
            credential: None,
            roster_entry: None,
            roster_entry_opening: None,
        }
    }

    /// DOCDOC
    ///
    /// # Returns
    ///
    pub fn obtain(&mut self) -> Result<SignalCredentialRequest, CredentialError> {
        let mut transcript = Transcript::new(b"SIGNAL ISSUANCE REQUEST");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(&mut thread_rng());

        // Map our phone number to a scalar mod ell.
        let number: PhoneNumber = PhoneNumber::try_from_string(&self.phone_number)?;

        // Create our roster entry.
        let opening = Scalar::random(&mut csprng);
        let commitment = CommittedPhoneNumber::from_phone_number(&number, &opening,
                                                                 &self.system_parameters.g,
                                                                 &self.system_parameters.h);
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
            g: &self.system_parameters.g,
            h: &self.system_parameters.h,
            roster_entry_commitment_number: &roster_entry.committed_phone_number.0.into(),
        };
        let proof = revealed_attributes::Proof::create(&mut transcript, publics, secrets);

        Ok(SignalCredentialRequest {
            proof: proof,
            phone_number: self.phone_number.clone(),
            roster_entry: roster_entry,
        })
    }

    /// DOCDOC
    pub fn obtain_finish(
        &mut self,
        issuance: Option<&SignalCredentialIssuance>,
    ) -> Result<(), CredentialError>
    {
        let mut transcript = Transcript::new(b"SIGNAL ISSUANCE");

        let issue: &SignalCredentialIssuance = match issuance {
            Some(i) => i,
            None    => return Err(CredentialError::CredentialIssuance),
        };
        let X1: RistrettoPoint = match self.issuer_parameters.Xn.get(0) {
            None => return Err(CredentialError::NoIssuerParameters),
            Some(x) => *x,
        };

        let publics: issuance::Publics = issuance::Publics {
            P: &issue.credential.mac.nonce,
            Q: &issue.credential.mac.mac,
            Cx0: &issue.secret_key_commitment,
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X1: &X1,
        };

        if issue.proof.verify(&mut transcript, publics).is_err() {
            println!("there was an error verifying the issuance proof");
            Err(CredentialError::CredentialIssuance)
        } else {
            self.credential = Some(issue.credential.clone());

            Ok(())
        }
    }

    /// Show proof of membership in a roster of signal group users.
    ///
    /// DOCDOC
    pub fn show(&self) -> Result<SignalCredentialPresentation, CredentialError> {
        let credential: &SignalCredential = match self.credential {
            Some(ref x) => x,
            None        => return Err(CredentialError::MissingData),
        };

        let mut transcript = Transcript::new(b"SIGNAL SHOW");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(&mut thread_rng());

        const N_ATTRIBUTES: usize = PRESENTATION_NUMBER_OF_HIDDEN_ATTRIBUTES;

        // Rerandomise the aMAC to prevent trivial linkages.
        //
        // XXX do we want to pass in a merlin transcript instead of using the rng here?
        let rerandomized_mac: amacs::Tag = amacs::Rerandomization::new().apply_to_tag(&credential.mac);

        let A = self.system_parameters.h;
        let B = self.system_parameters.g;
        let P = rerandomized_mac.nonce;
        let Q = rerandomized_mac.mac;

        // Commit to the rerandomised aMAC.
        let zQ: Scalar = Scalar::random(&mut csprng);
        let CQ: pedersen::Commitment = pedersen::Commitment::to(&Q, &zQ, &A);

        // Commit to the hidden attributes.
        let mut nonces: Vec<Scalar> = Vec::with_capacity(N_ATTRIBUTES);
        let mut commitments: Vec<pedersen::Commitment> = Vec::with_capacity(N_ATTRIBUTES);

        for attribute in credential.attributes.iter() {
            let zi: Scalar = Scalar::random(&mut csprng);
            let miP: RistrettoPoint = attribute * P;
            let Cmi: pedersen::Commitment = pedersen::Commitment::to(&(attribute * P), &zi, &A);

            nonces.push(zi);
            commitments.push(Cmi);
        }

        // Calculate the error factor.
        let mut V: RistrettoPoint = RistrettoPoint::identity();

        for (index, zi) in nonces.iter().enumerate() {
            V += &(zi * self.issuer_parameters.Xn[index]);
        }
        V -= &zQ * &A;

        let roster_entry: RosterEntry = match self.roster_entry {
            None        => return Err(CredentialError::MissingData),
            Some(ref x) => x.clone(),
        };
        let valid_credential_secrets = valid_credential::Secrets {
            m0: &credential.attributes[0],
            z0: &nonces[0],
            minus_zQ: &-zQ,
        };
        let valid_credential_publics = valid_credential::Publics {
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X0: &self.issuer_parameters.Xn[0],
            P: &rerandomized_mac.nonce,
            V: &V,
            Cm0: &commitments[0].into(),
        };
        let valid_credential_proof = valid_credential::Proof::create(&mut transcript,
                                                                     valid_credential_publics,
                                                                     valid_credential_secrets);

        let mut roster_membership_transcript = Transcript::new(b"SIGNAL GROUP MEMBERSHIP");
        let roster_membership_secrets = roster_membership::Secrets {
            m0: &credential.attributes[0],
            z0: &nonces[0],
            nonce: &self.roster_entry_opening?,
        };
        let roster_membership_publics = roster_membership::Publics {
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            P: &rerandomized_mac.nonce,
            Cm0: &commitments[0].into(),
            RosterEntryPhoneNumberCommitment: &roster_entry.committed_phone_number.0.into(),
        };
        let roster_membership_proof = roster_membership::Proof::create(&mut roster_membership_transcript,
                                                                       roster_membership_publics,
                                                                       roster_membership_secrets);

        Ok(SignalCredentialPresentation {
            proof: valid_credential_proof,
            rerandomized_mac_commitment: CQ,
            rerandomized_nonce: rerandomized_mac.nonce,
            revealed_attributes: Vec::with_capacity(0),
            hidden_attributes: commitments,
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
    //                                                              &self.system_parameters.g,
    //                                                              &self.system_parameters.h);
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
    //         B: &self.system_parameters.g,
    //         A: &self.system_parameters.h,
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
    //         B: &self.system_parameters.g,
    //         A: &self.system_parameters.h,
    //         X0: &self.issuer_parameters.Xn[0],
    //         X1: &self.issuer_parameters.Xn[1],
    //         X2: &self.issuer_parameters.Xn[2],
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
