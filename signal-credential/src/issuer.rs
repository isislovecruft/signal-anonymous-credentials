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
pub use amacs::IssuerParameters;
pub use amacs::SecretKey as IssuerSecretKey;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use elgamal;

use rand::thread_rng;

use zkp::Transcript;

use credential::EncryptedAttribute;
use credential::RevealedAttribute;
use credential::ISSUANCE_NUMBER_OF_HIDDEN_ATTRIBUTES;
use credential::ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES;
use credential::NUMBER_OF_ATTRIBUTES;
use credential::SignalCredential;
use credential::SignalCredentialBlindIssuance;
use credential::SignalCredentialBlindRequest;
use credential::SignalCredentialIssuance;
use credential::SignalCredentialRequest;
use credential::SignalCredentialPresentation;
use errors::CredentialError;
use parameters::SystemParameters;
use phone_number::PhoneNumber;
use proofs::blind_attributes;
use proofs::blind_issuance;
use proofs::issuance;
use proofs::revealed_attributes;
use proofs::roster_membership;
use traits::CredentialIssuer;

pub struct SignalIssuer {
    pub system_parameters: SystemParameters,
    /// The issuer's public key material.
    pub issuer_parameters: IssuerParameters,
    /// The issuer's secret key material.
    key: IssuerSecretKey,
}

impl SignalIssuer {
    pub fn new(system_parameters: SystemParameters, secret_key: Option<&IssuerSecretKey>) -> Self {
        let key: IssuerSecretKey = match secret_key {
            None    => IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES),
            Some(x) => x.clone(),
        };
        let issuer_parameters: IssuerParameters = key.get_issuer_parameters(&system_parameters.h);

        SignalIssuer{
            system_parameters: system_parameters,
            issuer_parameters: issuer_parameters,
            key: key,
        }
    }

    /// Unblinded credential issuance.
    ///
    /// # Note
    ///
    /// While the issuer can see all the credential attributes upon issuance if
    /// using this method, it does not necessarily see all attributes upon
    /// presentation.
    pub fn issue(&self, request: &SignalCredentialRequest)
        -> Result<SignalCredentialIssuance, CredentialError>
    {
        // Obtain our needed public and secret key material.
        let X1: RistrettoPoint = match self.issuer_parameters.Xn.get(0) {
            Some(x) => *x,
            None => return Err(CredentialError::NoIssuerParameters),
        };
        let x1: Scalar = match self.key.xn.get(0) {
            Some(x) => *x,
            None => return Err(CredentialError::NoIssuerKey),
        };

        // Construct the credential attributes.
        let number: PhoneNumber = PhoneNumber::try_from_string(&request.phone_number)?;
        let attributes: amacs::Message = number.into();

        // Create a transcript and feed the context into it
        let mut request_transcript = Transcript::new(b"SIGNAL ISSUANCE REQUEST");
        // XXX put the attributes into the transcript first

        // Verify the zero-knowledge proof that the roster entry is a commitment to the phone number.
        let roster_entry_commitment_number = request.roster_entry.committed_phone_number;

        let revealed_attributes_publics: revealed_attributes::Publics = revealed_attributes::Publics {
            g: &self.system_parameters.g,
            h: &self.system_parameters.h,
            roster_entry_commitment_number: &roster_entry_commitment_number.0.into(),
        };

        if request.proof.verify(&mut request_transcript, revealed_attributes_publics).is_err() {
            return Err(CredentialError::VerificationFailure);
        }

        // Create a transcript and feed the context into it
        let mut issuance_transcript = Transcript::new(b"SIGNAL ISSUANCE");

        // Calculate (u, u'), i.e. (nonce, mac)
        let tag: amacs::Tag = self.key.mac(&attributes).or(Err(CredentialError::MacCreation))?;

        // Choose a blinding factor, x~0
        let mut csprng = issuance_transcript.fork_transcript().reseed_from_rng(&mut thread_rng());
        let x0_tilde: Scalar = Scalar::random(&mut csprng);

        // Construct a commitment to the issuer secret key
        let Cx0: RistrettoPoint = (&self.system_parameters.g * &self.key.x0) +
                                  (&self.system_parameters.h * &x0_tilde);
        // XXX Could speed up the above by multiscalar_mul and generating a basepoint table

        // Construct the NIZK proof of correct issuance
        let secrets = issuance::Secrets {
            x0: &self.key.x0,
            x1: &x1,
            x0_tilde: &x0_tilde,
            m1x1: &(&attributes[0] * &x1),
        };
        let publics = issuance::Publics {
            P: &tag.nonce,
            Q: &tag.mac,
            Cx0: &Cx0,
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X1: &X1,
        };
        let proof: issuance::Proof = issuance::Proof::create(&mut issuance_transcript, publics, secrets);

        let cred: SignalCredential = SignalCredential { mac: tag.clone(),
                                                        attributes: attributes.into() };

        Ok(SignalCredentialIssuance{
            proof: proof,
            credential: cred,
            secret_key_commitment: Cx0,
        })
    }

    pub fn verify(&self, presentation: &SignalCredentialPresentation) -> Result<(), CredentialError> {
        let P = presentation.rerandomized_nonce;

        // Recompute the MAC
        let mut V_prime: RistrettoPoint = &self.key.x0 * &P;

        for (index, attribute) in presentation.revealed_attributes.iter().enumerate() {
            V_prime += (&self.key.xn[index] * attribute) * &P;
        }

        for (index, attribute) in presentation.hidden_attributes.iter().enumerate() {
            V_prime += &self.key.xn[index] * attribute;
        }
        V_prime -= presentation.rerandomized_mac_commitment;

        let mut transcript = Transcript::new(b"SIGNAL SHOW");
        let publics = roster_membership::Publics {
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X0: &self.issuer_parameters.Xn[0],
            P: &P,
            V: &V_prime,
            Cm0: &presentation.hidden_attributes[0].clone().into(), // XXX remove clones
            RosterEntryPhoneNumberCommitment: &presentation.roster_entry.committed_phone_number.0.into(),
        };

        if presentation.proof.verify(&mut transcript, publics).is_err() {
            return Err(CredentialError::MacVerification);
        }

        // XXX Do what the user asked at this point, e.g. add/remove another user, etc.
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use parameters::SystemParameters;
    use roster::GroupMembershipRoster;
    use roster::GroupRosterKey;
    use roster::RosterEntry;
    use user::SignalUser;

    const H: [u8; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                           93, 125, 218,  60,  36, 165, 166, 178,
                          118, 188,  77,  27, 133, 146, 193, 133,
                          234,  95,  69, 227, 213, 197,  84,  98, ];

    #[test]
    fn credential_issuance_and_presentation() {
        // Create an issuer
        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));

        // Get the issuer's parameters so we can advertise them to new users:
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();

        // Create a couple users
        let alice_phone_number_input: &str = "14155551234";
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    String::from(alice_phone_number_input));

        let bob_phone_number_input: &str = "14155556666";
        let mut bob: SignalUser = SignalUser::new(system_parameters,
                                                  issuer_parameters.clone(),
                                                  None, // no encrypted attributes so the key isn't needed
                                                  String::from(bob_phone_number_input));

        // Form a request for a credential
        let alice_request: SignalCredentialRequest = alice.obtain().unwrap();

        // Try to get the issuer to give Alice a new credential
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request).unwrap();

        // Give the result back to Alice for processing
        alice.obtain_finish(Some(alice_issuance));
        
        // And the same for Bob:
        let bob_request: SignalCredentialRequest = bob.obtain().unwrap();
        let bob_issuance: SignalCredentialIssuance = issuer.issue(&bob_request).unwrap();

        bob.obtain_finish(Some(bob_issuance));

        let alice_roster_entry: RosterEntry = alice.roster_entry.unwrap();
        let bob_roster_entry: RosterEntry = bob.roster_entry.unwrap();

        // Pretend that Bob had previously made a Signal group with a key:
        let group_roster_key: GroupRosterKey = GroupRosterKey([0u8; 32]);
        let mut roster: GroupMembershipRoster = GroupMembershipRoster::new(42, bob_roster_entry,
                                                                           group_roster_key);

        // Now Bob adds Alice:
        let _ = roster.add_user(alice_roster_entry); // XXX that api is bad

        // Alice wants to prove they're in the roster:
        let alice_presentation: SignalCredentialPresentation = alice.show().unwrap();

        let proof: Result<(), CredentialError> = issuer.verify(&alice_presentation);

        if proof.is_err() {
            println!("Got an error: {:?}", proof);
        }
        assert!(proof.is_ok());
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
    //             B: &self.system_parameters.g,
    //             A: &self.system_parameters.h,
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
    //     let P: RistrettoPoint = &self.system_parameters.g * &b; // XXX use basepoint table
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
    //             let key: Scalar = self.key.xn[index];
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
    //             EQH.encryption += attribute.encryption * &(&self.key.xn[index] * &b);
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
    //     let t0: Scalar = &b * &self.key.xn[0];
    //     let t1: Scalar = &b * &self.key.xn[1];
    //     let T0: RistrettoPoint = &t0 * &self.system_parameters.h;
    //     let T1: RistrettoPoint = &t1 * &self.system_parameters.h;
    // 
    //     // Form a NIPK showing that we issued the credential correctly, the encrypted aMAC was
    //     // encrypted to the user's public key, the decryption of the encrypted aMAC was produced
    //     // with the secret key corresponding to the issuer's known public key, and the system
    //     // parameters are as expected.
    //     let secrets = blind_issuance::Secrets {
    //         x0_tilde: &x0_tilde,
    //         x0: &self.key.x0,
    //         x1: &self.key.xn[0],
    //         x2: &self.key.xn[1],
    //         s: &s,
    //         b: &b,
    //         t0: &t0,
    //         t1: &t1,
    //     };
    // 
    //     let publics = blind_issuance::Publics {
    //         B: &self.system_parameters.g,
    //         A: &self.system_parameters.h,
    //         X0: &self.issuer_parameters.Xn[0],
    //         X1: &self.issuer_parameters.Xn[1],
    //         X2: &self.issuer_parameters.Xn[2],
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
