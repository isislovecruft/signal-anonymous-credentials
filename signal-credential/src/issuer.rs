// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use aeonflux::amacs::{self};
use aeonflux::amacs::Tag;
use aeonflux::amacs::IssuerParameters;
use aeonflux::credential::Credential;
use aeonflux::credential::CredentialIssuance;
use aeonflux::credential::CredentialPresentation;
use aeonflux::credential::CredentialRequest;
use aeonflux::credential::EncryptedAttribute;
use aeonflux::credential::RevealedAttribute;
use aeonflux::errors::CredentialError;
use aeonflux::issuer::Issuer;
use aeonflux::issuer::IssuerSecretKey;
use aeonflux::parameters::SystemParameters;
use aeonflux::pedersen::{self, Commitment};
use aeonflux::proofs::issuance_revealed;
use aeonflux::proofs::valid_credential;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::RngCore;
use rand_core::CryptoRng;

use zkp::Transcript;

use credential::ISSUANCE_NUMBER_OF_HIDDEN_ATTRIBUTES;
use credential::ISSUANCE_NUMBER_OF_REVEALED_ATTRIBUTES;
use credential::NUMBER_OF_ATTRIBUTES;
use credential::SignalCredential;
use credential::SignalCredentialBlindIssuance;
use credential::SignalCredentialBlindRequest;
use credential::SignalCredentialIssuance;
use credential::SignalCredentialRequest;
use credential::SignalCredentialPresentation;
use credential::VerifiedSignalCredential;
use errors::RosterError;
use phone_number::PhoneNumber;
use proofs::blind_attributes;
use proofs::blind_issuance;
use proofs::revealed_attributes;
use proofs::roster_membership;
use roster::GroupMembershipLevel;
use roster::GroupMembershipRoster;

/// An issuer and honest verifier of `SignalCredential`s.
pub struct SignalIssuer {
    pub issuer: Issuer,
}

impl SignalIssuer {
    /// Create a new `SignalIssuer` from some agreed upon `system_parameters`
    /// and an optional `secret_key`.
    ///
    /// # Inputs
    ///
    /// * `system_parameters` are a set of `SystemParameters` containing the
    ///   distinguished basepoints, `G` and `H`.
    /// * `secret_key` is an `Option<&IssuerSecretKey>`.  If `None`, a new
    ///   `IssuerSecretKey` will be created.
    pub fn new<R>(
        system_parameters: SystemParameters,
        secret_key: Option<&IssuerSecretKey>,
        csprng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        SignalIssuer {
            issuer: Issuer::new(system_parameters, secret_key, csprng),
        }
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
    /// * `request` is a `SignalCredentialRequest` containing a `proof` that the
    ///   revealed attributes match those in some commitments, the user's phone
    ///   number (as a `String`), and the user's `RosterEntry`.
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
    pub fn issue<R>(&self, request: &SignalCredentialRequest, rng: &mut R)
        -> Result<SignalCredentialIssuance, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        // Construct the phone number and check that it matches the attributes.
        let number: PhoneNumber = PhoneNumber::try_from_string(&request.phone_number)?;

        if number.0 != request.request.attributes_revealed[0] {
            return Err(CredentialError::BadAttribute);
        }

        // Create a transcript and feed the context into it
        let mut request_transcript = Transcript::new(b"SIGNAL ISSUANCE REQUEST");
        // XXX put the attributes into the transcript first

        // Verify the zero-knowledge proof that the roster entry is a commitment to the phone number.
        let roster_entry_commitment_number = request.roster_entry.committed_phone_number;

        let revealed_attributes_publics: revealed_attributes::Publics = revealed_attributes::Publics {
            g: &self.issuer.system_parameters.g,
            h: &self.issuer.system_parameters.h,
            roster_entry_commitment_number: &roster_entry_commitment_number.0.into(),
        };

        if request.proof.verify(&mut request_transcript, revealed_attributes_publics).is_err() {
            return Err(CredentialError::VerificationFailure);
        }

        self.issuer.issue(&request.request, rng)
    }

    pub fn verify<'a>(&self, signal_presentation: &'a SignalCredentialPresentation)
        -> Result<VerifiedSignalCredential<'a>, CredentialError>
    {
        self.issuer.verify(&signal_presentation.presentation)?;

        Ok(VerifiedSignalCredential(signal_presentation))
    }

    pub fn verify_roster_membership(
        &self,
        credential: &VerifiedSignalCredential,
        roster: &GroupMembershipRoster,
        level: &GroupMembershipLevel,
    ) -> Result<(), RosterError>
    {
        match level {
            GroupMembershipLevel::Owner => 
                if ! &roster.owners[..].contains(&credential.0.roster_entry) {
                    return Err(RosterError::MemberIsNotOwner);
                },
            GroupMembershipLevel::Admin =>
                if ! &roster.owners[..].contains(&credential.0.roster_entry) &&
                ! &roster.admins[..].contains(&credential.0.roster_entry) {
                    return Err(RosterError::MemberIsNotAdmin);
                },
            GroupMembershipLevel::User =>
                if ! &roster.owners[..].contains(&credential.0.roster_entry) &&
                ! &roster.admins[..].contains(&credential.0.roster_entry) &&
                ! &roster.users[..].contains(&credential.0.roster_entry) {
                    return Err(RosterError::MemberIsNotUser);
                }
        }

        let publics = roster_membership::Publics {
            B: &self.issuer.system_parameters.g,
            A: &self.issuer.system_parameters.h,
            P: &credential.0.presentation.rerandomized_nonce,
            Cm0: &credential.0.presentation.attributes_blinded[0].clone().into(),
            RosterEntryPhoneNumberCommitment: &credential.0.roster_entry.committed_phone_number.0.into(),
        };
        let mut transcript = Transcript::new(b"SIGNAL GROUP MEMBERSHIP");

        if credential.0.roster_membership_proof.verify(&mut transcript, publics).is_ok() {
            Ok(())
        } else {
            Err(RosterError::InvalidProof)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use aeonflux::parameters::SystemParameters;
    use rand::thread_rng;
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
        // Create RNGs for each party.
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();
        let mut bob_rng = thread_rng();

        // Create an issuer
        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES, &mut issuer_rng);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key), &mut issuer_rng);

        // Get the issuer's parameters so we can advertise them to new users:
        let issuer_parameters: IssuerParameters = issuer.issuer.issuer_parameters.clone();

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
        let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();

        // Try to get the issuer to give Alice a new credential
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request, &mut issuer_rng).unwrap();

        // Give the result back to Alice for processing
        alice.obtain_finish(Some(&alice_issuance));
        
        // And the same for Bob:
        let bob_request: SignalCredentialRequest = bob.obtain(&mut bob_rng).unwrap();
        let bob_issuance: SignalCredentialIssuance = issuer.issue(&bob_request, &mut issuer_rng).unwrap();

        bob.obtain_finish(Some(&bob_issuance));

        let alice_roster_entry: RosterEntry = alice.roster_entry.unwrap();
        let bob_roster_entry: RosterEntry = bob.roster_entry.unwrap();

        // Pretend that Bob had previously made a Signal group with a key:
        let group_roster_key: GroupRosterKey = GroupRosterKey([0u8; 32]);
        let mut roster: GroupMembershipRoster = GroupMembershipRoster::new(42, bob_roster_entry,
                                                                           group_roster_key);

        // Now Bob adds Alice:
        let _ = roster.add_user(alice_roster_entry); // XXX that api is bad

        // Alice wants to prove they're in the roster:
        let alice_presentation: SignalCredentialPresentation = alice.show(&mut alice_rng).unwrap();

        let verified_credential: VerifiedSignalCredential = issuer.verify(&alice_presentation).unwrap();

        let user_proof = issuer.verify_roster_membership(&verified_credential, &roster,
                                                         &GroupMembershipLevel::User);
        assert!(user_proof.is_ok());

        let admin_proof = issuer.verify_roster_membership(&verified_credential, &roster,
                                                         &GroupMembershipLevel::Admin);
        assert!(admin_proof.is_err());
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
    //         x1: &self.key.xn[0],
    //         x2: &self.key.xn[1],
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
