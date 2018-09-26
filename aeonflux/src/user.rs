// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

// We denote group elements with capital and scalars with lowercased names.
#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand_core::RngCore;
use rand_core::CryptoRng;

use zkp::Transcript;

use amacs;
use amacs::SecretKey;
use credential::Credential;
use credential::CredentialBlindIssuance;
use credential::CredentialBlindRequest;
use credential::CredentialIssuance;
use credential::CredentialPresentation;
use credential::CredentialRequest;
use credential::EncryptedAttribute;
use credential::RevealedAttribute;
use elgamal;
use errors::CredentialError;
use issuer::IssuerParameters;
use parameters::SystemParameters;
use pedersen;
use proofs::attributes_blinded;
use proofs::issuance_blinded;
use proofs::issuance_revealed;
use proofs::valid_credential;

/// DOCDOC
pub struct User {
    pub system_parameters: SystemParameters,
    pub issuer_parameters: IssuerParameters,
    pub key: Option<elgamal::Keypair>,
    pub credential: Option<Credential>,
    pub transcript: Option<Transcript>,
}

impl User {
    /// DOCDOC
    pub fn new(
        system_parameters: SystemParameters,
        issuer_parameters: IssuerParameters,
        key: Option<elgamal::Keypair>,
    ) -> User
    {
        User {
            system_parameters: system_parameters,
            issuer_parameters: issuer_parameters,
            key: key,
            credential: None,
            transcript: None,
        }
    }

    /// DOCDOC
    ///
    /// # Returns
    ///
    pub fn obtain(
        &self,
        attributes_revealed: Vec<RevealedAttribute>,
    ) -> CredentialRequest
    {
        CredentialRequest {
            attributes_revealed,
        }
    }

    /// DOCDOC
    pub fn obtain_finish(
        &mut self,
        issuance: Option<&CredentialIssuance>,
    ) -> Result<(), CredentialError>
    {
        let mut transcript = Transcript::new(b"AEONFLUX ISSUANCE");

        let issue: &CredentialIssuance = match issuance {
            Some(i) => i,
            None    => return Err(CredentialError::CredentialIssuance),
        };
        let X1: RistrettoPoint = match self.issuer_parameters.Xn.get(0) {
            None => return Err(CredentialError::NoIssuerParameters),
            Some(x) => *x,
        };

        let publics = issuance_revealed::Publics {
            P: &issue.credential.mac.nonce,
            Q: &issue.credential.mac.mac,
            Cx0: &issue.secret_key_commitment,
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X1: &X1,
        };

        if issue.proof.verify(&mut transcript, publics).is_err() {
            Err(CredentialError::CredentialIssuance)
        } else {
            self.credential = Some(issue.credential.clone());
            self.transcript = None;

            Ok(())
        }
    }

    pub fn show<R>(
        &self,
        rng: &mut R
    ) -> Result<(CredentialPresentation, Vec<Scalar>), CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        let credential: &Credential = match self.credential {
            Some(ref x) => x,
            None        => return Err(CredentialError::MissingData),
        };

        let mut transcript = Transcript::new(b"AEONFLUX SHOW");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(rng);

        const N_ATTRIBUTES: usize = 1;

        // Rerandomise the aMAC to prevent trivial linkages.
        //
        // XXX do we want to pass in a merlin transcript instead of using the rng here?
        let rerandomized_mac: amacs::Tag = amacs::Rerandomization::new(&mut csprng).apply_to_tag(&credential.mac);

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
            let Cmi: pedersen::Commitment = pedersen::Commitment::to(&miP, &zi, &A);

            nonces.push(zi);
            commitments.push(Cmi);
        }

        // Calculate the error factor.
        let mut V: RistrettoPoint = RistrettoPoint::identity();

        for (index, zi) in nonces.iter().enumerate() {
            V += &(zi * self.issuer_parameters.Xn[index]);
        }
        V -= &zQ * &A;

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

        Ok(
            (CredentialPresentation {
                proof: valid_credential_proof,
                rerandomized_mac_commitment: CQ,
                rerandomized_nonce: rerandomized_mac.nonce,
                attributes_revealed: Vec::with_capacity(0),
                attributes_blinded: commitments,
            },
             // We also return the nonces here in order to allow reusing them in
             // proofs regaring the committed attributes:
             nonces.clone()))
    }
}
