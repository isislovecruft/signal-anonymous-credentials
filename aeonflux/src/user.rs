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

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;

use merlin::Transcript;

use rand_core::RngCore;
use rand_core::CryptoRng;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use amacs;
use credential::Credential;
use credential::CredentialIssuance;
use credential::CredentialPresentation;
use credential::CredentialRequest;
use credential::RevealedAttribute;
use elgamal;
use errors::CredentialError;
use issuer::IssuerParameters;
use nonces::Ephemeral;
use nonces::Nonces;
use parameters::SystemParameters;
use pedersen;
use proofs::issuance_revealed;
use proofs::valid_credential;

/// DOCDOC
#[derive(Debug, Eq, PartialEq)]
pub struct User {
    pub system_parameters: SystemParameters,
    pub issuer_parameters: IssuerParameters,
    pub key: Option<elgamal::Keypair>,
    pub credential: Option<Credential>,
}

impl User {
    pub fn from_bytes(bytes: &[u8]) -> Result<User, CredentialError> {
        if bytes.len() != 256 {
            return Err(CredentialError::MissingData);
        }

        let system_parameters = SystemParameters::from_bytes(&bytes[00..64])?;
        let issuer_parameters = IssuerParameters::from_bytes(&bytes[64..96])?;

        let key: Option<elgamal::Keypair>;

        if &bytes[96..160] == &[0u8; 64][..] {
            key = None;
        } else {
            key = Some(elgamal::Keypair::from_bytes(&bytes[96..160])?);
        }

        let credential: Option<Credential>;

        if &bytes[160..256] == &[0u8; 96][..] {
            credential = None;
        } else {
            credential = Some(Credential::from_bytes(&bytes[160..])?);
        }

        Ok(User {
            system_parameters,
            issuer_parameters,
            key,
            credential,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();

        v.extend(self.system_parameters.to_bytes());
        v.extend(self.issuer_parameters.to_bytes());

        match self.key {
            None        => v.extend([0u8; 64].iter()),
            Some(ref x) => v.extend(x.to_bytes().iter()),
        }

        match self.credential {
            None        => v.extend([0u8; 96].iter()),
            Some(ref x) => v.extend(x.to_bytes().iter()),
        }

        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(User, "A valid byte sequence representing a User");

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
            Cx0: &issue.secret_key_commitment.into(),
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X1: &X1,
        };

        if issue.proof.verify(&mut transcript, publics).is_err() {
            Err(CredentialError::CredentialIssuance)
        } else {
            self.credential = Some(issue.credential.clone());

            Ok(())
        }
    }

    // We also pass in the nonces here in order to allow reusing them in
    // proofs regarding the committed attributes.
    pub fn show<R>(
        &self,
        nonces: &Nonces,
        rng: &mut R,
    ) -> Result<CredentialPresentation, CredentialError>
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
        let zQ: Ephemeral = Ephemeral::new(&mut csprng);
        let CQ: pedersen::Commitment = pedersen::Commitment::to(&Q, &zQ, &A);

        // Commit to the hidden attributes.
        let mut commitments: Vec<pedersen::Commitment> = Vec::with_capacity(N_ATTRIBUTES);

        for (zi, mi) in nonces.iter().zip(credential.attributes.iter()) {
            let Cmi: pedersen::Commitment = pedersen::Commitment::to(&(mi * P), zi, &A);

            commitments.push(Cmi);
        }

        // Calculate the error factor.
        let mut V: RistrettoPoint = RistrettoPoint::identity();

        for (index, zi) in nonces.iter().enumerate() {
            V += &(zi * self.issuer_parameters.Xn[index]);
        }
        V -= &zQ * &A;

        let minus_zQ = -zQ;

        let valid_credential_secrets = valid_credential::Secrets {
            m0: &credential.attributes[0],
            z0: (&nonces[0]).into(),
            minus_zQ: (&minus_zQ).into(),
        };
        let valid_credential_publics = valid_credential::Publics {
            B: &B,
            A: &A,
            X0: &self.issuer_parameters.Xn[0],
            P: &rerandomized_mac.nonce,
            V: &V,
            Cm0: &commitments[0].into(),
        };
        let valid_credential_proof = valid_credential::Proof::create(&mut transcript,
                                                                     valid_credential_publics,
                                                                     valid_credential_secrets);

        Ok(CredentialPresentation {
            proof: valid_credential_proof,
            rerandomized_mac_commitment: CQ,
            rerandomized_nonce: rerandomized_mac.nonce,
            attributes_revealed: Vec::with_capacity(0),
            attributes_blinded: commitments,
        })
    }
}

impl User {
    pub fn blind_request<C>(
        &mut self,
        csprng: &mut C,
    ) -> CredentialBlindRequest
    where
        C: CryptoRng + RngCore,
    {
        if self.key.is_none() {
            self.key = elgamal::Keypair::generate::<C>(&mut csprng);
        }

        unimplemented!();
    }
}
