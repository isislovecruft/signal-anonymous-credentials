// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use amacs;
pub use amacs::PublicKey as IssuerParameters;
pub use amacs::SecretKey as IssuerSecretKey;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::RngCore;
use rand_core::CryptoRng;

use zkp::Transcript;

use credential::Credential;
use credential::CredentialIssuance;
use credential::CredentialRequest;
use credential::CredentialPresentation;
use credential::VerifiedCredential;
use errors::CredentialError;
use parameters::SystemParameters;
use pedersen::{self};
use proofs::issuance_revealed;
use proofs::valid_credential;

/// An issuer and honest verifier of `Credential`s.
#[repr(C)]
pub struct Issuer {
    /// The system parameters.  Users and issuers must agree on parameters.
    pub system_parameters: SystemParameters,
    /// The issuer's aMAC key material.
    pub keypair: amacs::Keypair,
}

impl Issuer {
    pub fn from_bytes(bytes: &[u8]) -> Result<Issuer, CredentialError> {
        if bytes.len() < 64 + 96 {
            return Err(CredentialError::MissingData);
        }

        let system_parameters = SystemParameters::from_bytes(&bytes[..64])?;
        let keypair = amacs::Keypair::from_bytes(&bytes[64..])?;

        Ok(Issuer{ system_parameters, keypair })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64 + self.keypair.len() * 32);

        v.extend(self.system_parameters.to_bytes().iter());
        v.extend(self.keypair.to_bytes().iter());

        v
    }
}

impl Issuer {
    /// Create a new `Issuer` from some agreed upon `system_parameters`.
    ///
    /// This will create an entirely new issuer with new key material.  For
    /// instantiating an `Issuer` from previously generated key material, use
    /// `Issuer::new()`.
    ///
    /// # Inputs
    ///
    /// * `system_parameters` are a set of `SystemParameters` containing the
    ///   distinguished basepoints, `G` and `H`.
    pub fn create<R>(
        system_parameters: SystemParameters,
        csprng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let keypair = amacs::Keypair::new(&system_parameters.h, csprng);

        Issuer { system_parameters, keypair }
    }

    /// Initialize an `Issuer`.
    pub fn new(
        system_parameters: SystemParameters,
        keypair: amacs::Keypair,
    ) -> Self
    {
        Issuer { system_parameters, keypair }
    }

    /// Get this `Issuer`s parameters for publishing to users.
    pub fn get_issuer_parameters(&self) -> IssuerParameters {
        self.keypair.public.clone()
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
    /// * `request` is a `CredentialRequest` containing some revealed_attributes.
    ///
    /// # Errors
    ///
    /// This method may return the following errors:
    ///
    /// * `CredentialError::NoIssuerParameters` if this `Issuer`'s
    ///   `keypair.public` didn't contain the correct length of public key.
    /// * `CredentialError::NoIssuerKey` if this `Issuer`'s secret `key`
    ///   was not the correct length.
    ///
    /// # Returns
    ///
    /// A `CredentialIssuance` upon successful issuance.
    pub fn issue<R>(&self, request: &CredentialRequest, rng: &mut R)
        -> Result<CredentialIssuance, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        // Obtain our needed public and secret key material.
        let X1: RistrettoPoint = match self.keypair.public.Xn.get(0) {
            Some(x) => *x,
            None => return Err(CredentialError::NoIssuerParameters),
        };
        let x1: Scalar = match self.keypair.secret.xn.get(0) {
            Some(x) => *x,
            None => return Err(CredentialError::NoIssuerKey),
        };

        let attributes = &request.attributes_revealed;

        // Create a transcript and feed the context into it
        let mut transcript = Transcript::new(b"AEONFLUX ISSUANCE");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(rng);

        // Calculate (u, u'), i.e. (nonce, mac)
        let tag: amacs::Tag = self.keypair.secret.mac(&attributes.clone().into(), &mut csprng)
            .or(Err(CredentialError::MacCreation))?;

        // Choose a blinding factor, x~0
        let x0_tilde: Scalar = Scalar::random(&mut csprng);

        // Construct a commitment to the issuer secret key
        let Cx0 = pedersen::Commitment::to(&(&self.system_parameters.g * &self.keypair.secret.x0),
                                           &x0_tilde, &self.system_parameters.h);
        // XXX Could speed up the above by multiscalar_mul and generating a basepoint table

        // Construct the NIZK proof of correct issuance
        let secrets = issuance_revealed::Secrets {
            x0: &self.keypair.secret.x0,
            x1: &x1,
            x0_tilde: &x0_tilde,
            m1x1: &(&attributes[0] * &x1),
        };
        let publics = issuance_revealed::Publics {
            P: &tag.nonce,
            Q: &tag.mac,
            Cx0: &Cx0.into(),
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X1: &X1,
        };
        let proof = issuance_revealed::Proof::create(&mut transcript, publics, secrets);
        let cred = Credential {
            mac: tag.clone(),
            attributes: attributes.clone(),
        };

        Ok(CredentialIssuance{
            proof: proof,
            credential: cred,
            secret_key_commitment: Cx0,
        })
    }

    pub fn verify(&self, presentation: &CredentialPresentation)
        -> Result<VerifiedCredential, CredentialError>
    {
        let P = presentation.rerandomized_nonce;

        // Recompute the MAC
        let mut V_prime: RistrettoPoint = &self.keypair.secret.x0 * &P;

        for (index, attribute) in presentation.attributes_revealed.iter().enumerate() {
            V_prime += (&self.keypair.secret.xn[index] * attribute) * &P;
        }

        for (index, attribute) in presentation.attributes_blinded.iter().enumerate() {
            V_prime += &self.keypair.secret.xn[index] * attribute;
        }
        V_prime -= presentation.rerandomized_mac_commitment;

        let mut transcript = Transcript::new(b"AEONFLUX SHOW");
        let publics = valid_credential::Publics {
            B: &self.system_parameters.g,
            A: &self.system_parameters.h,
            X0: &self.keypair.public.Xn[0],
            P: &P,
            V: &V_prime,
            Cm0: &presentation.attributes_blinded[0].into(),
        };

        if presentation.proof.verify(&mut transcript, publics).is_err() {
            return Err(CredentialError::MacVerification);
        }

        Ok(VerifiedCredential(presentation.clone()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    use credential::RevealedAttribute;
    use parameters::NUMBER_OF_ATTRIBUTES;
    use parameters::SystemParameters;
    use nonces::Nonces;
    use user::User;

    const H: [u8; 32] = [ 154, 189, 169, 176, 131,  12,  78, 199,
                          127,   4, 178,  70, 212, 141, 119, 112,
                          153, 154, 135,  11, 227, 132, 247,  47,
                           68, 192,  72, 200,  23,  88,  51,  82, ];

    #[test]
    fn credential_issuance_and_presentation() {
        // Create RNGs for each party.
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        // Create an issuer
        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer: Issuer = Issuer::create(system_parameters, &mut issuer_rng);

        // Get the issuer's parameters so we can advertise them to new users:
        let issuer_parameters: IssuerParameters = issuer.get_issuer_parameters();

        // Create a user
        let mut alice: User = User::new(system_parameters,
                                        issuer_parameters.clone(),
                                        None); // no encrypted attributes so the key isn't needed

        // Form a request for a credential
        let alice_attributes: Vec<RevealedAttribute> = vec![Scalar::random(&mut alice_rng)];
        let alice_request: CredentialRequest = alice.obtain(alice_attributes);

        // Try to get the issuer to give Alice a new credential
        let alice_issuance: CredentialIssuance = issuer.issue(&alice_request, &mut issuer_rng).unwrap();

        // Give the result back to Alice for processing
        alice.obtain_finish(Some(&alice_issuance)).unwrap();
        
        let alice_nonces: Nonces = Nonces::new(&mut alice_rng, NUMBER_OF_ATTRIBUTES);
        let alice_presentation: CredentialPresentation = alice.show(&alice_nonces, &mut alice_rng).unwrap();
        let _verified_credential: VerifiedCredential = issuer.verify(&alice_presentation).unwrap();
    }
}
