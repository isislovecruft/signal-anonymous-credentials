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

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use elgamal;

use rand_core::RngCore;
use rand_core::CryptoRng;

use zkp::Transcript;

use credential::EncryptedAttribute;
use credential::RevealedAttribute;
use credential::Credential;
use credential::CredentialBlindIssuance;
use credential::CredentialBlindRequest;
use credential::CredentialIssuance;
use credential::CredentialRequest;
use credential::CredentialPresentation;
use credential::VerifiedCredential;
use errors::CredentialError;
use parameters::SystemParameters;
use proofs::attributes_blinded;
use proofs::issuance_blinded;
use proofs::issuance_revealed;
use proofs::valid_credential;

const NUMBER_OF_ATTRIBUTES: usize = 1;

/// An issuer and honest verifier of `Credential`s.
pub struct Issuer {
    /// The issuer's aMAC key material.
    keypair: amacs::Keypair,
    /// The system parameters.  Users and issuers must agree on parameters.
    pub system_parameters: SystemParameters,
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
        let keypair: amacs::Keypair::new(system_parameters.h, csprng);

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
        self.keypair.public
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
        let x1: Scalar = match self.key.xn.get(0) {
            Some(x) => *x,
            None => return Err(CredentialError::NoIssuerKey),
        };

        let attributes = &request.attributes_revealed;

        // Create a transcript and feed the context into it
        let mut transcript = Transcript::new(b"AEONFLUX ISSUANCE");
        let mut csprng = transcript.fork_transcript().reseed_from_rng(rng);

        // Calculate (u, u'), i.e. (nonce, mac)
        let tag: amacs::Tag = self.key.mac(&attributes.clone().into(), &mut csprng)
            .or(Err(CredentialError::MacCreation))?;

        // Choose a blinding factor, x~0
        let x0_tilde: Scalar = Scalar::random(&mut csprng);

        // Construct a commitment to the issuer secret key
        let Cx0: RistrettoPoint = (&self.system_parameters.g * &self.key.x0) +
                                  (&self.system_parameters.h * &x0_tilde);
        // XXX Could speed up the above by multiscalar_mul and generating a basepoint table

        // Construct the NIZK proof of correct issuance
        let secrets = issuance_revealed::Secrets {
            x0: &self.key.x0,
            x1: &x1,
            x0_tilde: &x0_tilde,
            m1x1: &(&attributes[0] * &x1),
        };
        let publics = issuance_revealed::Publics {
            P: &tag.nonce,
            Q: &tag.mac,
            Cx0: &Cx0,
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

    pub fn verify<'a>(&self, presentation: &'a CredentialPresentation)
        -> Result<VerifiedCredential<'a>, CredentialError>
    {
        let P = presentation.rerandomized_nonce;

        // Recompute the MAC
        let mut V_prime: RistrettoPoint = &self.key.x0 * &P;

        for (index, attribute) in presentation.attributes_revealed.iter().enumerate() {
            V_prime += (&self.key.xn[index] * attribute) * &P;
        }

        for (index, attribute) in presentation.attributes_blinded.iter().enumerate() {
            V_prime += &self.key.xn[index] * attribute;
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

        Ok(VerifiedCredential(presentation))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use parameters::SystemParameters;
    use rand::thread_rng;
    use user::User;

    const H: [u8; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                           93, 125, 218,  60,  36, 165, 166, 178,
                          118, 188,  77,  27, 133, 146, 193, 133,
                          234,  95,  69, 227, 213, 197,  84,  98, ];

    #[test]
    fn credential_issuance_and_presentation() {
        // Create RNGs for each party.
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        // Create an issuer
        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES, &mut issuer_rng);
        let issuer: Issuer = Issuer::new(system_parameters, Some(&issuer_secret_key), &mut issuer_rng);

        // Get the issuer's parameters so we can advertise them to new users:
        let issuer_parameters: IssuerParameters = issuer.get_issuer_parameters();

        // Create a user
        let mut alice: User = User::new(system_parameters,
                                        issuer_parameters.clone(),
                                        None); // no encrypted attributes so the key isn't needed

        // Form a request for a credential
        let alice_attributes: Vec<RevealedAttribute> = vec![Scalar::random(&mut alice_rng)];
        let alice_request: CredentialRequest = alice.obtain(alice_attributes).unwrap();

        // Try to get the issuer to give Alice a new credential
        let alice_issuance: CredentialIssuance = issuer.issue(&alice_request, &mut issuer_rng).unwrap();

        // Give the result back to Alice for processing
        alice.obtain_finish(Some(&alice_issuance));
        
        let alice_presentation: CredentialPresentation = alice.show(&mut alice_rng).unwrap();
        let verified_credential: VerifiedCredential = issuer.verify(&alice_presentation).unwrap();
    }
}
