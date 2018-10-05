// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(not(feature = "std"))]
use core::ops::Add;

#[cfg(feature = "std")]
use std::ops::Add;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use clear_on_drop::clear::Clear;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::CryptoRng;
use rand_core::RngCore;

use errors::CredentialError;

pub use nonces::Ephemeral;

pub const SIZEOF_PUBLIC_KEY: usize = 32;
pub const SIZEOF_SECRET_KEY: usize = 32;
pub const SIZEOF_KEYPAIR: usize = SIZEOF_PUBLIC_KEY + SIZEOF_SECRET_KEY;
pub const SIZEOF_ENCRYPTION: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct PublicKey(pub(crate) RistrettoPoint);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SecretKey(pub(crate) Scalar);

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// A plaintext elGamal message.
///
/// ElGamal cryptosystems in the elliptic curve context require a canonical,
/// invertible, isomorphic mapping from messages as scalars to messages as group
/// elements.  One such construction is given in "Elliptic Curve Cryptosystems"
/// (1987) by Neal Koblitz.
///
/// Rather than dealing with mapping scalars to group elements, instead we
/// require that the user save their plaintext while giving the encryption to
/// the credential issuer.  Later, rather than decrypt and map back to the
/// original scalar, they simply use the original plaintext.  For this reason,
/// we are able to map scalars to group elements by simply multiplying them by
/// the basepoint, which is obviously not invertible but works for the
/// algebraic-MAC-based anonymous credential blind issuance use-case.
pub struct Message(pub(crate) RistrettoPoint);

impl<'a> From<&'a Scalar> for Message {
    fn from(source: &'a Scalar) -> Message {
        Message(source * &RISTRETTO_BASEPOINT_TABLE)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Encryption {
    pub commitment: RistrettoPoint,
    pub encryption: RistrettoPoint,
}

impl<'a, 'b> Add<&'b Encryption> for &'a Encryption {
    type Output = Encryption;

    fn add(self, other: &'b Encryption) -> Encryption {
        Encryption {
            commitment: self.commitment + other.commitment,
            encryption: self.encryption + other.encryption,
        }
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, CredentialError> {
        assert!(bytes.len() == 32);

        let mut tmp = [0u8; 32];

        tmp.copy_from_slice(bytes);

        let point = CompressedRistretto(tmp).decompress()?;

        Ok(PublicKey(point))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32);

        v.extend(self.0.compress().to_bytes().iter());

        v
    }
}

impl PublicKey {
    pub fn encrypt(&self, message: &Message, nonce: &Ephemeral)
        -> Encryption
    {
        // The mapping to the point representing the message must be invertible
        let commitment: RistrettoPoint = &RISTRETTO_BASEPOINT_TABLE * &nonce.0;
        let encryption: RistrettoPoint = &message.0 + (&self.0 * &nonce.0);

        Encryption{ commitment, encryption }
    }
}

impl From<PublicKey> for RistrettoPoint {
    fn from(public: PublicKey) -> RistrettoPoint {
        public.0
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey(&RISTRETTO_BASEPOINT_TABLE * &secret.0)
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, CredentialError> {
        assert!(bytes.len() == 32);

        let mut tmp = [0u8; 32];

        tmp.copy_from_slice(bytes);

        let s = Scalar::from_canonical_bytes(tmp)?;

        Ok(SecretKey(s))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32);

        v.extend(self.0.to_bytes().iter());

        v
    }
}

impl SecretKey {
    pub fn generate<C>(csprng: &mut C) -> SecretKey
    where
        C: CryptoRng + RngCore,
    {
        SecretKey(Scalar::random(csprng))
    }

    pub fn decrypt(&self, encryption: &Encryption) -> RistrettoPoint {
        let secret: RistrettoPoint = &encryption.commitment * &self.0;

        &encryption.encryption - &secret
    }
}

impl From<SecretKey> for Scalar {
    fn from(secret: SecretKey) -> Scalar {
        secret.0
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl Keypair {
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, CredentialError> {
        assert!(bytes.len() == 64);

        let secret = SecretKey::from_bytes(&bytes[00..32])?;
        let public = PublicKey::from_bytes(&bytes[32..64])?;

        Ok(Keypair{ secret, public })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64);

        v.extend(self.secret.to_bytes());
        v.extend(self.public.to_bytes());

        v
    }
}

impl Keypair {
    pub fn generate<C>(csprng: &mut C) -> Keypair
    where 
        C: CryptoRng + RngCore,
    {
        let secret: SecretKey = SecretKey::generate(csprng);
        let public: PublicKey = PublicKey::from(&secret);

        Keypair{ secret, public }
    }

    pub fn encrypt(&self, message: &Message, nonce: &Ephemeral) -> Encryption
    {
        self.public.encrypt(message, nonce)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn roundtrip() {
        let mut csprng = thread_rng();
        let nonce = Ephemeral(Scalar::random(&mut csprng));
        let msg = Message(&RISTRETTO_BASEPOINT_TABLE * &nonce);
        let keypair = Keypair::generate(&mut csprng);
        let enc = keypair.public.encrypt(&msg, &nonce);

        assert!(keypair.secret.decrypt(&enc) == msg.0);
    }
}
