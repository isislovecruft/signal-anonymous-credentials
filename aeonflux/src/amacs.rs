// -*- mode: rust; -*-
//
// This file is part of amacs.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Implementation of the MAC_GGM scheme in [CMZ'13](https://eprint.iacr.org/2013/516.pdf).
//!
//! The system parameters are:
//! 
//! - A group `G` of prime order `p`;
//! - A generator `g` of G;
//! - A generator `h` of G so that `log_g(h)` is unknown;
//!
//! In our case, the generator is the Ristretto basepoint.  This fixes `G`, `g`,
//! and `l`.
//!
//! The only parameter remaining is the second generator `h`, which is only used
//! for the "issuer parameters" used for anonymous credentials.  It should be
//! generated securely.

use std::string::String;
use std::vec::Vec;

use std::ops::{Index, Mul};

use clear_on_drop::clear::Clear;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;

use rand_core::RngCore;
use rand_core::CryptoRng;

use sha2::Sha512;

use errors::MacError;

use parameters::NUMBER_OF_ATTRIBUTES;

pub const SIZEOF_TAG: usize = 64;

/// A `Message` is a vector of `Scalar`s in \( \mathbb{Z}/\mathbb{Z}\ell \).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Message(pub Vec<Scalar>);

/// Convert a static `&str` to a `Message`.
///
/// # Example
///
/// ```
/// use aeonflux::amacs::Message;
///
/// let string: String = String::from("this is a test");
/// let msg: Message = string.into();
/// ```
impl From<String> for Message {
    fn from(source: String) -> Message {
        let mut v = Vec::new();

        v.push(Scalar::hash_from_bytes::<Sha512>(source.as_bytes()));

        Message( v )
    }
}

impl From<Scalar> for Message {
    fn from(source: Scalar) -> Message {
        let mut v = Vec::with_capacity(1);

        v.push(source);

        Message( v )
    }
}

impl From<Vec<Scalar>> for Message {
    fn from(source: Vec<Scalar>) -> Message {
        Message( source )
    }
}

impl From<Message> for Vec<Scalar> {
    fn from(source: Message) -> Vec<Scalar> {
        source.0
    }
}

impl Index<usize> for Message {
    type Output = Scalar;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// A `Tag` for an authenticated `Message`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Tag {
    pub nonce: RistrettoPoint,
    pub mac: RistrettoPoint,
}

impl Tag {
    pub fn from_bytes(bytes: &[u8]) -> Result<Tag, MacError> {
        if bytes.len() != 64 {
            return Err(MacError::PointDecompressionError);
        }

        let mut P_bytes: [u8; 32] = [0u8; 32];
        let mut Q_bytes: [u8; 32] = [0u8; 32];

        P_bytes.copy_from_slice(&bytes[00..32]);
        Q_bytes.copy_from_slice(&bytes[32..64]);

        let P: RistrettoPoint = CompressedRistretto(P_bytes).decompress()?;
        let Q: RistrettoPoint = CompressedRistretto(Q_bytes).decompress()?;

        Ok(Tag {
            nonce: P,
            mac: Q,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64);

        v.extend(self.nonce.compress().to_bytes().iter());
        v.extend(self.mac.compress().to_bytes().iter());

        v
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PublicKey {
    pub Xn: Vec<RistrettoPoint>,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, MacError> {
        let length: usize = bytes.len();

        // The bytes must be a multiple of 32.
        if length % 32 != 0 {
            return Err(MacError::MessageLengthError { length });
        }
        let mut Xn: Vec<RistrettoPoint> = Vec::with_capacity(length % 32);

        // When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in bytes.chunks(32) {
            let X: RistrettoPoint = match CompressedRistretto::from_slice(chunk).decompress() {
                None    => return Err(MacError::PointDecompressionError),
                Some(x) => x,
            };
            Xn.push(X);
        }

        Ok(PublicKey { Xn })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(self.Xn.len() * 32);

        for X in self.Xn.iter() {
            v.extend(X.compress().0.iter());
        }

        v
    }

    pub fn len(&self) -> usize {
        self.Xn.len()
    }
}

/// A secret key for authenticating and verifying `Tag`s.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct SecretKey {
    pub x0: Scalar,
    pub xn: Vec<Scalar>,
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.x0.clear();

        for scalar in self.xn.iter_mut() {
            scalar.clear();
        }
    }
}

impl SecretKey {
    /// Create a new `SecretKey` for authenticating a message of `n` `Scalar`s.
    pub fn new<R>(n: usize, csprng: &mut R) -> SecretKey
    where
        R: RngCore + CryptoRng,
    {
        let mut xn: Vec<Scalar> = Vec::with_capacity(n);
        let x0: Scalar = Scalar::random(csprng);

        for _ in 0..n {
            xn.push(Scalar::random(csprng));
        }

        SecretKey{ x0, xn }
    }

    /// Construct this secret key from some `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, MacError> {
        let length: usize = bytes.len();

        // The bytes must be a multiple of 32.
        if length % 32 != 0 {
            return Err(MacError::MessageLengthError{ length });
        }
        let mut x0: Option<Scalar> = None;
        let mut xn: Vec<Scalar> = Vec::with_capacity((length / 32) - 1);

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in bytes.chunks(32) {
            let mut tmp = [0u8; 32];

            tmp.copy_from_slice(chunk);

            let x = match Scalar::from_canonical_bytes(tmp) {
                None    => return Err(MacError::ScalarFormatError),
                Some(x) => x,
            };

            match x0 {
                None    => x0 = Some(x),
                Some(_) => xn.push(x),
            }
        }
        match x0 {
            None    => Err(MacError::MessageLengthError{ length }),
            Some(x) => Ok(SecretKey { x0: x, xn: xn })
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32 + 32 * self.xn.len());

        v.extend(self.x0.to_bytes().iter());

        for x in self.xn.iter() {
            v.extend(x.to_bytes().iter())
        }

        v
    }

    pub fn len(&self) -> usize {
        self.xn.len() + 1
    }

    /// Compute public issuer parameters for use with anonymous credentials.
    ///
    /// # Inputs
    ///
    /// * `h`, a distinguished basepoint orthogonal to the `RISTRETTO_BASEPOINT_POINT`.
    #[allow(non_snake_case)]
    pub fn get_public_key(&self, h: &RistrettoPoint) -> PublicKey {
        let mut Xn: Vec<RistrettoPoint> = Vec::with_capacity(self.xn.len());

        for xi in self.xn.iter() {
            Xn.push(h * xi);
        }

        PublicKey { Xn }
    }

    pub fn mac<R>(&self, message: &Message, csprng: &mut R) -> Result<Tag, MacError>
    where
        R: RngCore + CryptoRng,
    {
        if self.xn.len() != message.0.len() {
            return Err(MacError::MessageLengthError{ length: self.xn.len() });
        }

        let nonce: RistrettoPoint = &Scalar::random(csprng) * &RISTRETTO_BASEPOINT_TABLE;
        let mut exponent: Scalar = self.x0;

        for (xi, mi) in self.xn.iter().zip(message.0.iter()) {
            exponent += xi * mi;
        }
        let mac = nonce * exponent;

        Ok(Tag { nonce: nonce, mac: mac })
    }

    pub fn verify(&self, mac: &Tag, message: &Message) -> Result<(), MacError> {
        if mac.nonce == RISTRETTO_BASEPOINT_POINT {
            return Err(MacError::AuthenticationError);
        }
        let mut exponent = self.x0;

        for (xi, mi) in self.xn.iter().zip(message.0.iter()) {
            exponent = (xi * mi) + exponent;
        }
        let check: RistrettoPoint = mac.nonce * exponent;

        if mac.mac == check {
            Ok(())
        } else {
            Err(MacError::AuthenticationError)
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl Keypair {
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, MacError> {
        let length: usize = bytes.len();

        // The public key must always be 32 bytes shorter since the secret key has the extra x0 element.
        let public_key_length: usize = (length - 32) / 2;
        let secret_key_length: usize = length - public_key_length;

        if public_key_length % 32 != 0 || secret_key_length % 32 != 0 {
            return Err(MacError::KeypairDeserialisation);
        }

        let public: PublicKey = PublicKey::from_bytes(&bytes[..public_key_length])?;
        let secret: SecretKey = SecretKey::from_bytes(&bytes[public_key_length..])?;

        Ok(Keypair { public, secret })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity((self.public.len() + self.secret.len()) * 32);

        v.extend(self.public.to_bytes().iter());
        v.extend(self.secret.to_bytes().iter());

        v
    }

    pub fn len(&self) -> usize {
        self.public.len() + self.secret.len()
    }
}

impl Keypair {
    pub fn new<R>(h: &RistrettoPoint, csprng: &mut R) -> Keypair
    where
        R: RngCore + CryptoRng,
    {
        let secret = SecretKey::new(NUMBER_OF_ATTRIBUTES, csprng);
        let public = secret.get_public_key(&h);

        Keypair { public, secret }
    }
}

/// A type for generating secret nonces for aMAC rerandomisation and then
/// clearing them from memory.
#[derive(Clone, Debug, Default)]
pub struct Rerandomization(pub(crate) Scalar);

impl<'a, 'b> Mul<&'a Rerandomization> for &'b Tag {
    type Output = Tag;

    fn mul(self, other: &'a Rerandomization) -> Tag {
        Tag {
            nonce: other.0 * self.nonce,
            mac:   other.0 * self.mac,
        }
    }
}

impl<'a, 'b> Mul<&'b Tag> for &'a Rerandomization {
    type Output = Tag;

    fn mul(self, other: &'b Tag) -> Tag {
        Tag {
            nonce: self.0 * other.nonce,
            mac:   self.0 * other.mac,
        }
    }
}

impl Rerandomization {
    pub fn new<R>(csprng: &mut R) -> Rerandomization
    where
        R: RngCore + CryptoRng,
    {
        Rerandomization(Scalar::random(csprng))
    }

    pub fn apply_to_tag(&self, tag: &Tag) -> Tag {
        tag * self
    }
}

impl Drop for Rerandomization {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn test_mac_authentication() {
        let mut csprng = thread_rng();
        let key = SecretKey::new(2, &mut csprng);
        let s1 = Scalar::random(&mut csprng);
        let s2 = Scalar::random(&mut csprng);
        let s3 = Scalar::random(&mut csprng);
        let mut v1 = Vec::new();
        v1.extend_from_slice(&[s1, s2]);
        let m1 = Message(v1);
        let mut v2 = Vec::new();
        v2.extend_from_slice(&[s1, s3]);
        let m2 = Message(v2);
        let tagged_m1 = key.mac(&m1, &mut csprng).unwrap();

        assert!(key.verify(&tagged_m1, &m1).is_ok());
        assert!(key.verify(&tagged_m1, &m2).is_err());
    }

    #[test]
    fn test_rerandomised_mac_authentication() {
        let mut csprng = thread_rng();
        let key = SecretKey::new(2, &mut csprng);
        let s1 = Scalar::random(&mut csprng);
        let s2 = Scalar::random(&mut csprng);
        let s3 = Scalar::random(&mut csprng);
        let mut v1 = Vec::new();
        v1.extend_from_slice(&[s1, s2]);
        let m1 = Message(v1);
        let mut v2 = Vec::new();
        v2.extend_from_slice(&[s1, s3]);
        let m2 = Message(v2);
        let tag = key.mac(&m1, &mut csprng).unwrap();

        let rerandomised = Rerandomization::new(&mut csprng).apply_to_tag(&tag);

        assert!(key.verify(&rerandomised, &m1).is_ok());
        assert!(key.verify(&rerandomised, &m2).is_err());
    }
}
