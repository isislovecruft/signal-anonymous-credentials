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

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use core::ops::{Index, Mul};

#[cfg(feature = "std")]
use std::ops::{Index, Mul};

use clear_on_drop::clear::Clear;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use rand_core::RngCore;
use rand_core::CryptoRng;

use sha2::Sha512;

use errors::MacError;

/// A `Message` is a vector of `Scalar`s in \( \mathbb{Z}/\mathbb{Z}\ell \).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Message(pub Vec<Scalar>);

/// Convert a static `&str` to a `Message`.
///
/// # Example
///
/// ```
/// use amacs::Message;
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

#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IssuerParameters {
    pub Xn: Vec<RistrettoPoint>,
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

    /// Compute public issuer parameters for use with anonymous credentials.
    ///
    /// # Inputs
    ///
    /// * `h`, a distinguished basepoint orthogonal to the `RISTRETTO_BASEPOINT_POINT`.
    #[allow(non_snake_case)]
    pub fn get_issuer_parameters(&self, h: &RistrettoPoint) -> IssuerParameters {
        let mut Xn: Vec<RistrettoPoint> = Vec::with_capacity(self.xn.len());

        for xi in self.xn.iter() {
            Xn.push(h * xi);
        }

        IssuerParameters{ Xn }
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
