// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Implementation of the MAC_GGM scheme in CMZ'13.
//!
//! The system parameters are:
//! 
//! - A group `G` of prime order `l` (in the paper, `p`);
//! - A generator `g` of G;
//! - A generator `h` of G so that `log_g(h)` is unknown;
//!
//! In our case, the generator is the Ristretto basepoint.  This fixes `G`, `g`,
//! and `l`.  Note that we rename `p` to `l` so that we do not confuse the group
//! order with `p=2^255 -19`.
//!
//! The only parameter remaining is the second generator `h`, which is only used
//! for the "issuer parameters" used for anonymous credentials.  It should be
//! generated securely.

// XXX think about how the h parameter should work for the AC use case
//     is there a meaningful separation between the parameter 'h'
//     and the issuer parameters?
// XXX does Elligator2 work for trusted setup?

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

use clear_on_drop::clear::Clear;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;

use rand::thread_rng;

use sha2::Sha512;

use subtle::ConstantTimeEq;

use errors::MacError;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Message(pub(crate) Vec<Scalar>);

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

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TaggedMessage {
    nonce:   CompressedRistretto,
    mac:     CompressedRistretto,
    message: Message,
}

#[derive(Clone, Debug)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IssuerParameters {
    Xn: Vec<RistrettoPoint>,
}

/// A secret key for authenticating and verifying `TaggedMessage`s.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct SecretKey {
    x0: Scalar,
    xn: Vec<Scalar>,
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
    pub fn new(n: usize) -> SecretKey {
        let mut csprng = thread_rng();
        let mut xn: Vec<Scalar> = Vec::with_capacity(n);
        let x0: Scalar = Scalar::random(&mut csprng);

        for _ in 0..n {
            xn.push(Scalar::random(&mut csprng));
        }

        SecretKey{ x0, xn }
    }

    /// Compute public issuer parameters for use with anonymous credentials.
    ///
    /// # Inputs
    ///
    /// * `h`, a distinguished basepoint orthogonal to the `RISTRETTO_BASEPOINT_POINT`.
    #[allow(non_snake_case)]
    pub fn get_issuer_parameters(&self, h: RistrettoPoint) -> IssuerParameters {
        let mut Xn: Vec<RistrettoPoint> = Vec::with_capacity(self.xn.len());

        for xi in self.xn.iter() {
            Xn.push(h * xi);
        }

        IssuerParameters{ Xn }
    }

    pub fn mac(&self, message: &Message) -> Result<TaggedMessage, MacError> {
        if self.xn.len() != message.0.len() {
            return Err(MacError::MessageLengthError{ length: self.xn.len() });
        }

        let mut csprng = thread_rng();
        let nonce: RistrettoPoint = &Scalar::random(&mut csprng) * &RISTRETTO_BASEPOINT_TABLE;
        let mut exponent: Scalar = self.x0;

        for (xi, mi) in self.xn.iter().zip(message.0.iter()) {
            exponent = (xi * mi) + exponent;
        }
        let mac = nonce * exponent;

        Ok(TaggedMessage { nonce: nonce.compress(), mac: mac.compress(), message: message.clone() })
    }

    pub fn verify(&self, mac: &TaggedMessage) -> Result<Message, MacError> {
        if mac.nonce == RISTRETTO_BASEPOINT_COMPRESSED {
            return Err(MacError::AuthenticationError);
        }

        let mut check: RistrettoPoint = match mac.nonce.decompress() {
            None    => return Err(MacError::AuthenticationError),
            Some(x) => x,
        };

        let orig: RistrettoPoint = match mac.mac.decompress() {
            None    => return Err(MacError::AuthenticationError),
            Some(x) => x,
        };
        let mut exponent = self.x0;

        for (xi, mi) in self.xn.iter().zip(mac.message.0.iter()) {
            exponent = (xi * mi) + exponent;
        }
        check *= exponent;

        match orig.ct_eq(&check).unwrap_u8() {
            0 => Err(MacError::AuthenticationError),
            1 => Ok(mac.message.clone()),
            _ => unsafe { ::core::hint::unreachable_unchecked() },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mac_authentication() {
        let mut csprng = thread_rng();
        let key = SecretKey::new(2);
        let s1 = Scalar::random(&mut csprng);
        let s2 = Scalar::random(&mut csprng);
        let s3 = Scalar::random(&mut csprng);
        let mut v1 = Vec::new();
        v1.extend_from_slice(&[s1, s2]);
        let m1 = Message(v1);
        let mut v2 = Vec::new();
        v2.extend_from_slice(&[s1, s3]);
        let m2 = Message(v2);
        let tagged_m1 = key.mac(&m1).unwrap();
        let tagged_m2 = TaggedMessage{ nonce: tagged_m1.nonce,
                                       mac:   tagged_m1.mac,
                                       message: m2 };
        assert!(key.verify(&tagged_m1).is_ok());
        assert!(key.verify(&tagged_m2).is_err());
    }
}
