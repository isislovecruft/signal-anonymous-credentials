// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(not(feature = "std"))]
use core::ops::{Mul, SubAssign};

#[cfg(feature = "std")]
use std::ops::{Mul, SubAssign};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use errors::CredentialError;

pub const SIZEOF_COMMITMENT: usize = 32;

/// A Pedersen commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Commitment(RistrettoPoint);

impl From<Commitment> for RistrettoPoint {
    fn from(source: Commitment) -> RistrettoPoint {
        source.0
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Commitment {
    type Output = RistrettoPoint;

    fn mul(self, other: &'b Scalar) -> RistrettoPoint {
        self.0 * other
    }
}

impl<'a, 'b> Mul<&'a Commitment> for &'b Scalar {
    type Output = RistrettoPoint;

    fn mul(self, other: &'a Commitment) -> RistrettoPoint {
        self * other.0
    }
}

impl SubAssign<Commitment> for RistrettoPoint {
    fn sub_assign(&mut self, other: Commitment) {
        *self -= other.0;
    }
}

impl Commitment {
    pub fn from_bytes(bytes: &[u8]) -> Result<Commitment, CredentialError> {
        let mut tmp: [u8; 32] = [0u8; 32];

        tmp.copy_from_slice(&bytes[0..32]);

        Ok(Commitment(CompressedRistretto(tmp).decompress()?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32);

        v.extend(self.0.compress().to_bytes().iter());

        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(Commitment);

impl Commitment {
    /// Create a Pedersen commitment to some `value` using the specified `nonce`
    /// and `basepoint`.
    ///
    /// # Returns
    ///
    /// A `Commitment`.
    pub fn to(value: &RistrettoPoint, nonce: &Scalar, basepoint: &RistrettoPoint) -> Commitment {
        Commitment(value + &(nonce * basepoint))
    }

    pub fn open(&self, value: &RistrettoPoint, nonce: &Scalar, basepoint: &RistrettoPoint) -> Result<(), ()> {
        if *value == &self.0 - &(nonce * basepoint) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::ristretto::CompressedRistretto;

    use rand::thread_rng;

    pub const H: CompressedRistretto = CompressedRistretto(
        [ 76, 178,  52, 156, 167, 219,  63, 134,
         191, 228,  77, 182, 140,  65, 148, 163,
         247, 169, 129, 154,  54,  20,  36,  75,
          89,  50,  60, 243, 104,  44, 214,  50, ]);

    #[test]
    fn good_commitment() {
        let mut csprng = thread_rng();
        let nonce: Scalar = Scalar::random(&mut csprng);
        let value: RistrettoPoint = &Scalar::random(&mut csprng) * &RISTRETTO_BASEPOINT_TABLE;
        let basepoint: RistrettoPoint = H.decompress().unwrap();

        let cmt: Commitment = Commitment::to(&value, &nonce, &basepoint);

        assert!(cmt.open(&value, &nonce, &basepoint).is_ok());
    }

    #[test]
    fn bad_commitment() {
        let mut csprng = thread_rng();
        let nonce: Scalar = Scalar::random(&mut csprng);
        let value: RistrettoPoint = &Scalar::random(&mut csprng) * &RISTRETTO_BASEPOINT_TABLE;
        let other_value: RistrettoPoint = &Scalar::random(&mut csprng) * &RISTRETTO_BASEPOINT_TABLE;
        let basepoint: RistrettoPoint = H.decompress().unwrap();

        let cmt: Commitment = Commitment::to(&value, &nonce, &basepoint);

        assert!(cmt.open(&other_value, &nonce, &basepoint).is_err());
    }
}
