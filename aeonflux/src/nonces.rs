// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(not(feature = "std"))]
use core::ops::{Mul, Index};

#[cfg(feature = "std")]
use std::ops::{Mul, Index};

use clear_on_drop::clear::Clear;

use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::CryptoRng;
use rand_core::RngCore;


/// An ephemeral key or nonce, used in elGamal encryptions and then discarded.
///
/// # Note
///
/// The encapsulated `Scalar` is `pub` so that we can access it (by borrow) for
/// zero-knowledge proof creations, without copying or changing its type
/// (otherwise the `clear()` on `Drop` would never run).
#[derive(Clone, Debug, Default)]
pub struct Ephemeral(pub Scalar);

impl From<Scalar> for Ephemeral {
    fn from(source: Scalar) -> Ephemeral {
        Ephemeral(source)
    }
}

impl<'s, 'e: 's> From<&'e Ephemeral> for &'s Scalar {
    fn from(source: &'e Ephemeral) -> &'s Scalar {
        &source.0
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<'a, 'b> Mul<&'b RistrettoBasepointTable> for &'a Ephemeral {
    type Output = RistrettoPoint;

    fn mul(self, other: &'b RistrettoBasepointTable) -> RistrettoPoint {
        &self.0 * other
    }
}

impl<'a, 'b> Mul<&'a Ephemeral> for &'b RistrettoBasepointTable {
    type Output = RistrettoPoint;

    fn mul(self, other: &'a Ephemeral) -> RistrettoPoint {
        self * &other.0
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a Ephemeral {
    type Output = RistrettoPoint;

    fn mul(self, other: &'b RistrettoPoint) -> RistrettoPoint {
        &self.0 * other
    }
}

impl<'a, > Mul<&'a Ephemeral> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn mul(self, other: &'a Ephemeral) -> RistrettoPoint {
        self * &other.0
    }
}

impl<'b> Mul<&'b RistrettoPoint> for Ephemeral {
    type Output = RistrettoPoint;

    fn mul(self, other: &'b RistrettoPoint) -> RistrettoPoint {
        &self.0 * other
    }
}

impl<'a> Mul<RistrettoPoint> for &'a Ephemeral {
    type Output = RistrettoPoint;

    fn mul(self, other: RistrettoPoint) -> RistrettoPoint {
        &self.0 * other
    }
}

impl<'b> Mul<Ephemeral> for &'b RistrettoPoint {
    type Output = RistrettoPoint;

    fn mul(self, other: Ephemeral) -> RistrettoPoint {
        self * &other.0
    }
}

impl Mul<RistrettoPoint> for Ephemeral {
    type Output = RistrettoPoint;

    fn mul(self, other: RistrettoPoint) -> RistrettoPoint {
        &self.0 * other
    }
}

impl Mul<Ephemeral> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn mul(self, other: Ephemeral) -> RistrettoPoint {
        self * &other.0
    }
}

#[derive(Clone, Debug, Default)]
pub struct Nonces(pub(crate) Vec<Ephemeral>);

impl Drop for Nonces {
    fn drop(&mut self) {
        for x in self.0.iter_mut() {
            x.clear();
        }
    }
}

impl Index<usize> for Nonces {
    type Output = Ephemeral;

    fn index(&self, idx: usize) -> &Ephemeral {
        &self.0[idx]
    }
}

impl Nonces {
    pub fn new<R>(
        csprng: &mut R,
        size: usize,
    ) -> Nonces
    where
        R: CryptoRng + RngCore
    {
        let mut v: Vec<Ephemeral> = Vec::with_capacity(size);

        for _ in 0..size {
            v.push(Ephemeral(Scalar::random(csprng)));
        }

        Nonces(v)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Ephemeral> {
        self.0.iter()
    }
}
