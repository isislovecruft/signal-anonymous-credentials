// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use errors::CredentialError;

pub const NUMBER_OF_ATTRIBUTES: usize = 1;

/// The `SystemParameters` define the system-wide context in which the anonymous
/// credentials scheme and its proofs are constructed within.
///
/// They are defined as \\( \( \mathbb{G}, p, G, H \) \\) where:
///
/// * \\( \mathbb{G} \\) is a group with order \\( p \\), where
///   `p` is a `k`-bit prime (`k = 255` in the case of using the Ristretto255
///   group),
/// * `g` and `h` are generators of `G`,
/// * `log_g(h)` is unknown, that is `h` is chosen as a distinguished basepoint
///   which is orthogonal to `g`.
///
//
// DOCDOC fix above to use latex
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemParameters {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl SystemParameters {
    pub fn from_bytes(bytes: &[u8]) -> Result<SystemParameters, CredentialError> {
        assert!(bytes.len() == 32);

        let mut g_bytes = [0u8; 32];
        let mut h_bytes = [0u8; 32];

        g_bytes.copy_from_slice(&bytes[00..32]);
        h_bytes.copy_from_slice(&bytes[32..64]);

        Ok(SystemParameters {
            g: CompressedRistretto(g_bytes).decompress()?,
            h: CompressedRistretto(h_bytes).decompress()?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64);

        v.extend(self.g.compress().to_bytes().iter());
        v.extend(self.h.compress().to_bytes().iter());

        v
    }
}

// XXX use hyphae notation
impl From<RistrettoPoint> for SystemParameters {
    /// Construct new system parameters from a chosen basepoint, `h`.
    ///
    /// # Inputs
    ///
    /// * `h`, a generator of the group `G`, which also has generator `g`, where
    /// h is chosen orthogonally such that `log_g(h)` is unknown.
    ///
    /// # Returns
    ///
    /// The `SystemParameters` for an anonymous credential protocol.
    fn from(h: RistrettoPoint) -> SystemParameters {
        debug_assert!(h != RISTRETTO_BASEPOINT_POINT);

        SystemParameters {
            g: RISTRETTO_BASEPOINT_POINT,
            h: h,
        }
    }
}

impl From<[u8; 32]> for SystemParameters {
    /// Construct new system parameters from a `secret`.
    ///
    /// The `secret` will be used to derive the basepoint, `h`.
    ///
    /// # Inputs
    ///
    /// * `secret`, 32 secretly chosen random bytes. This is only supplied by a
    ///   credential issuer.
    ///
    /// # Returns
    ///
    /// The `SystemParameters` for an anonymous credential protocol.
    fn from(secret: [u8; 32]) -> SystemParameters {
        let h = &Scalar::from_bytes_mod_order(secret) * &RISTRETTO_BASEPOINT_TABLE;

        h.into()
    }
}
