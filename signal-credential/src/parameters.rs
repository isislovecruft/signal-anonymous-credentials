// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use curve25519_dalek::constants::BASEPOINT_ORDER;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;


/// The `SystemParameters` define the system-wide context in which the anonymous
/// credentials scheme and its proofs are constructed within.
///
/// They are defined as `(G, p, g, h)` where:
///
/// * `G` is a group with order `p`,
/// * `p` is a `k`-bit prime (`k = 255` in the case of using the Ristretto255
///   group),
/// * `g` and `h` are generators of `G`,
/// * `log_g(h)` is unknown, that is `h` is chosen as a distinguished basepoint
///   which is orthogonal to `g`.
///
/// Although `g` and `h` are basepoints, they are written lowercased, in order
/// to follow the notation used in the CMZ'13 paper.
///
/// # Note
///
/// When owned by a `CredentialUser` the `h` member is a `Non` because a
/// user must not know `h`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemParameters {
    pub(crate) p: Scalar,
    pub(crate) g: RistrettoPoint,
    pub(crate) h: RistrettoPoint,
}

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

        SystemParameters{ p: BASEPOINT_ORDER,
                          g: RISTRETTO_BASEPOINT_POINT,
                          h: h, }
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
