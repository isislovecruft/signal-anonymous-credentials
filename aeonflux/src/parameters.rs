// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use rand_core::CryptoRng;
use rand_core::RngCore;

use errors::CredentialError;

pub const NUMBER_OF_ATTRIBUTES: usize = 1;
pub const SIZEOF_SYSTEM_PARAMETERS: usize = 64;

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
        if bytes.len() != SIZEOF_SYSTEM_PARAMETERS {
            return Err(CredentialError::NoSystemParameters);
        }

        let mut g_bytes = [0u8; 32];
        let mut h_bytes = [0u8; 32];

        g_bytes.copy_from_slice(&bytes[00..32]);
        h_bytes.copy_from_slice(&bytes[32..64]);

        let g: RistrettoPoint = match CompressedRistretto(g_bytes).decompress() {
            Some(x)  => x,
            None     => {
                // println!("Could not decode G from bytes: {:?}", g_bytes);
                return Err(CredentialError::PointDecompressionError);
            },
        };
        let h: RistrettoPoint = match CompressedRistretto(h_bytes).decompress() {
            Some(x) => x,
            None    => {
                // println!("Could not decode H from bytes: {:?}", h_bytes);
                return Err(CredentialError::PointDecompressionError);
            },
        };

        Ok(SystemParameters { g, h })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64);

        v.extend(self.g.compress().to_bytes().iter());
        v.extend(self.h.compress().to_bytes().iter());

        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SystemParameters,
                                         "A valid byte sequence representing a SystemParameters");

impl SystemParameters {
    /// Generate the `SystemParameters` randomly via an RNG.
    ///
    /// In order to never have a secret scalar in memory for generating the
    /// orthogonal basepoint, this method can be used to obtain bytes from the
    /// `csprng` and attempt to decompress them into a basepoint.
    pub fn hunt_and_peck<R>(
        csprng: &mut R,
    ) -> SystemParameters
    where
        R: RngCore + CryptoRng,
    {
        let mut tmp: [u8; 32] = [0u8; 32];
        let mut H: Option<RistrettoPoint> = None;

        while H.is_none() {
            csprng.fill_bytes(&mut tmp);

            // Extremely unlikely but we may as well be careful.
            if CompressedRistretto(tmp) != RISTRETTO_BASEPOINT_COMPRESSED {
                H = CompressedRistretto(tmp).decompress();
            }
        }

        SystemParameters {
            g: RISTRETTO_BASEPOINT_POINT,
            h: H.unwrap(),
        }
    }
}

// XXX use hyphae notation
impl From<RistrettoPoint> for SystemParameters {
    /// Construct new system parameters from a chosen basepoint, `h`.
    ///
    /// # Inputs
    ///
    /// * `h`, a generator of the group `G`, which also has generator `g`, where
    ///    `h` is chosen orthogonally such that `log_g(h)` is unknown.
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
    /// Construct the `SystemParameters` from a `CompressedRistretto` point.
    ///
    /// # Inputs
    ///
    /// * `h`, the compressed form a generator of the group `G`, which also has
    ///   generator `g`, where h is chosen orthogonally such that `log_g(h)` is
    ///   unknown.
    ///
    /// # Panics
    ///
    /// If `h` cannot be decompressed.
    ///
    /// # Returns
    ///
    /// The `SystemParameters` for an anonymous credential protocol.
    fn from(h: [u8; 32]) -> SystemParameters {
        debug_assert!(CompressedRistretto(h) != RISTRETTO_BASEPOINT_COMPRESSED);

        SystemParameters {
            g: RISTRETTO_BASEPOINT_POINT,
            h: CompressedRistretto(h).decompress().unwrap(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    const H: [u8; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                           93, 125, 218,  60,  36, 165, 166, 178,
                          118, 188,  77,  27, 133, 146, 193, 133,
                          234,  95,  69, 227, 213, 197,  84,  98, ];

    #[test]
    fn system_parameters_serialize_deserialize() {
        let system_parameters: SystemParameters = H.into();

        let serialized = system_parameters.to_bytes();
        let deserialized = SystemParameters::from_bytes(&serialized).unwrap();

        assert!(system_parameters == deserialized);
        assert!(&serialized[32..64] == &H);
    }

    #[test]
    fn system_parameters_from_bytes() {
        let bytes: [u8; 64] = [115, 121, 115, 116, 101, 109,  95, 112,
                                97, 114,  97, 109, 101, 116, 101, 114,
                               115,  95, 108, 101, 110, 103, 116, 104,
                                32, 105, 115,  32,  54,  52,  10, 115,
                               111, 109, 101,  32, 115, 104, 105, 116,
                                32, 119,  97, 115,  32, 109, 105, 115,
                               115, 105, 110, 103,  10, 146, 193, 133,
                               234,  95,  69, 227, 213, 197,  84,  98, ];
        let system_parameters = SystemParameters::from_bytes(&bytes);

        assert!(system_parameters.is_err());
    }

    #[test]
    fn hunt_and_peck() {
        let mut rng = thread_rng();

        SystemParameters::hunt_and_peck(&mut rng);
    }
}
