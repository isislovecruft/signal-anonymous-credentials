// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Zero-knowledge proofs.
//!
//! # Note
//!
//! The notation and variable names used throughout this module are that of
//! [LdV'17](https://patternsinthevoid.net/hyphae/hyphae.pdf), not those of
//! [CMZ'13](https://eprint.iacr.org/2013/516.pdf) because the latter was
//! missing signification details of the construction.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

// rustc thinks the MultiscalarMul traits are unused, possibly because
// their usage occurs in submodules only.
#[allow(unused_imports)]
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};

use merlin::Transcript;

use rand::thread_rng;

#[cfg(not(feature = "std"))]
use core::iter;
#[cfg(feature = "std")]
use std::iter;

pub mod blind_attributes {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Secrets<'a> {
        pub d: &'a Scalar,
        pub e0: &'a Scalar,
        pub m0: &'a Scalar,
        pub nonce: &'a Scalar,
    }

    #[derive(Copy, Clone)]
    pub struct Publics<'a> {
        pub B: &'a RistrettoPoint,
        pub A: &'a RistrettoPoint,
        pub D: &'a RistrettoPoint,
        pub roster_entry: &'a RistrettoPoint,
        pub encrypted_attribute_0_0: &'a RistrettoPoint,
        pub encrypted_attribute_0_1: &'a RistrettoPoint,
    }

    struct Commitments {
        D: RistrettoPoint,
        encrypted_attribute_0_0: RistrettoPoint,
        encrypted_attribute_0_1: RistrettoPoint,
        roster_entry: RistrettoPoint,
    }

    struct Randomnesses {
        d: Scalar,
        e0: Scalar,
        m0: Scalar,
        nonce: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    struct Responses {
        d: Scalar,
        e0: Scalar,
        m0: Scalar,
        nonce: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    pub struct Proof {
        challenge: Scalar,
        responses: Responses,
    }

    impl Proof {
        /// Create a `Proof` from the given `Publics` and `Secrets`.
        #[allow(dead_code)]
        pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Proof {
            transcript.commit_bytes(b"domain-sep", "_blind_attributes".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("D".as_bytes(), publics.D.compress().as_bytes());
            transcript.commit_bytes(
                "roster_entry".as_bytes(),
                publics.roster_entry.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "encrypted_attribute_0_0".as_bytes(),
                publics.encrypted_attribute_0_0.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "encrypted_attribute_0_1".as_bytes(),
                publics.encrypted_attribute_0_1.compress().as_bytes(),
            );
            let rng_ctor = transcript.fork_transcript();
            let rng_ctor = rng_ctor.commit_witness_bytes("d".as_bytes(), secrets.d.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("e0".as_bytes(), secrets.e0.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("m0".as_bytes(), secrets.m0.as_bytes());
            let rng_ctor =
                rng_ctor.commit_witness_bytes("nonce".as_bytes(), secrets.nonce.as_bytes());
            let mut transcript_rng = rng_ctor.reseed_from_rng(&mut thread_rng());
            let rand = Randomnesses {
                d: Scalar::random(&mut transcript_rng),
                e0: Scalar::random(&mut transcript_rng),
                m0: Scalar::random(&mut transcript_rng),
                nonce: Scalar::random(&mut transcript_rng),
            };
            let commitments = Commitments {
                D: RistrettoPoint::multiscalar_mul(&[rand.d], &[*(publics.B)]),
                encrypted_attribute_0_0: RistrettoPoint::multiscalar_mul(
                    &[rand.e0],
                    &[*(publics.B)],
                ),
                encrypted_attribute_0_1: RistrettoPoint::multiscalar_mul(
                    &[rand.m0, rand.e0],
                    &[*(publics.B), *(publics.D)],
                ),
                roster_entry: RistrettoPoint::multiscalar_mul(
                    &[rand.m0, rand.nonce],
                    &[*(publics.A), *(publics.B)],
                ),
            };
            transcript.commit_bytes("com D".as_bytes(), commitments.D.compress().as_bytes());
            transcript.commit_bytes(
                "com encrypted_attribute_0_0".as_bytes(),
                commitments.encrypted_attribute_0_0.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com encrypted_attribute_0_1".as_bytes(),
                commitments.encrypted_attribute_0_1.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com roster_entry".as_bytes(),
                commitments.roster_entry.compress().as_bytes(),
            );
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let responses = Responses {
                d: &(&challenge * secrets.d) + &rand.d,
                e0: &(&challenge * secrets.e0) + &rand.e0,
                m0: &(&challenge * secrets.m0) + &rand.m0,
                nonce: &(&challenge * secrets.nonce) + &rand.nonce,
            };
            Proof { challenge: challenge, responses: responses }
        }

        /// Verify the `Proof` using the public parameters `Publics`.
        #[allow(dead_code)]
        pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
            let responses = &self.responses;
            let minus_c = -&self.challenge;
            let commitments = Commitments {
                D: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.d]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B)]).into_iter().chain(iter::once(publics.D)),
                ),
                encrypted_attribute_0_0: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.e0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B)])
                        .into_iter()
                        .chain(iter::once(publics.encrypted_attribute_0_0)),
                ),
                encrypted_attribute_0_1: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.m0, responses.e0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B), *(publics.D)])
                        .into_iter()
                        .chain(iter::once(publics.encrypted_attribute_0_1)),
                ),
                roster_entry: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.m0, responses.nonce]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.A), *(publics.B)])
                        .into_iter()
                        .chain(iter::once(publics.roster_entry)),
                ),
            };
            transcript.commit_bytes(b"domain-sep", "_blind_attributes".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("D".as_bytes(), publics.D.compress().as_bytes());
            transcript.commit_bytes(
                "roster_entry".as_bytes(),
                publics.roster_entry.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "encrypted_attribute_0_0".as_bytes(),
                publics.encrypted_attribute_0_0.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "encrypted_attribute_0_1".as_bytes(),
                publics.encrypted_attribute_0_1.compress().as_bytes(),
            );
            transcript.commit_bytes("com D".as_bytes(), commitments.D.compress().as_bytes());
            transcript.commit_bytes(
                "com encrypted_attribute_0_0".as_bytes(),
                commitments.encrypted_attribute_0_0.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com encrypted_attribute_0_1".as_bytes(),
                commitments.encrypted_attribute_0_1.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com roster_entry".as_bytes(),
                commitments.roster_entry.compress().as_bytes(),
            );
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            if challenge == self.challenge {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}

pub mod revealed_attributes {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Secrets<'a> {
        pub nonce: &'a Scalar,
        pub phone_number: &'a Scalar,
    }

    #[derive(Copy, Clone)]
    pub struct Publics<'a> {
        pub g: &'a RistrettoPoint,
        pub h: &'a RistrettoPoint,
        pub roster_entry_commitment_number: &'a RistrettoPoint,
    }

    struct Commitments {
        roster_entry_commitment_number: RistrettoPoint,
    }

    struct Randomnesses {
        nonce: Scalar,
        phone_number: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    struct Responses {
        nonce: Scalar,
        phone_number: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    pub struct Proof {
        challenge: Scalar,
        responses: Responses,
    }

    impl Proof {
        /// Create a `Proof` from the given `Publics` and `Secrets`.
        #[allow(dead_code)]
        pub fn create(transcript: &mut Transcript, publics: Publics, secrets: Secrets) -> Proof {
            transcript.commit_bytes(b"domain-sep", "revealed_attributes".as_bytes());
            transcript.commit_bytes("g".as_bytes(), publics.g.compress().as_bytes());
            transcript.commit_bytes("h".as_bytes(), publics.h.compress().as_bytes());
            transcript.commit_bytes(
                "roster_entry_commitment_number".as_bytes(),
                publics.roster_entry_commitment_number.compress().as_bytes(),
            );
            let rng_ctor = transcript.fork_transcript();
            let rng_ctor =
                rng_ctor.commit_witness_bytes("nonce".as_bytes(), secrets.nonce.as_bytes());
            let rng_ctor = rng_ctor
                .commit_witness_bytes("phone_number".as_bytes(), secrets.phone_number.as_bytes());
            let mut transcript_rng = rng_ctor.reseed_from_rng(&mut thread_rng());
            let rand = Randomnesses {
                nonce: Scalar::random(&mut transcript_rng),
                phone_number: Scalar::random(&mut transcript_rng),
            };
            let commitments = Commitments {
                roster_entry_commitment_number: RistrettoPoint::multiscalar_mul(
                    &[rand.phone_number, rand.nonce],
                    &[*(publics.h), *(publics.g)],
                ),
            };
            transcript.commit_bytes(
                "com roster_entry_commitment_number".as_bytes(),
                commitments.roster_entry_commitment_number.compress().as_bytes(),
            );
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let responses = Responses {
                nonce: &(&challenge * secrets.nonce) + &rand.nonce,
                phone_number: &(&challenge * secrets.phone_number) + &rand.phone_number,
            };
            Proof { challenge: challenge, responses: responses }
        }

        /// Verify the `Proof` using the public parameters `Publics`.
        #[allow(dead_code)]
        pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
            let responses = &self.responses;
            let minus_c = -&self.challenge;
            let commitments = Commitments {
                roster_entry_commitment_number: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.phone_number, responses.nonce])
                        .into_iter()
                        .chain(iter::once(&(minus_c))),
                    (&[*(publics.h), *(publics.g)])
                        .into_iter()
                        .chain(iter::once(publics.roster_entry_commitment_number)),
                ),
            };
            transcript.commit_bytes(b"domain-sep", "revealed_attributes".as_bytes());
            transcript.commit_bytes("g".as_bytes(), publics.g.compress().as_bytes());
            transcript.commit_bytes("h".as_bytes(), publics.h.compress().as_bytes());
            transcript.commit_bytes(
                "roster_entry_commitment_number".as_bytes(),
                publics.roster_entry_commitment_number.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com roster_entry_commitment_number".as_bytes(),
                commitments.roster_entry_commitment_number.compress().as_bytes(),
            );
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            if challenge == self.challenge {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}
