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

pub mod issuance_revealed {
    use super::*;

    #[derive(Clone, Copy)]
    pub struct Secrets<'a> {
        pub x0: &'a Scalar,
        pub x1: &'a Scalar,
        pub x0_tilde: &'a Scalar,
        pub m1x1: &'a Scalar,
    }

    #[derive(Clone, Copy)]
    pub struct Publics<'a> {
        pub P: &'a RistrettoPoint,
        pub Q: &'a RistrettoPoint,
        pub Cx0: &'a RistrettoPoint,
        pub B: &'a RistrettoPoint,
        pub A: &'a RistrettoPoint,
        pub X1: &'a RistrettoPoint,
    }

    struct Commitments {
        Q: RistrettoPoint,
        Cx0: RistrettoPoint,
        X1: RistrettoPoint,
    }

    struct Randomnesses {
        x0: Scalar,
        x1: Scalar,
        x0_tilde: Scalar,
        m1x1: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    struct Responses {
        x0: Scalar,
        x1: Scalar,
        x0_tilde: Scalar,
        m1x1: Scalar,
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
            transcript.commit_bytes(b"domain-sep", "issuance_revealed".as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("Q".as_bytes(), publics.Q.compress().as_bytes());
            transcript.commit_bytes("Cx0".as_bytes(), publics.Cx0.compress().as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("X1".as_bytes(), publics.X1.compress().as_bytes());
            let rng_ctor = transcript.fork_transcript();
            let rng_ctor = rng_ctor.commit_witness_bytes("x0".as_bytes(), secrets.x0.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("x1".as_bytes(), secrets.x1.as_bytes());
            let rng_ctor =
                rng_ctor.commit_witness_bytes("x0_tilde".as_bytes(), secrets.x0_tilde.as_bytes());
            let rng_ctor =
                rng_ctor.commit_witness_bytes("m1x1".as_bytes(), secrets.m1x1.as_bytes());
            let mut transcript_rng = rng_ctor.reseed_from_rng(&mut thread_rng());
            let rand = Randomnesses {
                x0: Scalar::random(&mut transcript_rng),
                x1: Scalar::random(&mut transcript_rng),
                x0_tilde: Scalar::random(&mut transcript_rng),
                m1x1: Scalar::random(&mut transcript_rng),
            };
            let commitments = Commitments {
                Q: RistrettoPoint::multiscalar_mul(
                    &[rand.x0, rand.m1x1],
                    &[*(publics.P), *(publics.P)],
                ),
                Cx0: RistrettoPoint::multiscalar_mul(
                    &[rand.x0, rand.x0_tilde],
                    &[*(publics.B), *(publics.A)],
                ),
                X1: RistrettoPoint::multiscalar_mul(&[rand.x1], &[*(publics.A)]),
            };
            transcript.commit_bytes("com Q".as_bytes(), commitments.Q.compress().as_bytes());
            transcript.commit_bytes("com Cx0".as_bytes(), commitments.Cx0.compress().as_bytes());
            transcript.commit_bytes("com X1".as_bytes(), commitments.X1.compress().as_bytes());
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let responses = Responses {
                x0: &(&challenge * secrets.x0) + &rand.x0,
                x1: &(&challenge * secrets.x1) + &rand.x1,
                x0_tilde: &(&challenge * secrets.x0_tilde) + &rand.x0_tilde,
                m1x1: &(&challenge * secrets.m1x1) + &rand.m1x1,
            };
            Proof { challenge: challenge, responses: responses }
        }

        /// Verify the `Proof` using the public parameters `Publics`.
        #[allow(dead_code)]
        pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
            let responses = &self.responses;
            let minus_c = -&self.challenge;
            let commitments = Commitments {
                Q: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.x0, responses.m1x1]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.P), *(publics.P)]).into_iter().chain(iter::once(publics.Q)),
                ),
                Cx0: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.x0, responses.x0_tilde]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B), *(publics.A)]).into_iter().chain(iter::once(publics.Cx0)),
                ),
                X1: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.x1]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.A)]).into_iter().chain(iter::once(publics.X1)),
                ),
            };
            transcript.commit_bytes(b"domain-sep", "issuance_revealed".as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("Q".as_bytes(), publics.Q.compress().as_bytes());
            transcript.commit_bytes("Cx0".as_bytes(), publics.Cx0.compress().as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("X1".as_bytes(), publics.X1.compress().as_bytes());
            transcript.commit_bytes("com Q".as_bytes(), commitments.Q.compress().as_bytes());
            transcript.commit_bytes("com Cx0".as_bytes(), commitments.Cx0.compress().as_bytes());
            transcript.commit_bytes("com X1".as_bytes(), commitments.X1.compress().as_bytes());
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

pub mod attributes_blinded {
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
        pub encrypted_attribute_0_0: &'a RistrettoPoint,
        pub encrypted_attribute_0_1: &'a RistrettoPoint,
    }

    struct Commitments {
        D: RistrettoPoint,
        encrypted_attribute_0_0: RistrettoPoint,
        encrypted_attribute_0_1: RistrettoPoint,
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
            transcript.commit_bytes(b"domain-sep", "attributes_blinded".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("D".as_bytes(), publics.D.compress().as_bytes());
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
            };
            transcript.commit_bytes(b"domain-sep", "attributes_blinded".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("D".as_bytes(), publics.D.compress().as_bytes());
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

pub mod issuance_blinded {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Secrets<'a> {
        pub x0_tilde: &'a Scalar,
        pub x0: &'a Scalar,
        pub x1: &'a Scalar,
        pub s: &'a Scalar,
        pub b: &'a Scalar,
        pub t0: &'a Scalar,
    }

    #[derive(Copy, Clone)]
    pub struct Publics<'a> {
        pub B: &'a RistrettoPoint,
        pub A: &'a RistrettoPoint,
        pub X0: &'a RistrettoPoint,
        pub X1: &'a RistrettoPoint,
        pub D: &'a RistrettoPoint,
        pub P: &'a RistrettoPoint,
        pub T0_0: &'a RistrettoPoint,
        pub T0_1: &'a RistrettoPoint,
        pub EQ_commitment: &'a RistrettoPoint,
        pub EQ_encryption: &'a RistrettoPoint,
        pub encrypted_attribute_0_0: &'a RistrettoPoint,
        pub encrypted_attribute_0_1: &'a RistrettoPoint,
    }

    struct Commitments {
        X0: RistrettoPoint,
        X1: RistrettoPoint,
        P: RistrettoPoint,
        T0_0: RistrettoPoint,
        T0_1: RistrettoPoint,
        EQ_commitment: RistrettoPoint,
        EQ_encryption: RistrettoPoint,
    }

    struct Randomnesses {
        x0_tilde: Scalar,
        x0: Scalar,
        x1: Scalar,
        s: Scalar,
        b: Scalar,
        t0: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    struct Responses {
        x0_tilde: Scalar,
        x0: Scalar,
        x1: Scalar,
        s: Scalar,
        b: Scalar,
        t0: Scalar,
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
            transcript.commit_bytes(b"domain-sep", "issuance_blinded".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("X0".as_bytes(), publics.X0.compress().as_bytes());
            transcript.commit_bytes("X1".as_bytes(), publics.X1.compress().as_bytes());
            transcript.commit_bytes("D".as_bytes(), publics.D.compress().as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("T0_0".as_bytes(), publics.T0_0.compress().as_bytes());
            transcript.commit_bytes("T0_1".as_bytes(), publics.T0_1.compress().as_bytes());
            transcript.commit_bytes(
                "EQ_commitment".as_bytes(),
                publics.EQ_commitment.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "EQ_encryption".as_bytes(),
                publics.EQ_encryption.compress().as_bytes(),
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
            let rng_ctor =
                rng_ctor.commit_witness_bytes("x0_tilde".as_bytes(), secrets.x0_tilde.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("x0".as_bytes(), secrets.x0.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("x1".as_bytes(), secrets.x1.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("s".as_bytes(), secrets.s.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("b".as_bytes(), secrets.b.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("t0".as_bytes(), secrets.t0.as_bytes());
            let mut transcript_rng = rng_ctor.reseed_from_rng(&mut thread_rng());
            let rand = Randomnesses {
                x0_tilde: Scalar::random(&mut transcript_rng),
                x0: Scalar::random(&mut transcript_rng),
                x1: Scalar::random(&mut transcript_rng),
                s: Scalar::random(&mut transcript_rng),
                b: Scalar::random(&mut transcript_rng),
                t0: Scalar::random(&mut transcript_rng),
            };
            let commitments = Commitments {
                X0: RistrettoPoint::multiscalar_mul(
                    &[rand.x0, rand.x0_tilde],
                    &[*(publics.B), *(publics.A)],
                ),
                X1: RistrettoPoint::multiscalar_mul(&[rand.x1], &[*(publics.A)]),
                P: RistrettoPoint::multiscalar_mul(&[rand.b], &[*(publics.B)]),
                T0_0: RistrettoPoint::multiscalar_mul(&[rand.b], &[*(publics.X0)]),
                T0_1: RistrettoPoint::multiscalar_mul(&[rand.t0], &[*(publics.A)]),
                EQ_commitment: RistrettoPoint::multiscalar_mul(
                    &[rand.s, rand.t0],
                    &[*(publics.B), *(publics.encrypted_attribute_0_0)],
                ),
                EQ_encryption: RistrettoPoint::multiscalar_mul(
                    &[rand.s, rand.t0],
                    &[*(publics.D), *(publics.encrypted_attribute_0_1)],
                ),
            };
            transcript.commit_bytes("com X0".as_bytes(), commitments.X0.compress().as_bytes());
            transcript.commit_bytes("com X1".as_bytes(), commitments.X1.compress().as_bytes());
            transcript.commit_bytes("com P".as_bytes(), commitments.P.compress().as_bytes());
            transcript.commit_bytes("com T0_0".as_bytes(), commitments.T0_0.compress().as_bytes());
            transcript.commit_bytes("com T0_1".as_bytes(), commitments.T0_1.compress().as_bytes());
            transcript.commit_bytes(
                "com EQ_commitment".as_bytes(),
                commitments.EQ_commitment.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com EQ_encryption".as_bytes(),
                commitments.EQ_encryption.compress().as_bytes(),
            );
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let responses = Responses {
                x0_tilde: &(&challenge * secrets.x0_tilde) + &rand.x0_tilde,
                x0: &(&challenge * secrets.x0) + &rand.x0,
                x1: &(&challenge * secrets.x1) + &rand.x1,
                s: &(&challenge * secrets.s) + &rand.s,
                b: &(&challenge * secrets.b) + &rand.b,
                t0: &(&challenge * secrets.t0) + &rand.t0,
            };
            Proof { challenge: challenge, responses: responses }
        }

        /// Verify the `Proof` using the public parameters `Publics`.
        #[allow(dead_code)]
        pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
            let responses = &self.responses;
            let minus_c = -&self.challenge;
            let commitments = Commitments {
                X0: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.x0, responses.x0_tilde]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B), *(publics.A)]).into_iter().chain(iter::once(publics.X0)),
                ),
                X1: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.x1]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.A)]).into_iter().chain(iter::once(publics.X1)),
                ),
                P: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.b]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B)]).into_iter().chain(iter::once(publics.P)),
                ),
                T0_0: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.b]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.X0)]).into_iter().chain(iter::once(publics.T0_0)),
                ),
                T0_1: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.t0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.A)]).into_iter().chain(iter::once(publics.T0_1)),
                ),
                EQ_commitment: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.s, responses.t0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.B), *(publics.encrypted_attribute_0_0)])
                        .into_iter()
                        .chain(iter::once(publics.EQ_commitment)),
                ),
                EQ_encryption: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.s, responses.t0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.D), *(publics.encrypted_attribute_0_1)])
                        .into_iter()
                        .chain(iter::once(publics.EQ_encryption)),
                ),
            };
            transcript.commit_bytes(b"domain-sep", "issuance_blinded".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("X0".as_bytes(), publics.X0.compress().as_bytes());
            transcript.commit_bytes("X1".as_bytes(), publics.X1.compress().as_bytes());
            transcript.commit_bytes("D".as_bytes(), publics.D.compress().as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("T0_0".as_bytes(), publics.T0_0.compress().as_bytes());
            transcript.commit_bytes("T0_1".as_bytes(), publics.T0_1.compress().as_bytes());
            transcript.commit_bytes(
                "EQ_commitment".as_bytes(),
                publics.EQ_commitment.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "EQ_encryption".as_bytes(),
                publics.EQ_encryption.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "encrypted_attribute_0_0".as_bytes(),
                publics.encrypted_attribute_0_0.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "encrypted_attribute_0_1".as_bytes(),
                publics.encrypted_attribute_0_1.compress().as_bytes(),
            );
            transcript.commit_bytes("com X0".as_bytes(), commitments.X0.compress().as_bytes());
            transcript.commit_bytes("com X1".as_bytes(), commitments.X1.compress().as_bytes());
            transcript.commit_bytes("com P".as_bytes(), commitments.P.compress().as_bytes());
            transcript.commit_bytes("com T0_0".as_bytes(), commitments.T0_0.compress().as_bytes());
            transcript.commit_bytes("com T0_1".as_bytes(), commitments.T0_1.compress().as_bytes());
            transcript.commit_bytes(
                "com EQ_commitment".as_bytes(),
                commitments.EQ_commitment.compress().as_bytes(),
            );
            transcript.commit_bytes(
                "com EQ_encryption".as_bytes(),
                commitments.EQ_encryption.compress().as_bytes(),
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

pub mod valid_credential {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Secrets<'a> {
        pub m0: &'a Scalar,
        pub z0: &'a Scalar,
        pub minus_zQ: &'a Scalar,
    }

    #[derive(Copy, Clone)]
    pub struct Publics<'a> {
        pub B: &'a RistrettoPoint,
        pub A: &'a RistrettoPoint,
        pub X0: &'a RistrettoPoint,
        pub P: &'a RistrettoPoint,
        pub V: &'a RistrettoPoint,
        pub Cm0: &'a RistrettoPoint,
    }

    struct Commitments {
        Cm0: RistrettoPoint,
        V: RistrettoPoint,
    }

    struct Randomnesses {
        m0: Scalar,
        z0: Scalar,
        minus_zQ: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    struct Responses {
        m0: Scalar,
        z0: Scalar,
        minus_zQ: Scalar,
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
            transcript.commit_bytes(b"domain-sep", "valid_credential".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("X0".as_bytes(), publics.X0.compress().as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("V".as_bytes(), publics.V.compress().as_bytes());
            transcript.commit_bytes("Cm0".as_bytes(), publics.Cm0.compress().as_bytes());
            let rng_ctor = transcript.fork_transcript();
            let rng_ctor = rng_ctor.commit_witness_bytes("m0".as_bytes(), secrets.m0.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("z0".as_bytes(), secrets.z0.as_bytes());
            let rng_ctor =
                rng_ctor.commit_witness_bytes("minus_zQ".as_bytes(), secrets.minus_zQ.as_bytes());
            let mut transcript_rng = rng_ctor.reseed_from_rng(&mut thread_rng());
            let rand = Randomnesses {
                m0: Scalar::random(&mut transcript_rng),
                z0: Scalar::random(&mut transcript_rng),
                minus_zQ: Scalar::random(&mut transcript_rng),
            };
            let commitments = Commitments {
                Cm0: RistrettoPoint::multiscalar_mul(
                    &[rand.m0, rand.z0],
                    &[*(publics.P), *(publics.A)],
                ),
                V: RistrettoPoint::multiscalar_mul(
                    &[rand.z0, rand.minus_zQ],
                    &[*(publics.X0), *(publics.A)],
                ),
            };
            transcript.commit_bytes("com Cm0".as_bytes(), commitments.Cm0.compress().as_bytes());
            transcript.commit_bytes("com V".as_bytes(), commitments.V.compress().as_bytes());
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let responses = Responses {
                m0: &(&challenge * secrets.m0) + &rand.m0,
                z0: &(&challenge * secrets.z0) + &rand.z0,
                minus_zQ: &(&challenge * secrets.minus_zQ) + &rand.minus_zQ,
            };
            Proof { challenge: challenge, responses: responses }
        }

        /// Verify the `Proof` using the public parameters `Publics`.
        #[allow(dead_code)]
        pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
            let responses = &self.responses;
            let minus_c = -&self.challenge;
            let commitments = Commitments {
                Cm0: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.m0, responses.z0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.P), *(publics.A)]).into_iter().chain(iter::once(publics.Cm0)),
                ),
                V: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.z0, responses.minus_zQ]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.X0), *(publics.A)]).into_iter().chain(iter::once(publics.V)),
                ),
            };
            transcript.commit_bytes(b"domain-sep", "valid_credential".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("X0".as_bytes(), publics.X0.compress().as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("V".as_bytes(), publics.V.compress().as_bytes());
            transcript.commit_bytes("Cm0".as_bytes(), publics.Cm0.compress().as_bytes());
            transcript.commit_bytes("com Cm0".as_bytes(), commitments.Cm0.compress().as_bytes());
            transcript.commit_bytes("com V".as_bytes(), commitments.V.compress().as_bytes());
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

pub mod committed_values_equal {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Secrets<'a> {
        pub m0: &'a Scalar,
        pub z0: &'a Scalar,
        pub z1: &'a Scalar,
    }

    #[derive(Copy, Clone)]
    pub struct Publics<'a> {
        pub B: &'a RistrettoPoint,
        pub A: &'a RistrettoPoint,
        pub P: &'a RistrettoPoint,
        pub Cm0: &'a RistrettoPoint,
        pub Cm1: &'a RistrettoPoint,
    }

    struct Commitments {
        Cm0: RistrettoPoint,
        Cm1: RistrettoPoint,
    }

    struct Randomnesses {
        m0: Scalar,
        z0: Scalar,
        z1: Scalar,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    struct Responses {
        m0: Scalar,
        z0: Scalar,
        z1: Scalar,
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
            transcript.commit_bytes(b"domain-sep", "committed_values_equal".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("Cm0".as_bytes(), publics.Cm0.compress().as_bytes());
            transcript.commit_bytes("Cm1".as_bytes(), publics.Cm1.compress().as_bytes());
            let rng_ctor = transcript.fork_transcript();
            let rng_ctor = rng_ctor.commit_witness_bytes("m0".as_bytes(), secrets.m0.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("z0".as_bytes(), secrets.z0.as_bytes());
            let rng_ctor = rng_ctor.commit_witness_bytes("z1".as_bytes(), secrets.z1.as_bytes());
            let mut transcript_rng = rng_ctor.reseed_from_rng(&mut thread_rng());
            let rand = Randomnesses {
                m0: Scalar::random(&mut transcript_rng),
                z0: Scalar::random(&mut transcript_rng),
                z1: Scalar::random(&mut transcript_rng),
            };
            let commitments = Commitments {
                Cm0: RistrettoPoint::multiscalar_mul(
                    &[rand.m0, rand.z0],
                    &[*(publics.P), *(publics.A)],
                ),
                Cm1: RistrettoPoint::multiscalar_mul(
                    &[rand.m0, rand.z1],
                    &[*(publics.A), *(publics.B)],
                ),
            };
            transcript.commit_bytes("com Cm0".as_bytes(), commitments.Cm0.compress().as_bytes());
            transcript.commit_bytes("com Cm1".as_bytes(), commitments.Cm1.compress().as_bytes());
            let challenge = {
                let mut bytes = [0; 64];
                transcript.challenge_bytes(b"chal", &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let responses = Responses {
                m0: &(&challenge * secrets.m0) + &rand.m0,
                z0: &(&challenge * secrets.z0) + &rand.z0,
                z1: &(&challenge * secrets.z1) + &rand.z1,
            };
            Proof { challenge: challenge, responses: responses }
        }

        /// Verify the `Proof` using the public parameters `Publics`.
        #[allow(dead_code)]
        pub fn verify(&self, transcript: &mut Transcript, publics: Publics) -> Result<(), ()> {
            let responses = &self.responses;
            let minus_c = -&self.challenge;
            let commitments = Commitments {
                Cm0: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.m0, responses.z0]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.P), *(publics.A)]).into_iter().chain(iter::once(publics.Cm0)),
                ),
                Cm1: RistrettoPoint::vartime_multiscalar_mul(
                    (&[responses.m0, responses.z1]).into_iter().chain(iter::once(&(minus_c))),
                    (&[*(publics.A), *(publics.B)]).into_iter().chain(iter::once(publics.Cm1)),
                ),
            };
            transcript.commit_bytes(b"domain-sep", "committed_values_equal".as_bytes());
            transcript.commit_bytes("B".as_bytes(), publics.B.compress().as_bytes());
            transcript.commit_bytes("A".as_bytes(), publics.A.compress().as_bytes());
            transcript.commit_bytes("P".as_bytes(), publics.P.compress().as_bytes());
            transcript.commit_bytes("Cm0".as_bytes(), publics.Cm0.compress().as_bytes());
            transcript.commit_bytes("Cm1".as_bytes(), publics.Cm1.compress().as_bytes());
            transcript.commit_bytes("com Cm0".as_bytes(), commitments.Cm0.compress().as_bytes());
            transcript.commit_bytes("com Cm1".as_bytes(), commitments.Cm1.compress().as_bytes());
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
