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

/// A NIPK showing correct non-blinded issuance.
///
/// # Inputs
///
/// Secrets:
///
/// * `x0, x1, x2` are the `Issuer`'s private key material.
/// * `x0_tilde` is a blinding factor for the secret key.
/// * `m1x1` is the message `m1` multiplied by the secret key `x1`.
/// * `m2x2` is the message `m2` multiplied by the secret key `x2`.
///
/// Publics:
///
/// * `u` is the aMAC nonce.
/// * `Cx0` is a Pedersen commitment to the secret key `x0`.
/// * `B` and `A` are generators of the group, where `A` is chosen orthogonally
///   such that `log_B(A)` is intractible.
/// * `X1, X2` are the issuer's public key material.
/// * `u_prime` is the aMAC tag.
//
// TODO The "m1x1" is `m1*x1` and is a hack because the zkp crate doesn't
// currently support multiplying to scalars together before multiplying them by
// the public point, so we multiply them before passing them into the
// macro-generated code as an additional secret value (since it depend on x1).
create_nipk!(issuance_revealed,
             (x0, x1, x0_tilde, m1x1),
             (P, Q, Cx0, B, A, X1)
             :
             Q = (P * x0 + P * m1x1),
             Cx0 = (B * x0 + A * x0_tilde),
             X1 = (A * x1)
);

/// A NIPK proving that the blinded attributes are valid elGamal encryptions
/// created with the user's public key.
///
/// # Inputs
///
/// Secrets:
///
/// * `d` the `User`'s private elGamal encryption key,
/// * `e0`...`en` the nonces used to form the elGamal encrypted attributes,
/// * `m0`...`mn` the plaintext attributes,
///
/// Publics:
///
/// * `B` the basepoint,
/// * `D` the `User`'s public elGamal encryption key,
/// * `encrypted_attribute_0`...`encrypted_attribute_n` the encrypted attributes,
///
/// # Proof Statements
///
// DOCDOC
create_nipk!(attributes_blinded,
             (d, e0, m0, nonce),
             (B, A, D, encrypted_attribute_0_0, encrypted_attribute_0_1)
             :
             D = (B * d),
             encrypted_attribute_0_0 = (B * e0),
             encrypted_attribute_0_1 = (B * m0 + D * e0)
);

// XXX The T0_0 and T0_1, etc., should be the same points but we need to pass
//     them in twice because the zkp macro won't let us pass in AND proofs
//     w.r.t. the same value, e.g.
//
//     T0 = (X0 * b), T0 = (h * t0),
//     T1 = (X1 * b), T1 = (h * t1),
create_nipk!(issuance_blinded,
             (x0_tilde, x0, x1, s, b, t0),
             (B, A, X0, X1, D, P, T0_0, T0_1,
              EQ_commitment, EQ_encryption,
              encrypted_attribute_0_0, encrypted_attribute_0_1)
             :
             X0 = (B * x0 + A * x0_tilde),
             X1 = (A * x1),
             P  = (B * b),
             T0_0 = (X0 * b), T0_1 = (A * t0), // XXX the zkp crate doesn't like this, hack around it
             EQ_commitment = (B * s + encrypted_attribute_0_0 * t0),
             EQ_encryption = (D * s + encrypted_attribute_0_1 * t0
// This part is only if there were revealed attributes:
//                              + x0 * P + x1m1 * P + x2m2 * P
                              )
);

create_nipk!(valid_credential,
             (m0, z0, minus_zQ),
             (B, A, X0, P, V, Cm0)
             :
             Cm0 = (P * m0 + A * z0),
             V = (X0 * z0 + A * minus_zQ)
);
