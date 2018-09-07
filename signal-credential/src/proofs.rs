// -*- mode: rust; -*-
//
// This file is part of groupzk.
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
/// * `x0, x1, x2` are the `SignalIssuer`'s private key material.
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
create_nipk!(_issuance,
             (x0, x1, x2, x0_tilde, m1x1, m2x2),
             (P, Q, Cx0, B, A, X1, X2)
             :
             Q = (P * x0 + P * m1x1 + P * m2x2),
             Cx0 = (B * x0 + A * x0_tilde),
             X1 = (A * x1),
             X2 = (A * x2)
);

pub mod issuance {
    pub use super::_issuance::Publics;
    pub use super::_issuance::Secrets;
    pub use super::_issuance::Proof;
}

/// A NIPK proving that the blinded attributes are valid elGamal encryptions
/// created with the user's public key.
///
/// # Inputs
///
/// Secrets:
///
/// * `d` the `SignalUser`'s private elGamal encryption key,
/// * `e0`...`en` the nonces used to form the elGamal encrypted attributes,
/// * `m0`...`mn` the plaintext attributes,
///
/// Publics:
///
/// * `B` the basepoint,
/// * `D` the `SignalUser`'s public elGamal encryption key,
/// * `encrypted_attribute_0`...`encrypted_attribute_n` the encrypted attributes,
///
/// # Proof Statements
///
/// DOCDOC
//
// TODO The hacky _0 and _1 notation is due to the elGamal ciphertexts being a
// tuple and the macro in the zkp crate doesn't expect a tuple and can't deal
// with it.
//
// XXX The above TODO *must* be fixed before deployment, as the current proof
//     does only implements the Chaum-Pedersen statements for honest provers
//     only.
create_nipk!(_blind_attributes,
             (d, e0, m0, e1, m1, nonce),
             (B, A, D, roster_entry,
              encrypted_attribute_0_0, encrypted_attribute_0_1,
              encrypted_attribute_1_0, encrypted_attribute_1_1)
             :
             D = (B * d),
             encrypted_attribute_0_0 = (B * e0),
             encrypted_attribute_0_1 = (B * m0 + D * e0),
             encrypted_attribute_1_0 = (B * e1),
             encrypted_attribute_1_1 = (B * m1 + D * e1),
             roster_entry = (A * m0 + B * nonce)
);

pub mod blind_attributes {
    pub use super::_blind_attributes::Publics;
    pub use super::_blind_attributes::Secrets;
    pub use super::_blind_attributes::Proof;
}

// XXX The T0_0 and T0_1, etc., should be the same points but we need to pass
//     them in twice because the zkp macro won't let us pass in AND proofs
//     w.r.t. the same value, e.g.
//
//     T0 = (X0 * b), T0 = (h * t0),
//     T1 = (X1 * b), T1 = (h * t1),
create_nipk!(_blind_issuance,
             (x0_tilde, x0, x1, x2, s, b, t0, t1),
             (B, A, X0, X1, X2, D, P, T0_0, T0_1, T1_0, T1_1,
              EQ_commitment, EQ_encryption,
              encrypted_attribute_0_0, encrypted_attribute_0_1,
              encrypted_attribute_1_0, encrypted_attribute_1_1)
             :
             X0 = (B * x0 + A * x0_tilde),
             X1 = (A * x1),
             X2 = (A * x2),
             P  = (B * b),
             T0_0 = (X0 * b), T0_1 = (A * t0), // XXX the zkp crate doesn't like this, hack around it
             T1_0 = (X1 * b), T1_1 = (A * t1),
             EQ_commitment = (B * s + encrypted_attribute_0_0 * t0 + encrypted_attribute_1_0 * t1),
             EQ_encryption = (D * s + encrypted_attribute_0_1 * t0 + encrypted_attribute_1_1 * t1
// This part is only if there were revealed attributes:
//                              + x0 * P + x1m1 * P + x2m2 * P
                              )
);

pub mod blind_issuance {
    pub use super::_blind_issuance::Publics;
    pub use super::_blind_issuance::Secrets;
    pub use super::_blind_issuance::Proof;
}

// XXX This is hacky because the "phone_number" here is actually the
//     phone_number * h, where phone_number is also public but the zkp crate
//     won't let us multiply two publics (or let us have a public scalar).
//
//     When we pull the code out of the macros the phone_number and phone_length
//     here should be publics.
create_nipk!(_revealed_attributes,
             (nonce, phone_number, phone_length),
             (g, h,
              roster_entry_commitment_number,
              roster_entry_commitment_length)
             :
             roster_entry_commitment_number = (h * phone_number + g * nonce),
             roster_entry_commitment_length = (h * phone_length + g * nonce)
);

pub mod revealed_attributes {
    pub use super::_revealed_attributes::Publics;
    pub use super::_revealed_attributes::Secrets;
    pub use super::_revealed_attributes::Proof;
}

create_nipk!(_roster_membership,
             (m0, m1, z0, z1, minus_zQ, nonce),
             (B, A, X0, X1, P, V, Cm0, Cm1,
              RosterEntryPhoneNumberCommitment,
              RosterEntryLengthCommitment)
             :
             Cm0 = (P * m0 + A * z0),
             Cm1 = (P * m1 + A * z1),
             V = (X0 * z0 + X1 * z1 + A * minus_zQ),
             // ECDLEQ over the two entries to prove equivalence of committed values:
             RosterEntryPhoneNumberCommitment = (A * m0 + B * nonce),
             RosterEntryLengthCommitment = (A * m1 + B * nonce)
);

pub mod roster_membership {
    pub use super::_roster_membership::Publics;
    pub use super::_roster_membership::Secrets;
    pub use super::_roster_membership::Proof;
}
