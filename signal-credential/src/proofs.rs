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
create_nipk!(_blind_attributes,
             (d, e0, m0, nonce),
             (B, A, D, roster_entry,
              encrypted_attribute_0_0, encrypted_attribute_0_1)
             :
             D = (B * d),
             encrypted_attribute_0_0 = (B * e0),
             encrypted_attribute_0_1 = (B * m0 + D * e0),
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

pub mod blind_issuance {
    pub use super::_blind_issuance::Publics;
    pub use super::_blind_issuance::Secrets;
    pub use super::_blind_issuance::Proof;
}

// XXX This is hacky because the "phone_number" here is actually the
//     phone_number * h, where phone_number is also public but the zkp crate
//     won't let us multiply two publics (or let us have a public scalar).
//
//     When we pull the code out of the macros the phone_number here
//     should be a public.
create_nipk!(revealed_attributes,
             (nonce, phone_number),
             (g, h, roster_entry_commitment_number)
             :
             roster_entry_commitment_number = (h * phone_number + g * nonce)
);

create_nipk!(roster_membership,
             (m0, z0, nonce),
             (B, A, P, Cm0, RosterEntryPhoneNumberCommitment)
             :
             // ECDLEQ over the two entries to prove equivalence of committed values:
             Cm0 = (P * m0 + A * z0),
             RosterEntryPhoneNumberCommitment = (A * m0 + B * nonce)
);
