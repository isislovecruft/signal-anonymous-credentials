// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Implementation of the anonymous credentials scheme in CMZ'13.

// TODO The zkp crate currently requires std.
//#![no_std]

// TODO The test feature is needed by the zkp crate.  This is preventing no_std from working.
#![feature(test)]
// TODO Get rid of the syntax that uses the nightly-only try_trait.
#![feature(try_trait)]

extern crate amacs;
#[cfg(not(feature = "std"))]
extern crate core;
extern crate curve25519_dalek;
extern crate failure;
extern crate elgamal;
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate subtle;
#[macro_use]
extern crate zkp;

pub mod credential;
pub mod errors;
pub mod issuer;
pub mod parameters;
pub mod pedersen;
pub mod phone_number;
pub mod proofs;
pub mod roster;
pub mod traits;
pub mod user;
