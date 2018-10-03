// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

// TODO The test feature is needed by the zkp crate.  This is preventing no_std from working.
#![feature(test)]
// TODO Get rid of the syntax that uses the nightly-only try_trait.
#![feature(try_trait)]
// We denote group elements with capital and scalars with lowercased names.
#![allow(non_snake_case)]

extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate failure;
extern crate rand_core;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha2;
extern crate subtle;
#[macro_use]
extern crate zkp;

#[cfg(test)]
extern crate rand;

pub mod amacs;
pub mod credential;
pub mod elgamal;
pub mod errors;
pub mod issuer;
pub mod nonces;
pub mod parameters;
pub mod pedersen;
pub mod proofs;
pub mod user;
