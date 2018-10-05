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

#![allow(unused_imports)] // XXX remove this

extern crate aeonflux;
extern crate bincode;
#[cfg(not(feature = "std"))]
extern crate core;
extern crate curve25519_dalek;
extern crate failure;
extern crate rand_core;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

#[cfg(test)]
extern crate rand;

pub mod credential;
pub mod errors;
pub mod issuer;
pub mod phone_number;
pub mod proofs;
pub mod roster;
pub mod user;

pub use credential::*;
pub use errors::*;
pub use issuer::*;
pub use phone_number::*;
pub use proofs::*;
pub use roster::*;
pub use user::*;

// Re-export common externally-used types from aeonflux.
pub use aeonflux::prelude::*;

pub mod parameters {
    pub use aeonflux::prelude::SystemParameters;
}
