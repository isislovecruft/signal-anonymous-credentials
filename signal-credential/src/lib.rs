// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Implementation of the anonymous credentials scheme in CMZ'13.

#![no_std]

// TODO Get rid of the syntax that uses the nightly-only try_trait.
#![feature(try_trait)]
// We denote group elements with capital and scalars with lowercased names.
#![allow(non_snake_case)]

#![allow(unused_imports)] // XXX remove this

#![cfg_attr(all(not(feature = "std"), feature = "alloc"), feature(alloc))]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

extern crate aeonflux;
extern crate bincode;
extern crate curve25519_dalek;
extern crate merlin;
extern crate failure;
extern crate rand;
extern crate rand_core;
#[macro_use]
extern crate serde_derive;

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
