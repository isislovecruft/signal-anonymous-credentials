// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]
#![cfg_attr(all(feature = "alloc", not(feature = "std")), feature(alloc))]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;
extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate failure;
extern crate rand_core;
extern crate sha2;
#[cfg(feature = "std")]
extern crate std;

#[cfg(test)]
extern crate rand;

mod amacs;
mod errors;

pub use amacs::*;
pub use errors::*;
