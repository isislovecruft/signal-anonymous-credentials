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
extern crate rand;
extern crate sha2;
#[cfg(feature = "std")]
extern crate std;
extern crate subtle;

mod amacs;
mod errors;

pub use amacs::*;
