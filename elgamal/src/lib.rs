// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]

#[cfg(feature = "std" )]
extern crate std;

extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate rand;

mod elgamal;

pub use elgamal::*;
