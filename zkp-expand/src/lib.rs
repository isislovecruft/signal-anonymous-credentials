// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]

#[cfg(feature = "std")]
extern crate std;
#[cfg(any(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate zkp;

pub mod proofs;
