// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]
#![allow(non_snake_case)]
#![cfg_attr(all(not(feature = "std"), feature = "alloc"), feature(alloc))]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

extern crate libc;
extern crate rand;
extern crate signal_credential;

pub mod c;
