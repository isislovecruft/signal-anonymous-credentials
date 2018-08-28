// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![feature(custom_attribute)]
// #![feature(proc_macro)] // Required for nightly rustc<1.29

extern crate maths;
extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern {
    /// Call the JS alert function from Rust.
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn do_things_with_maths() {
    alert(&format!("{:?}", maths::do_things_with_maths()));
}
