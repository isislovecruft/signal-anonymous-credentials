// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

extern crate allocator;
extern crate maths;

use std::os::raw::c_char;

use allocator::allocate_buffer_for_bytes;

#[no_mangle]
pub extern "C" fn do_things_with_maths() -> *mut c_char {
    let point = maths::do_things_with_maths();

    // We can't just use a core::ffi::CString here because the compressed point
    // could have null bytes in it, hence the insane allocation utility
    // functions above.
    //
    // The plus side, however, is that we can safely free these bytes in Swift or
    // Objective-C (unlike a CString).
    allocate_buffer_for_bytes(point.as_bytes())
}
