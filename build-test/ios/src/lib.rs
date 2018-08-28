// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

extern crate maths;

use std::mem::size_of;
use std::mem::size_of_val;
use std::ptr;
use std::slice;
use std::os::raw::c_char;
use std::os::raw::c_void;

// Use the same allocator as Swift/Objective-C would use.
extern "C" {
    fn malloc(size: usize) -> *mut c_void;
}

fn allocate_buffer_for_bytes(bytes: &[u8]) -> *mut c_char {
    let size = size_of_val::<[u8]>(bytes);
    let bytesize = size_of::<u8>();

    // Avoid integer overflow when adding one to the calculated size:
    let size_with_null = match size.checked_add(bytesize) {
        Some(n) => n,
        None    => return ptr::null_mut(),
    };

    let dest = unsafe { malloc(size_with_null) as *mut u8 };

    if dest.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), dest, size);
    }

    // Let slice::from_raw_parts_mut do the pointer arithmetic for us:
    let s = unsafe { slice::from_raw_parts_mut(dest, size_with_null) };
    s[size] = 0; // Add a null terminator

    dest as *mut c_char
}

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
