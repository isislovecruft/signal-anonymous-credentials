// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use std::mem::size_of;
use std::mem::size_of_val;
use std::ptr;
use std::slice;
use std::os::raw::c_char;
use std::os::raw::c_void;

// Use the same allocator as Swift/Objective-C or Java would use.
extern "C" {
    fn malloc(size: usize) -> *mut c_void;
}

pub fn allocate_buffer_for_bytes(bytes: &[u8]) -> *mut c_char {
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
