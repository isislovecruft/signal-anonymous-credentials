// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[macro_export]
macro_rules! slice_to_len_and_ptr {
    ($x:expr) => {{
        let x: &[u8] = $x;

        buf_t {
            len: x.len() as uint64_t,
            ptr: x.as_ptr() as *const uint8_t,
        }
    }}
}

#[macro_export]
macro_rules! zero_len_and_ptr {
    () => {
        slice_to_len_and_ptr!(&[])
    }
}

#[macro_export]
macro_rules! len_and_ptr_to_slice {
    ($len:expr, $ptr:ident) => {{
        if $ptr.is_null() || $len == 0 {
            return zero_len_and_ptr!();
        } else {
            unsafe { slice::from_raw_parts($ptr, $len as size_t) } // XXX dangerous downcast
        }
    }}
}

#[macro_export]
macro_rules! ok_or_return {
    ($expr:expr) => {
        match $expr {
            Ok(x)   => x,
            Err(_x) => {
                #[cfg(feature = "std")]
                println!("{:?}", _x);
                return zero_len_and_ptr!();
            },
        };
    }
}

#[macro_export]
macro_rules! csprng_from_seed {
    ($seed:ident) => {{
        let seed_array: [u8; LENGTH_SEED] = ok_or_return!(uint8_to_array!($seed, LENGTH_SEED));

        SignalRng::from_seed(seed_array)
   }}
}

#[macro_export]
macro_rules! uint8_to_array {
    ($ptr:ident, $array_length:expr) => {{
        if $ptr.is_null() || $array_length == 0 {
            Err(())
        } else {
            let bytes: &[u8] = unsafe { slice::from_raw_parts($ptr, $array_length as size_t) };

            if bytes.len() != $array_length {
                Err(())
            } else {
                let mut array: [u8; $array_length] = [0u8; $array_length];

                // This will panic if the bytes.len() isn't equal to the array_length,
                // hence the explicit double-checks on the lengths above.
                array.copy_from_slice(bytes);

                Ok(array)
            }
        }
    }}
}

#[macro_export]
macro_rules! deserialize_or_return {
    ($t:tt, $len:expr, $ptr:ident) => {{
        let bytes: &[u8] = len_and_ptr_to_slice!($len, $ptr);

        ok_or_return!($t::from_bytes(bytes))
    }}
}

#[macro_export]
macro_rules! serialize_or_return {
    ($t:expr) => {{
        $t.to_bytes()
    }}
}

// The following code was shamelessly stolen from the libc crate.

/// A macro for defining #[cfg] if-else statements.
///
/// This is similar to the `if/elif` C preprocessor macro by allowing definition
/// of a cascade of `#[cfg]` cases, emitting the implementation which matches
/// first.
///
/// This allows you to conveniently provide a long list #[cfg]'d blocks of code
/// without having to rewrite each clause multiple times.
#[macro_export]
macro_rules! cfg_if {
    ($(
        if #[cfg($($meta:meta),*)] { $($it:item)* }
    ) else * else {
        $($it2:item)*
    }) => {
        __cfg_if_items! {
            () ;
            $( ( ($($meta),*) ($($it)*) ), )*
            ( () ($($it2)*) ),
        }
    }
}

macro_rules! __cfg_if_items {
    (($($not:meta,)*) ; ) => {};
    (($($not:meta,)*) ; ( ($($m:meta),*) ($($it:item)*) ), $($rest:tt)*) => {
        __cfg_if_apply! { cfg(all(not(any($($not),*)), $($m,)*)), $($it)* }
        __cfg_if_items! { ($($not,)* $($m,)*) ; $($rest)* }
    }
}

macro_rules! __cfg_if_apply {
    ($m:meta, $($it:item)*) => {
        $(#[$m] $it)*
    }
}
