// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use core::fmt;
use core::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MacError {
    PointDecompressionError,
    ScalarFormatError,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass the `length` in bytes which its constructor expects.
    MessageLengthError{ length: usize },
    /// The MAC could not be authenticated.
    AuthenticationError,
}

impl Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MacError::PointDecompressionError
                => write!(f, "Cannot decompress Ristretto point"),
            MacError::ScalarFormatError
                => write!(f, "Cannot use scalar with high-bit set"),
            MacError::MessageLengthError{ length: l }
                => write!(f, "Message must be {} bytes in length", l),
            MacError::AuthenticationError
                => write!(f, "MAC could not be authenticated"),
        }
    }
}

impl ::failure::Fail for MacError {}
