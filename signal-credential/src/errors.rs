// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::option::NoneError;

#[cfg(feature = "std")]
use std::option::NoneError;

use aeonflux::errors::CredentialError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PhoneNumberError {
    LengthExceeded,
    InvalidPhoneNumber,
}

impl fmt::Display for PhoneNumberError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PhoneNumberError::LengthExceeded
                => write!(f, "A canonicalised phone number cannot be more than 32 bytes"),
            PhoneNumberError::InvalidPhoneNumber
                => write!(f, "The user's proof of roster membership could not be verified"),
        }
    }
}

impl ::failure::Fail for PhoneNumberError { }

impl From<NoneError> for PhoneNumberError {
    fn from(_source: NoneError) -> PhoneNumberError {
        PhoneNumberError::InvalidPhoneNumber
    }
}

impl From<PhoneNumberError> for CredentialError {
    fn from(_source: PhoneNumberError) -> CredentialError {
        NoneError.into()
    }
}

impl From<CredentialError> for PhoneNumberError {
    fn from(_source: CredentialError) -> PhoneNumberError {
        NoneError.into()
    }
}
