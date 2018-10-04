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
pub enum RosterError {
    CouldNotAddMember,
    InvalidProof,
    MemberAlreadyPresent,
    MemberIsNotOwner,
    MemberIsNotAdmin,
    MemberIsNotUser,
    MissingProof,
    PhoneNumberInvalid,
    RosterEntryWrongSize,
}

impl fmt::Display for RosterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RosterError::CouldNotAddMember
                => write!(f, "Could not add member to roster for unknown reason"),
            RosterError::InvalidProof
                => write!(f, "The user's proof of roster membership could not be verified"),
            RosterError::MemberAlreadyPresent
                => write!(f, "The user is already present in the roster"),
            RosterError::MemberIsNotOwner
                => write!(f, "The user is not an owner of the group"),
            RosterError::MemberIsNotAdmin
                => write!(f, "The user is not an admin of the group"),
            RosterError::MemberIsNotUser
                => write!(f, "The user is not in the group"),
            RosterError::MissingProof
                => write!(f, "The user did not supply proof of roster membership"),
            RosterError::PhoneNumberInvalid
                => write!(f, "The phone number was invalid"),
            RosterError::RosterEntryWrongSize
                => write!(f, "The roster entry must be 96 bytes"),
        }
    }
}

impl ::failure::Fail for RosterError { }

impl From<NoneError> for RosterError {
    fn from(_source: NoneError) -> RosterError {
        RosterError::CouldNotAddMember
    }
}

impl From<PhoneNumberError> for RosterError {
    fn from(_source: PhoneNumberError) -> RosterError {
        RosterError::PhoneNumberInvalid
    }
}

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

impl From<RosterError> for CredentialError {
    fn from(_source: RosterError) -> CredentialError {
        NoneError.into()
    }
}
