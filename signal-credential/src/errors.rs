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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CredentialError {
    CredentialIssuance,
    MacCreation,
    MacVerification,
    MissingData,
    NoIssuerKey,
    NoIssuerParameters,
    NoSystemParameters,
    PhoneNumberLengthExceeded,
    WrongNumberOfAttributes,
    VerificationFailure,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CredentialError::CredentialIssuance
                => write!(f, "Failed to get a credential issued"),
            CredentialError::MacCreation
                => write!(f, "Could not create a MAC"),
            CredentialError::MacVerification
                => write!(f, "Could not verify a MAC"),
            CredentialError::MissingData
                => write!(f, "Some data, such as a key or zkproof, was missing"),
            CredentialError::NoIssuerKey
                => write!(f, "The issuer was not initialised properly and has no secret key"),
            CredentialError::NoIssuerParameters
                => write!(f, "The issuer was not initialised properly and has no parameters"),
            CredentialError::NoSystemParameters
                => write!(f, "The system parameters were not initialised"),
            CredentialError::PhoneNumberLengthExceeded
                => write!(f, "A canonicalised phone number cannot be more than 32 bytes"),
            CredentialError::WrongNumberOfAttributes
                => write!(f, "The credential did not have the correct number of attributes"),
            CredentialError::VerificationFailure
                => write!(f, "The proof could not be verified"),
        }
    }
}

impl ::failure::Fail for CredentialError { }

impl From<NoneError> for CredentialError {
    fn from(_source: NoneError) -> CredentialError {
        CredentialError::MissingData
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RosterError {
    CouldNotAddMember,
    MemberAlreadyPresent,
}

impl fmt::Display for RosterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RosterError::CouldNotAddMember
                => write!(f, "Could not add member to roster for unknown reason"),
            RosterError::MemberAlreadyPresent
                => write!(f, "The user is already present in the roster"),
        }
    }
}

impl ::failure::Fail for RosterError { }

impl From<NoneError> for RosterError {
    fn from(_source: NoneError) -> RosterError {
        RosterError::CouldNotAddMember
    }
}
