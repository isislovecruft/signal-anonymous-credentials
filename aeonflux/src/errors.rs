// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>


use std::fmt;
use std::fmt::Display;
use std::option::NoneError;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CredentialError {
    BadAttribute,
    CredentialIssuance,
    MacCreation,
    MacVerification,
    MissingData,
    NoIssuerKey,
    NoIssuerParameters,
    NoSystemParameters,
    WrongNumberOfAttributes,
    VerificationFailure,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CredentialError::BadAttribute
                => write!(f, "An attribute was unacceptable"),
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
