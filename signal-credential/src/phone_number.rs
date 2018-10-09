// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::string::String;

#[cfg(feature = "std")]
use std::ops::{Index};
#[cfg(not(feature = "std"))]
use core::ops::{Index};

use aeonflux::amacs::{self};
use aeonflux::credential::EncryptedAttribute;
use aeonflux::elgamal::{self};
use aeonflux::pedersen::{self};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use errors::PhoneNumberError;

pub const SIZEOF_PHONE_NUMBER: usize = 32;
pub const SIZEOF_COMMITTED_PHONE_NUMBER: usize = pedersen::SIZEOF_COMMITMENT;
pub const SIZEOF_ENCRYPTED_PHONE_NUMBER: usize = elgamal::SIZEOF_ENCRYPTION;

/// A `Scalar` which represents a canonicalised phone number and may be used
/// arithmetically.
///
/// # Note
///
/// To disambiguate numbers which may have significant leading zeros in some
/// countries and/or regions, we prefix the bytes of the scalar with
/// `0x15`s. These `0x15`s are not part of the `number`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct PhoneNumber(pub Scalar);

impl Index<usize> for PhoneNumber {
    type Output = u8;

    /// Index the bytes of this `PhoneNumber`.  Mutation is not permitted.
    fn index(&self, _index: usize) -> &u8 {
        &(self.0[_index])
    }
}

impl PhoneNumber {
    pub fn from_bytes(bytes: &[u8]) -> Result<PhoneNumber, PhoneNumberError> {
        if bytes.len() != SIZEOF_PHONE_NUMBER {
            return Err(PhoneNumberError::LengthExceeded);
        }

        let mut tmp: [u8; 32] = [0u8; 32];

        tmp.copy_from_slice(&bytes[00..32]);

        Ok(PhoneNumber(Scalar::from_bits(tmp)))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl_serde_with_to_bytes_and_from_bytes!(PhoneNumber);

impl PhoneNumber {
    /// Convert a `String` containing a canonicalised (as if it were to be
    /// dialed from San Francisco) phone number into a `PhoneNumber`.
    ///
    /// # Warning
    ///
    /// If ever there are two phone numbers whose canonicalisations map to the
    /// same String, this could end horribly.  Some measures have been taking to
    /// prevent this, for example, given the phone numbers `+1 800 MICROSOFT`
    /// and `800 642 7676` (which **MUST** both be canonicalised prior to
    /// calling this method into `001 800 642 7676`) this method will turn
    /// `001 800 642 7676` into:
    ///
    /// ```
    /// # extern crate aeonflux;
    /// # extern crate curve25519_dalek;
    /// # extern crate signal_credential;
    /// #
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use aeonflux::errors::CredentialError;
    /// use signal_credential::phone_number::PhoneNumber;
    ///
    /// # fn do_test() -> Result<(), CredentialError> {
    /// let microsoft: PhoneNumber = PhoneNumber(
    ///     Scalar::from_bytes_mod_order([
    ///         15, 15, 00, 00, 01, 08, 00, 00, 06, 04, 02, 07, 06, 07, 06, 15,
    ///         15, 13, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, ])
    /// );
    ///
    /// let expected: PhoneNumber = PhoneNumber::try_from_string(&String::from("0018006427676"))?;
    ///
    /// assert!(microsoft == expected);
    /// # Ok(())
    /// # }
    /// # fn main() { do_test(); }
    /// ```
    //
    // TODO Whenever core::convert::TryFrom is stabilised, this method should be changed to:
    //
    // impl TryFrom<String> for PhoneNumber {
    //     type Error = CredentialError;
    //
    //     fn try_from(source: String) -> Result<Self, Self::Error> {
    //         PhoneNumber::try_from_string(source)
    //     }
    // }
    pub fn try_from_string(source: &String) -> Result<Self, PhoneNumberError> {
        let bytes: &[u8] = source.as_bytes();
        let length: usize = bytes.len();

        if length > 32 {
            return Err(PhoneNumberError::LengthExceeded);
        }
        let mut bits: [u8; 32] = [0u8; 32];

        // Prefix it with some bogus digits to prevent phone numbers with
        // significant leading zeroes getting mapped to the same scalar:
        bits[0] = 15;
        bits[1] = 15;

        // Write the phone number into the bytes:
        for i in 2..length+2 {
            bits[i] = match bytes[i-2] {
                // Undo UTF-8 encoding:
                48 => 0,
                49 => 1,
                50 => 2,
                51 => 3,
                52 => 4,
                53 => 5,
                54 => 6,
                55 => 7,
                56 => 8,
                57 => 9,
                _  => 15,
            };
        }
        // Suffix some bogus digits as well and then finally add the length:
        bits[length+2] = 15;
        bits[length+3] = 15;
        bits[length+4] = length as u8;

        let number: Scalar = Scalar::from_bytes_mod_order(bits);

        Ok(PhoneNumber(number))
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, PhoneNumberError> {
        let length: usize = bytes.len();

        if length > 32 {
            return Err(PhoneNumberError::LengthExceeded);
        }
        let mut bits: [u8; 32] = [0u8; 32];

        // Prefix it with some bogus digits to prevent phone numbers with
        // significant leading zeroes getting mapped to the same scalar:
        bits[0] = 15;
        bits[1] = 15;

        // Write the phone number into the bytes:
        for i in 2..length+2 {
            bits[i] = bytes[i-2];
        }
        // Suffix some bogus digits as well and then finally add the length:
        bits[length+2] = 15;
        bits[length+3] = 15;
        bits[length+4] = length as u8;

        let number: Scalar = Scalar::from_bytes_mod_order(bits);

        Ok(PhoneNumber(number))
    }
}

impl From<PhoneNumber> for String {
    fn from(source: PhoneNumber) -> String {
        let mut length: usize = 0;

        // Work backwards to find the length:
        for i in (0..32).rev() {
            if source.0[i] == 0 {
                continue;
            } else {
                length = source[i] as usize;
                break;
            }
        }

        let mut s: String = String::with_capacity(length);

        for i in 2..length+2 {
            match source[i] {
                0 => s.push_str("0"),
                1 => s.push_str("1"),
                2 => s.push_str("2"),
                3 => s.push_str("3"),
                4 => s.push_str("4"),
                5 => s.push_str("5"),
                6 => s.push_str("6"),
                7 => s.push_str("7"),
                8 => s.push_str("8"),
                9 => s.push_str("9"),
                _ => {
                    #[cfg(feature = "std")]
                    println!("Got weird digit in phone number {:?}", source[i]);
                    continue;
                },
            }
        }

        s
    }
}

impl From<PhoneNumber> for amacs::Message {
    fn from(source: PhoneNumber) -> amacs::Message {
        amacs::Message::from(source.0)
    }
}

impl PhoneNumber {
    pub fn encrypt(
        &self,
        key: &elgamal::Keypair,
        number_nonce: &elgamal::Ephemeral,
    ) -> EncryptedPhoneNumber
    {
        let message: elgamal::Message = (&self.0).into();

        EncryptedPhoneNumber(key.encrypt(&message, &number_nonce))
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedPhoneNumber(pub elgamal::Encryption);

impl From<EncryptedPhoneNumber> for Vec<EncryptedAttribute> {
    fn from(source: EncryptedPhoneNumber) -> Vec<EncryptedAttribute> {
        let mut v = Vec::with_capacity(1);

        v.push(source.0);

        v
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedPhoneNumber(pub pedersen::Commitment);

impl CommittedPhoneNumber {
    pub fn from_bytes(bytes: &[u8]) -> Result<CommittedPhoneNumber, PhoneNumberError> {
        Ok(CommittedPhoneNumber(pedersen::Commitment::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl_serde_with_to_bytes_and_from_bytes!(CommittedPhoneNumber);

impl CommittedPhoneNumber {
    pub fn from_phone_number(
        phone_number: &PhoneNumber,
        nonce: &Scalar,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
    ) -> CommittedPhoneNumber
    {
        let number = pedersen::Commitment::to(&(phone_number.0 * h), nonce, &g);

        CommittedPhoneNumber(number)
    }

    pub fn open(
        &self,
        phone_number: &PhoneNumber,
        nonce: &Scalar,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
    ) -> Result<(), ()>
    {
        self.0.open(&(&phone_number.0 * h), nonce, &g)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let input: String = String::from("0018005551234");
        let number: PhoneNumber = PhoneNumber::try_from_string(&input).unwrap();
        let check: String = String::from(number);

        assert!(input == check,
                "input {:?} did not equal the check after roundtrip: {:?}",
                input, check);
    }

    #[test]
    fn test_equality_leading_zeroes() {
        let a: PhoneNumber = PhoneNumber::try_from_string(&String::from("0018005551234")).unwrap();
        let b: PhoneNumber = PhoneNumber::try_from_string(&String::from("00018005551234")).unwrap();

        assert!(a != b);
    }
}
