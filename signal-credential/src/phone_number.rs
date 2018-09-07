// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(any(feature = "alloc", not(feature = "std")))]
use alloc::string::String;

use amacs;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use elgamal;

use pedersen;

use subtle::Choice;
use subtle::ConstantTimeEq;

use credential::EncryptedAttribute;
use errors::CredentialError;

/// A `Scalar` which represents a canonicalised phone number and may be used
/// arithmetically.
///
/// # Note
///
/// To disambiguate numbers which may have significant leading zeros in some
/// countries and/or regions, we prefix the bytes of the scalar with
/// `0x15`s. These `0x15`s are not part of the `number`.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PhoneNumber {
    pub number: Scalar,
    pub length: usize,
}

/// Compare two `PhoneNumber`s to see if they are equal.
///
/// # Note
///
/// This function is contant-time since, in the context of encrypted attributes
/// on an anonymous credential, the phone number is a secret.
impl PartialEq for PhoneNumber {
    fn eq(&self, other: &PhoneNumber) -> bool {
        let mut result: Choice = self.number.ct_eq(&other.number);
        
        result ^= self.length.ct_eq(&other.length);
        result.into()
    }
}
impl Eq for PhoneNumber {}

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
    /// # extern crate curve25519_dalek;
    /// # extern crate signal_credential;
    /// #
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use signal_credential::errors::CredentialError;
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
    pub fn try_from_string(source: &String) -> Result<Self, CredentialError> {
        let bytes: &[u8] = &source.clone().into_bytes(); // XXX remove clone
        let length: usize = bytes.len();

        if length > 32 {
            return Err(CredentialError::PhoneNumberLengthExceeded);
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
        let number: Scalar = Scalar::from_bytes_mod_order(bits);

        Ok(PhoneNumber { number: number, length: length.into() })
    }
}

impl From<PhoneNumber> for String {
    fn from(source: PhoneNumber) -> String {
        let mut s: String = String::with_capacity(source.length);

        for i in 2..source.length+2 {
            match source.number[i] {
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
                _ => println!("Got weird digit in phone number {:?}", source.number[i]),
            }
        }
        s
    }
}

impl From<PhoneNumber> for amacs::Message {
    fn from(source: PhoneNumber) -> amacs::Message {
        let mut v = Vec::with_capacity(2);

        v.push(source.number);
        v.push(Scalar::from(source.length as u64));
        // TODO Remove this cast when the `impl From<usize> for Scalar` patch
        //      (PR #193) is merged into curve25519-dalek.

        amacs::Message::from(v)
    }
}

impl PhoneNumber {
    pub fn encrypt(
        &self, key: &elgamal::Keypair,
        number_nonce: &elgamal::Ephemeral,
        length_nonce: &elgamal::Ephemeral,
    ) -> EncryptedPhoneNumber
    {
        let number_as_point: elgamal::Message = (&self.number).into();
        let length_as_point: elgamal::Message = (&Scalar::from(self.length as u64)).into();
        // TODO remove cast when patch is merged

        EncryptedPhoneNumber {
            number: key.encrypt(&number_as_point, &number_nonce),
            length: key.encrypt(&length_as_point, &length_nonce),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedPhoneNumber {
    pub number: elgamal::Encryption,
    pub length: elgamal::Encryption,
}

impl From<EncryptedPhoneNumber> for Vec<EncryptedAttribute> {
    fn from(source: EncryptedPhoneNumber) -> Vec<EncryptedAttribute> {
        let mut v = Vec::with_capacity(2);

        v.push(source.number);
        v.push(source.length);
        v
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedPhoneNumber {
    pub number: pedersen::Commitment,
    pub length: pedersen::Commitment,
}

impl CommittedPhoneNumber {
    pub fn from_phone_number(
        phone_number: &PhoneNumber,
        nonce: &Scalar,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
    ) -> CommittedPhoneNumber
    {
        let number = pedersen::Commitment::to(&(phone_number.number * h), nonce, &g);
        let length = pedersen::Commitment::to(&(Scalar::from(phone_number.length as u64) * h), nonce, &g);

        CommittedPhoneNumber { number, length }
    }

    pub fn open(
        &self,
        phone_number: &PhoneNumber,
        nonce: &Scalar,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
    ) -> Result<(), ()>
    {
        self.number.open(&(h * &phone_number.number), nonce, &g)?;
        self.length.open(&(h * &Scalar::from(phone_number.length as u64)), nonce, &g)?;

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
