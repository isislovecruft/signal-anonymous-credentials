// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! C-like language FFI API.

use std::slice;

pub use libc::size_t;
pub use libc::uint8_t;
pub use libc::uint64_t;

pub use rand::ChaChaRng;
pub use rand::SeedableRng;

use signal_credential::amacs::Keypair as AmacsKeypair; // The $t:tt in the macro can't munch ::
use signal_credential::credential::SignalCredentialIssuance;
use signal_credential::credential::SignalCredentialPresentation;
use signal_credential::credential::SignalCredentialRequest;
use signal_credential::credential::VerifiedSignalCredential;
use signal_credential::elgamal::{self};
use signal_credential::issuer::IssuerParameters;
use signal_credential::issuer::SignalIssuer;
use signal_credential::parameters::SystemParameters;
use signal_credential::roster::GroupMembershipLevel;
use signal_credential::roster::GroupMembershipRoster;
use signal_credential::user::SignalUser;

pub type SignalRng = ChaChaRng;

const LENGTH_H: usize = 32;
const LENGTH_SEED: usize = 32;

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
            Err(x) => { println!("{:?}", x); return zero_len_and_ptr!(); },
            Ok(x)  => x,
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

#[repr(C)]
pub struct buf_t {
    pub len: uint64_t,
    pub ptr: *const uint8_t,
}

#[no_mangle]
pub extern "C" fn system_parameters_create(
    H: *const uint8_t,  // should be 32 bytes exactly
) -> buf_t
{
    let H_array: [u8; LENGTH_H] = ok_or_return!(uint8_to_array!(H, LENGTH_H));
    let system_parameters: SystemParameters = SystemParameters::from(H_array);
    let serialized: Vec<u8> = serialize_or_return!(&system_parameters);

    slice_to_len_and_ptr!(&serialized[..])
}

// returns a serialized Issuer struct
#[no_mangle]
pub extern "C" fn issuer_create(
    system_parameters: *const uint8_t,
    system_parameters_length: uint64_t,
    seed: *const uint8_t,
) -> buf_t
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let system_params = deserialize_or_return!(SystemParameters, system_parameters_length, system_parameters);
    let issuer: SignalIssuer = SignalIssuer::create(system_params, &mut csprng);
    let serialized: Vec<u8> = serialize_or_return!(&issuer);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn issuer_new(
    system_parameters: *const uint8_t,
    system_parameters_length: uint64_t,
    keypair: *const uint8_t,
    keypair_length: uint64_t,
) -> buf_t
{
    let system_params = deserialize_or_return!(SystemParameters, system_parameters_length, system_parameters);
    let keys = deserialize_or_return!(AmacsKeypair, keypair_length, keypair);
    let issuer: SignalIssuer = SignalIssuer::new(system_params, keys);
    let serialized: Vec<u8> = serialize_or_return!(&issuer);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn issuer_get_issuer_parameters(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
) -> buf_t
{
    let deserialized = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let issuer_parameters: IssuerParameters = deserialized.get_issuer_parameters();
    let serialized: Vec<u8> = serialize_or_return!(&issuer_parameters);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn issuer_issue(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
    seed: *const uint8_t, // must be 32 bytes exactly
    request: *const uint8_t,
    request_length: uint64_t,
    phone_number: *const uint8_t,
    phone_number_length: uint64_t,
) -> buf_t
{
    let issuer = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let req = deserialize_or_return!(SignalCredentialRequest, request_length, request);
    let user_number: &[u8] = len_and_ptr_to_slice!(phone_number_length, phone_number);
    let issuance: SignalCredentialIssuance = ok_or_return!(issuer.issue(&req, &user_number, &mut csprng));
    let serialized: Vec<u8> = serialize_or_return!(&issuance);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn user_new(
    system_parameters: *const uint8_t,
    system_parameters_length: uint64_t,
    keypair: *const uint8_t, // may optionally be a NULL pointer
    keypair_length: uint64_t,
    phone_number: *const uint8_t,
    phone_number_length: uint64_t,
    issuer_parameters: *const uint8_t,
    issuer_parameters_length: uint64_t,
    seed: *const uint8_t, // must be 32 bytes exactly
) -> buf_t
{
    let system_params = deserialize_or_return!(SystemParameters, system_parameters_length, system_parameters);
    let issuer_params = deserialize_or_return!(IssuerParameters, issuer_parameters_length, issuer_parameters);
    let mut csprng: SignalRng = csprng_from_seed!(seed);

    // The key is optional so we have to handle it more manually:
    let key: Option<elgamal::Keypair>;

    if keypair.is_null() || keypair_length == 0 {
        key = None;
    } else {
        let keypair_bytes: &[u8] = unsafe { slice::from_raw_parts(keypair, keypair_length as size_t) };

        key = Some(ok_or_return!(elgamal::Keypair::from_bytes(keypair_bytes)));
    }
    let phone_number_bytes: &[u8] = len_and_ptr_to_slice!(phone_number_length, phone_number);
    let user: SignalUser = ok_or_return!(SignalUser::new(system_params,
                                                         issuer_params,
                                                         key,
                                                         phone_number_bytes,
                                                         &mut csprng));
    let serialized: Vec<u8> = serialize_or_return!(&user);

    slice_to_len_and_ptr!(&serialized[..])
}


#[no_mangle]
pub extern "C" fn user_obtain(
    user: *const uint8_t,
    user_length: uint64_t,
) -> buf_t
{
    let user_deserialized = deserialize_or_return!(SignalUser, user_length, user);
    let request: SignalCredentialRequest = user_deserialized.obtain();
    let serialized_request: Vec<u8> = serialize_or_return!(&request);

    slice_to_len_and_ptr!(&serialized_request[..])
}

// XXX remember that the user mutates and this returns the mutated one rather than overwriting
#[no_mangle]
pub extern "C" fn user_obtain_finish(
    user: *const uint8_t,
    user_length: uint64_t,
    issuance: *const uint8_t,
    issuance_length: uint64_t,
) -> buf_t
{
    let mut user_deserialized = deserialize_or_return!(SignalUser, user_length, user);
    let issuance_deserialized = deserialize_or_return!(SignalCredentialIssuance, issuance_length, issuance);

    ok_or_return!(user_deserialized.obtain_finish(Some(&issuance_deserialized)));

    let serialized: Vec<u8> = serialize_or_return!(&user_deserialized);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn user_show(
    user: *const uint8_t,
    user_length: uint64_t,
    seed: *const uint8_t, // must be 32 bytes exactly
) -> buf_t
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let user_deserialized = deserialize_or_return!(SignalUser, user_length, user);
    let presentation: SignalCredentialPresentation = ok_or_return!(user_deserialized.show(&mut csprng));
    let serialized: Vec<u8> = serialize_or_return!(&presentation);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn issuer_verify(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
    presentation: *const uint8_t,
    presentation_length: uint64_t,
) -> buf_t
{
    let issuer_deserialized = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let presentation_deserialized = deserialize_or_return!(SignalCredentialPresentation,
                                                           presentation_length,
                                                           presentation);
    let verified = ok_or_return!(issuer_deserialized.verify(presentation_deserialized));
    let serialized = serialize_or_return!(&verified);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn issuer_verify_roster_membership_owner(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
    verified_credential: *const uint8_t,
    verified_credential_length: uint64_t,
    roster: *const uint8_t,
    roster_length: uint64_t,
) -> buf_t
{
    let issuer_deserialized = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let verified = deserialize_or_return!(VerifiedSignalCredential,
                                          verified_credential_length,
                                          verified_credential);
    let roster = deserialize_or_return!(GroupMembershipRoster, roster_length, roster);
    let is_in_roster = issuer_deserialized.verify_roster_membership(&verified, &roster,
                                                                    &GroupMembershipLevel::Owner);

    match is_in_roster {
        Ok(_)  => buf_t { len: 1, ptr: ptr::null(), },
        Err(_) => buf_t { len: 0, ptr: ptr::null(), },
    }
}

#[no_mangle]
pub extern "C" fn issuer_verify_roster_membership_admin(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
    verified_credential: *const uint8_t,
    verified_credential_length: uint64_t,
    roster: *const uint8_t,
    roster_length: uint64_t,
) -> buf_t
{
    let issuer_deserialized = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let verified = deserialize_or_return!(VerifiedSignalCredential,
                                          verified_credential_length,
                                          verified_credential);
    let roster = deserialize_or_return!(GroupMembershipRoster, roster_length, roster);
    let is_in_roster = issuer_deserialized.verify_roster_membership(&verified, &roster,
                                                                    &GroupMembershipLevel::Admin);

    match is_in_roster {
        Ok(_)  => buf_t { len: 1, ptr: ptr::null(), },
        Err(_) => buf_t { len: 0, ptr: ptr::null(), },
    }
}

#[no_mangle]
pub extern "C" fn issuer_verify_roster_membership_user(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
    verified_credential: *const uint8_t,
    verified_credential_length: uint64_t,
    roster: *const uint8_t,
    roster_length: uint64_t,
) -> buf_t
{
    let issuer_deserialized = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let verified = deserialize_or_return!(VerifiedSignalCredential,
                                          verified_credential_length,
                                          verified_credential);
    let roster = deserialize_or_return!(GroupMembershipRoster, roster_length, roster);
    let is_in_roster = issuer_deserialized.verify_roster_membership(&verified, &roster,
                                                                    &GroupMembershipLevel::User);

    match is_in_roster {
        Ok(_)  => buf_t { len: 1, ptr: ptr::null(), },
        Err(_) => buf_t { len: 0, ptr: ptr::null(), },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const H: [uint8_t; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                                93, 125, 218,  60,  36, 165, 166, 178,
                               118, 188,  77,  27, 133, 146, 193, 133,
                               234,  95,  69, 227, 213, 197,  84,  98, ];
    const SEED: [uint8_t; 32] = [  0,  1,  2,  3,  4,  5,  6,  7,
                                   8,  9, 10, 11, 12, 13, 14, 15,
                                  16, 17, 18, 19, 20, 21, 22, 23,
                                  24, 25, 26, 27, 28, 29, 30, 31, ];
    const PHONE_NUMBER: &'static [uint8_t] = &[ 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4 ];

    const SYSTEM_PARAMETERS: [uint8_t; 64] = [ 226, 242, 174,  10, 106, 188,  78, 113,
                                               168, 132, 169,  97, 197,   0,  81,  95,
                                                88, 227,  11, 106, 165, 130, 221, 141,
                                               182, 166,  89,  69, 224, 141,  45, 118,
                                               184, 238, 220,  64,   5, 247,  91, 135,
                                                93, 125, 218,  60,  36, 165, 166, 178,
                                               118, 188,  77,  27, 133, 146, 193, 133,
                                               234,  95,  69, 227, 213, 197,  84,  98, ];

    const ISSUER_PARAMETERS: [uint8_t; 32] = [ 190, 107,  28, 115, 128, 129,   2, 110,
                                                48,  38, 145, 168, 102, 138, 157, 161,
                                                62, 165,   6, 216,   8, 181,  63, 181,
                                               199,  35, 223,  53, 252, 147, 113,  76, ];

    const ISSUER_KEYPAIR: [uint8_t; 96] = [
        190, 107, 28, 115, 128, 129, 2, 110, 48, 38, 145, 168, 102, 138, 157, 161, 62, 165, 6,
        216, 8, 181, 63, 181, 199, 35, 223, 53, 252, 147, 113, 76, 54, 229, 180, 52, 25, 85, 26,
        146, 200, 9, 169, 149, 163, 210, 200, 23, 168, 108, 232, 245, 221, 151, 59, 6, 254, 156,
        181, 163, 240, 18, 135, 11, 97, 2, 57, 142, 254, 227, 59, 136, 111, 75, 183, 4, 43, 137,
        125, 131, 219, 89, 183, 26, 5, 175, 247, 110, 155, 99, 59, 135, 202, 222, 125, 0];

    const USER_WITH_CREDENTIAL: [uint8_t; 416] = [
         154, 246, 140, 237, 135, 85, 164, 20, 125, 22, 108, 216, 19, 233, 31, 73, 106, 201, 125,
         216, 89, 130, 107, 198, 99, 135, 218, 150, 201, 226, 43, 64, 15, 15, 1, 4, 1, 5, 5, 5, 5,
         1, 2, 3, 4, 15, 15, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 147, 244, 115, 88,
         141, 204, 138, 118, 161, 60, 236, 108, 224, 220, 178, 169, 238, 60, 36, 137, 20, 218, 221,
         15, 103, 20, 129, 102, 78, 173, 198, 15, 147, 244, 115, 88, 141, 204, 138, 118, 161, 60, 236,
         108, 224, 220, 178, 169, 238, 60, 36, 137, 20, 218, 221, 15, 103, 20, 129, 102, 78, 173,
         198, 15, 15, 15, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4, 15, 15, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95,
         88, 227, 11, 106, 165, 130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118, 184, 238, 220, 64,
         5, 247, 91, 135, 93, 125, 218, 60, 36, 165, 166, 178, 118, 188, 77, 27, 133, 146, 193, 133,
         234, 95, 69, 227, 213, 197, 84, 98, 190, 107, 28, 115, 128, 129, 2, 110, 48, 38, 145, 168,
         102, 138, 157, 161, 62, 165, 6, 216, 8, 181, 63, 181, 199, 35, 223, 53, 252, 147, 113, 76,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 122, 76, 107, 20, 1, 73, 138, 242, 56, 18, 121, 38, 199, 0, 206, 64, 243, 30,
         78, 222, 189, 130, 97, 186, 212, 114, 87, 90, 66, 210, 80, 63, 116, 170, 255, 227, 219, 207,
         210, 31, 147, 76, 130, 38, 159, 252, 57, 29, 98, 221, 229, 146, 76, 226, 65, 134, 228, 8,
         25, 134, 11, 151, 89, 60, 15, 15, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4, 15, 15, 11, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    const PRESENTATION: [uint8_t; 512] = [
        154, 246, 140, 237, 135, 85, 164, 20, 125, 22, 108, 216, 19, 233, 31, 73, 106, 201, 125,
        216, 89, 130, 107, 198, 99, 135, 218, 150, 201, 226, 43, 64, 15, 15, 1, 4, 1, 5, 5, 5, 5,
        1, 2, 3, 4, 15, 15, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 147, 244, 115, 88,
        141, 204, 138, 118, 161, 60, 236, 108, 224, 220, 178, 169, 238, 60, 36, 137, 20, 218, 221,
        15, 103, 20, 129, 102, 78, 173, 198, 15, 150, 167, 154, 16, 46, 35, 76, 131, 185, 231, 1,
        121, 33, 95, 249, 137, 166, 243, 170, 63, 61, 161, 64, 255, 81, 34, 49, 51, 140, 135, 134,
        88, 112, 66, 255, 34, 60, 11, 103, 241, 75, 146, 145, 252, 141, 140, 82, 77, 206, 158, 248,
        3, 171, 214, 36, 163, 123, 131, 100, 206, 191, 139, 201, 31, 146, 121, 216, 148, 189, 185,
        9, 246, 86, 125, 236, 214, 172, 205, 168, 86, 175, 206, 161, 32, 6, 206, 138, 13, 183, 242,
        100, 138, 241, 20, 199, 95, 32, 0, 0, 0, 0, 0, 0, 0, 236, 49, 75, 252, 13, 249, 202, 208,
        94, 115, 168, 135, 80, 173, 208, 180, 113, 176, 216, 164, 236, 64, 187, 174, 85, 74, 71,
        132, 232, 54, 135, 0, 32, 0, 0, 0, 0, 0, 0, 0, 8, 144, 110, 3, 211, 169, 53, 253, 98, 226,
        211, 85, 20, 103, 181, 43, 114, 112, 12, 221, 54, 226, 233, 201, 99, 183, 134, 164, 5, 78,
        103, 13, 32, 0, 0, 0, 0, 0, 0, 0, 150, 130, 37, 5, 249, 86, 120, 97, 192, 145, 150, 1, 5,
        213, 33, 216, 173, 223, 89, 56, 102, 53, 104, 83, 100, 194, 116, 209, 40, 101, 73, 1, 32,
        0, 0, 0, 0, 0, 0, 0, 22, 167, 14, 31, 3, 2, 198, 122, 177, 87, 38, 5, 127, 47, 238, 251,
        171, 52, 129, 146, 213, 93, 149, 39, 217, 26, 158, 94, 94, 9, 117, 11, 32, 0, 0, 0, 0, 0,
        0, 0, 76, 180, 47, 208, 164, 83, 189, 131, 154, 118, 56, 53, 140, 114, 162, 58, 178, 199,
        15, 65, 219, 71, 57, 115, 170, 240, 76, 118, 184, 156, 138, 15, 32, 0, 0, 0, 0, 0, 0, 0,
        202, 244, 249, 65, 149, 67, 89, 74, 119, 112, 5, 44, 133, 127, 231, 73, 202, 239, 47, 172,
        249, 7, 95, 190, 96, 175, 6, 25, 164, 62, 130, 4, 32, 0, 0, 0, 0, 0, 0, 0, 191, 178, 151,
        62, 63, 4, 63, 221, 173, 190, 39, 186, 100, 208, 100, 67, 193, 117, 118, 96, 59, 245, 114,
        45, 224, 184, 36, 178, 253, 173, 117, 6, 32, 0, 0, 0, 0, 0, 0, 0, 88, 128, 10, 185, 81, 112,
        94, 91, 97, 218, 93, 31, 242, 246, 250, 113, 40, 123, 32, 171, 117, 189, 135, 109, 210, 33,
        253, 187, 60, 122, 73, 2];

    macro_rules! assert_deserialized {
        ($t:tt, $len:expr, $ptr:expr) => {{
            let bytes: &[u8] = unsafe { slice::from_raw_parts($ptr, $len as size_t) };

            match $t::from_bytes(bytes) {
                Ok(t) => t,
                Err(x) => { println!("{}", x); panic!(); },
            }
        }}
    }

    #[allow(unused_variables)]
    #[test]
    fn test_system_parameters_create () {
        let system_parameters = system_parameters_create(H.as_ptr());

        let deserialized: SystemParameters = assert_deserialized!(SystemParameters,
                                                                  system_parameters.len,
                                                                  system_parameters.ptr);
        assert!(deserialized.h.compress().to_bytes() == H);
    }

    #[test]
    fn test_issuer_create() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                   SEED.as_ptr());

        assert!(issuer.len != 0);
        assert!(issuer.len == 160, "issuer length was {}", issuer.len);

        let deserialized: SignalIssuer = assert_deserialized!(SignalIssuer,
                                                              issuer.len,
                                                              issuer.ptr);

        assert!(deserialized.issuer.system_parameters.h.compress().to_bytes() == H,
                "deserialized was {:?}, original was {:?}",
                deserialized.issuer.system_parameters.h.compress().to_bytes(), H);
    }

    #[test]
    fn test_issuer_new() {
        let issuer = issuer_new(SYSTEM_PARAMETERS.as_ptr(),
                                SYSTEM_PARAMETERS.len() as uint64_t,
                                ISSUER_KEYPAIR.as_ptr(),
                                ISSUER_KEYPAIR.len() as uint64_t);

        assert_deserialized!(SignalIssuer, issuer.len, issuer.ptr);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_issuer_get_issuer_parameters() {
        let system_parameters = system_parameters_create(H.as_ptr());
        let issuer = issuer_create(system_parameters.ptr,
                                   system_parameters.len,
                                   SEED.as_ptr());
        let issuer_parameters = issuer_get_issuer_parameters(issuer.ptr, issuer.len);

        assert!(issuer_parameters.len != 0);
        assert!(issuer_parameters.len == 32, "issuer parameters length was {}", issuer_parameters.len);

        let deserialized: IssuerParameters = assert_deserialized!(IssuerParameters,
                                                                  issuer_parameters.len,
                                                                  issuer_parameters.ptr);

        assert!(deserialized.Xn.get(0).is_some());
    }

    #[allow(unused_variables)]
    #[test]
    fn test_user_new() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                   SEED.as_ptr());
        let issuer_parameters = issuer_get_issuer_parameters(issuer.ptr, issuer.len);
        let user = user_new(SYSTEM_PARAMETERS.as_ptr(),
                            SYSTEM_PARAMETERS.len() as uint64_t,
                            ptr::null(),
                            0 as uint64_t,
                            PHONE_NUMBER.as_ptr(),
                            PHONE_NUMBER.len() as uint64_t,
                            issuer_parameters.ptr,
                            issuer_parameters.len,
                            SEED.as_ptr());
        assert!(user.len != 0);
        assert!(user.len == 416, "user length was {}", user.len);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_user_obtain() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                                    SYSTEM_PARAMETERS.len() as uint64_t,
                                                    SEED.as_ptr());
        let issuer_parameters = issuer_get_issuer_parameters(issuer.ptr, issuer.len);
        let user = user_new(SYSTEM_PARAMETERS.as_ptr(),
                            SYSTEM_PARAMETERS.len() as uint64_t,
                            ptr::null(),
                            0 as uint64_t,
                            PHONE_NUMBER.as_ptr(),
                            PHONE_NUMBER.len() as uint64_t,
                            issuer_parameters.ptr,
                            issuer_parameters.len,
                            SEED.as_ptr());
        let request = user_obtain(user.ptr, user.len);

        assert!(request.len != 0);
        assert!(request.len == 248, "request length was {}", request.len);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_issuer_issue() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                   SEED.as_ptr());
        let user = user_new(SYSTEM_PARAMETERS.as_ptr(),
                            SYSTEM_PARAMETERS.len() as uint64_t,
                            ptr::null(),
                            0 as uint64_t,
                            PHONE_NUMBER.as_ptr(),
                            PHONE_NUMBER.len() as uint64_t,
                            ISSUER_PARAMETERS.as_ptr(),
                            ISSUER_PARAMETERS.len() as uint64_t,
                            SEED.as_ptr());
        let request = user_obtain(user.ptr, user.len);
        let issuance = issuer_issue(issuer.ptr,
                                    issuer.len,
                                    SEED.as_ptr(),
                                    request.ptr,
                                    request.len,
                                    PHONE_NUMBER.as_ptr(),
                                    PHONE_NUMBER.len() as uint64_t);
        assert!(issuance.len != 0);
        assert!(issuance.len == 328, "issuance length was {}", issuance.len);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_user_obtain_finish() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                   SEED.as_ptr());
        let user = user_new(SYSTEM_PARAMETERS.as_ptr(),
                            SYSTEM_PARAMETERS.len() as uint64_t,
                            ptr::null(),
                            0 as uint64_t,
                            PHONE_NUMBER.as_ptr(),
                            PHONE_NUMBER.len() as uint64_t,
                            ISSUER_PARAMETERS.as_ptr(),
                            ISSUER_PARAMETERS.len() as uint64_t,
                            SEED.as_ptr());
        let request = user_obtain(user.ptr, user.len);
        let issuance = issuer_issue(issuer.ptr,
                                    issuer.len,
                                    SEED.as_ptr(),
                                    request.ptr,
                                    request.len,
                                    PHONE_NUMBER.as_ptr(),
                                    PHONE_NUMBER.len() as uint64_t);
        let new_user = user_obtain_finish(user.ptr,
                                          user.len,
                                          issuance.ptr,
                                          issuance.len);
        assert!(new_user.len != 0);
        assert!(new_user.len == user.len);
    }

    #[test]
    fn test_user_show() {
        let presentation = user_show(USER_WITH_CREDENTIAL.as_ptr(),
                                     USER_WITH_CREDENTIAL.len() as uint64_t,
                                     SEED.as_ptr());

        assert_deserialized!(SignalCredentialPresentation, presentation.len, presentation.ptr);
    }

    #[test]
    fn test_issuer_verify() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                   SEED.as_ptr());
        let verified = issuer_verify(issuer.ptr, issuer.len,
                                     PRESENTATION.as_ptr(), PRESENTATION.len() as uint64_t);

        assert_deserialized!(VerifiedSignalCredential, verified.len, verified.ptr);
    }
}
