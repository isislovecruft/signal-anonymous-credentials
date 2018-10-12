// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! C-like language FFI API.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

cfg_if! {
    if #[cfg(feature = "std")] {
        use std::ptr;
        use std::slice;
    } else {
        use core::ptr;
        use core::slice;
    }
}

cfg_if! {
    // NOTE: The following only works because of wasm-bindgen.
    if #[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))] {
        #[allow(non_camel_case_types)] pub type size_t = usize;
        #[allow(non_camel_case_types)] pub type uint8_t = u8;
        #[allow(non_camel_case_types)] pub type uint64_t = u64;
    } else {
        pub use libc::size_t;
        pub use libc::uint8_t;
        pub use libc::uint64_t;
    }
}

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

pub const LENGTH_SEED: usize = 32;
pub const LENGTH_SYSTEM_PARAMETERS: u64 = 64;
pub const LENGTH_ISSUER: u64 = 160;
pub const LENGTH_ISSUER_PARAMETERS: u64 = 32;
pub const LENGTH_ISSUER_KEYPAIR: u64 = 96;
pub const LENGTH_USER: u64 = 416;
pub const LENGTH_CREDENTIAL_REQUEST: u64 = 248;
pub const LENGTH_CREDENTIAL_ISSUANCE: u64 = 328;
pub const LENGTH_CREDENTIAL_PRESENTATION: u64 = 512;
pub const LENGTH_VERIFIED_CREDENTIAL: u64 = 512;

#[repr(C)]
pub struct buf_t {
    pub len: uint64_t,
    pub ptr: *const uint8_t,
}

#[no_mangle]
pub extern "C" fn system_parameters_create(
    seed: *const uint8_t,  // should be 32 bytes exactly
) -> buf_t
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let system_parameters: SystemParameters = SystemParameters::hunt_and_peck(&mut csprng);
    let serialized: Vec<u8> = serialize_or_return!(&system_parameters);

    slice_to_len_and_ptr!(&serialized[..])
}

// returns a serialized Issuer keypair
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
    let serialized: Vec<u8> = serialize_or_return!(&issuer.issuer.keypair);

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
        100, 138, 241, 20, 199, 95, 32, 0, 0, 0, 0, 0, 0, 0, 46, 64, 243, 109, 220, 60, 117, 154,
        152, 182, 86, 223, 128, 163, 249, 69, 56, 32, 182, 26, 20, 13, 241, 205, 252, 110, 196, 181,
        184, 157, 0, 7, 32, 0, 0, 0, 0, 0, 0, 0, 151, 29, 126, 91, 247, 126, 158, 216, 192, 196, 99,
        20, 205, 251, 126, 204, 21, 53, 54, 69, 248, 145, 131, 63, 184, 219, 102, 224, 7, 194, 59,
        13, 32, 0, 0, 0, 0, 0, 0, 0, 160, 66, 64, 113, 16, 114, 80, 178, 117, 73, 204, 82, 128, 40,
        210, 49, 243, 20, 117, 100, 20, 145, 159, 123, 121, 72, 253, 129, 158, 251, 97, 0, 32, 0, 0,
        0, 0, 0, 0, 0, 159, 75, 167, 167, 18, 31, 117, 55, 33, 183, 90, 9, 92, 111, 0, 218, 206,
        109, 223, 200, 215, 137, 43, 18, 183, 208, 32, 150, 130, 244, 139, 1, 32, 0, 0, 0, 0, 0, 0,
        0, 113, 118, 105, 145, 220, 57, 64, 165, 131, 199, 105, 45, 232, 39, 22, 182, 22, 172, 168,
        17, 95, 130, 18, 168, 198, 5, 30, 125, 114, 17, 20, 4, 32, 0, 0, 0, 0, 0, 0, 0, 179, 109,
        126, 129, 234, 193, 76, 24, 146, 109, 135, 79, 217, 190, 43, 140, 142, 241, 12, 64, 53, 248,
        195, 145, 1, 160, 18, 142, 237, 86, 179, 0, 32, 0, 0, 0, 0, 0, 0, 0, 93, 167, 236, 2, 98,
        96, 112, 2, 230, 76, 72, 52, 61, 202, 205, 218, 11, 9, 38, 27, 28, 218, 230, 132, 177, 147,
        7, 196, 54, 185, 202, 4, 32, 0, 0, 0, 0, 0, 0, 0, 241, 218, 54, 19, 221, 247, 45, 164, 193,
        11, 255, 215, 185, 170, 9, 148, 129, 193, 178, 143, 209, 253, 152, 52, 6, 251, 204, 66, 50,
        145, 201, 4];

    macro_rules! assert_deserialized {
        ($t:tt, $len:expr, $ptr:expr) => {{
            let bytes: &[u8] = unsafe { slice::from_raw_parts($ptr, $len as size_t) };

            match $t::from_bytes(bytes) {
                Ok(t)   => t,
                Err(_x) => {
                    #[cfg(feature = "std")]
                    println!("{}", _x);
                    panic!();
                },
            }
        }}
    }

    #[allow(unused_variables)]
    #[test]
    fn test_system_parameters_create () {
        let system_parameters = system_parameters_create(H.as_ptr());

        assert!(system_parameters.len != 0);
        assert!(system_parameters.len == LENGTH_SYSTEM_PARAMETERS);

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
        assert!(issuer.len == LENGTH_ISSUER, "issuer length was {}", issuer.len);

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

        assert!(issuer.len != 0);
        assert!(issuer.len == LENGTH_ISSUER, "issuer length was {}", issuer.len);

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
        assert!(issuer_parameters.len == LENGTH_ISSUER_PARAMETERS,
                "issuer parameters length was {}", issuer_parameters.len);

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
        assert!(user.len == LENGTH_USER, "user length was {}", user.len);
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
        assert!(request.len == LENGTH_CREDENTIAL_REQUEST,
                "request length was {}", request.len);
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
        assert!(issuance.len == LENGTH_CREDENTIAL_ISSUANCE,
                "issuance length was {}", issuance.len);
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

        assert!(presentation.len != 0);
        assert!(presentation.len == LENGTH_CREDENTIAL_PRESENTATION,
                "presentation length was {}", presentation.len);

        assert_deserialized!(SignalCredentialPresentation, presentation.len, presentation.ptr);
    }

    #[test]
    fn test_issuer_verify() {
        let issuer = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                   SEED.as_ptr());
        let verified = issuer_verify(issuer.ptr, issuer.len,
                                     PRESENTATION.as_ptr(), PRESENTATION.len() as uint64_t);

        assert!(verified.len != 0);
        assert!(verified.len == LENGTH_VERIFIED_CREDENTIAL,
                "verified length was {}", verified.len);

        assert_deserialized!(VerifiedSignalCredential, verified.len, verified.ptr);
    }
}
