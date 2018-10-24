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
use signal_credential::credential::VerifiedSignalCredential;
use signal_credential::issuer::IssuerParameters;
use signal_credential::issuer::SignalIssuer;
use signal_credential::parameters::SystemParameters;
use signal_credential::phone_number::RosterEntryCommitment;
use signal_credential::user::SignalUser;

pub type SignalRng = ChaChaRng;

pub const LENGTH_SEED: usize = 32;
pub const LENGTH_SYSTEM_PARAMETERS: u64 = 64;
pub const LENGTH_ISSUER: u64 = 160;
pub const LENGTH_ISSUER_PARAMETERS: u64 = 32;
pub const LENGTH_ISSUER_KEYPAIR: u64 = 96;
pub const LENGTH_USER: u64 = 288;
pub const LENGTH_CREDENTIAL_ISSUANCE: u64 = 328;
pub const LENGTH_CREDENTIAL_PRESENTATION: u64 = 448;
pub const LENGTH_VERIFIED_CREDENTIAL: u64 = 448;

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
    phone_number: *const uint8_t,
    phone_number_length: uint64_t,
    seed: *const uint8_t, // must be 32 bytes exactly
) -> buf_t
{
    let issuer = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let user_number: &[u8] = len_and_ptr_to_slice!(phone_number_length, phone_number);
    let issuance: SignalCredentialIssuance = ok_or_return!(issuer.issue(&user_number, &mut csprng));
    let serialized: Vec<u8> = serialize_or_return!(&issuance);

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
pub extern "C" fn issuer_verify_roster_membership(
    issuer: *const uint8_t,
    issuer_length: uint64_t,
    verified_credential: *const uint8_t,
    verified_credential_length: uint64_t,
) -> buf_t
{
    let issuer_deserialized = deserialize_or_return!(SignalIssuer, issuer_length, issuer);
    let verified = deserialize_or_return!(VerifiedSignalCredential,
                                          verified_credential_length,
                                          verified_credential);
    let roster_entry_commitment = ok_or_return!(issuer_deserialized.verify_roster_membership(&verified));
    let serialized = serialize_or_return!(&roster_entry_commitment);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn user_obtain_finish(
    phone_number: *const uint8_t,
    phone_number_length: uint64_t,
    system_parameters: *const uint8_t,
    system_parameters_length: uint64_t,
    issuer_parameters: *const uint8_t,
    issuer_parameters_length: uint64_t,
    issuance: *const uint8_t,
    issuance_length: uint64_t,
) -> buf_t
{
    let system_params = deserialize_or_return!(SystemParameters, system_parameters_length, system_parameters);
    let issuer_params = deserialize_or_return!(IssuerParameters, issuer_parameters_length, issuer_parameters);
    let issuance_deserialized = deserialize_or_return!(SignalCredentialIssuance, issuance_length, issuance);
    let phone_number_bytes: &[u8] = len_and_ptr_to_slice!(phone_number_length, phone_number);
    let mut user: SignalUser = ok_or_return!(SignalUser::new(system_params,
                                                             issuer_params,
                                                             None,
                                                             phone_number_bytes));

    ok_or_return!(user.obtain_finish(Some(&issuance_deserialized)));

    let serialized: Vec<u8> = serialize_or_return!(&user);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn user_show(
    user: *const uint8_t,
    user_length: uint64_t,
    roster_entry_commitment: *const uint8_t,
    roster_entry_commitment_length: uint64_t,
    seed: *const uint8_t, // must be 32 bytes exactly
) -> buf_t
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let user_deserialized = deserialize_or_return!(SignalUser, user_length, user);
    let entry = deserialize_or_return!(RosterEntryCommitment,
                                       roster_entry_commitment_length,
                                       roster_entry_commitment);
    let presentation: SignalCredentialPresentation = ok_or_return!(user_deserialized.show(&mut csprng, &entry));
    let serialized: Vec<u8> = serialize_or_return!(&presentation);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn roster_entry_commitment_create(
    phone_number: *const uint8_t,
    phone_number_length: uint64_t,
    system_parameters: *const uint8_t,
    system_parameters_length: uint64_t,
    seed: *const uint8_t
) -> buf_t
{
    let mut csprng: SignalRng = csprng_from_seed!(seed);
    let number: &[u8] = len_and_ptr_to_slice!(phone_number_length, phone_number);
    let system_params = deserialize_or_return!(SystemParameters, system_parameters_length, system_parameters);
    let roster_entry = ok_or_return!(RosterEntryCommitment::create(&number, &system_params, &mut csprng));
    let serialized: Vec<u8> = serialize_or_return!(&roster_entry);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn roster_entry_commitment_remove_opening(
    roster_entry_commitment: *const uint8_t,
    roster_entry_commitment_length: uint64_t,
) -> buf_t
{
    let deserialized = deserialize_or_return!(RosterEntryCommitment,
                                              roster_entry_commitment,
                                              roster_entry_commitment_length);
    let serialized = serialize_or_return!(deserialized.commitment);

    slice_to_len_and_ptr!(&serialized[..])
}

#[no_mangle]
pub extern "C" fn roster_entry_commitment_open(
    roster_entry_commitment: *const uint8_t, // also contains the opening
    roster_entry_commitment_length: uint64_t,
    phone_number: *const uint8_t,
    phone_number_length: uint64_t,
    system_parameters: *const uint8_t,
    system_parameters_length: uint64_t
) -> buf_t  // XXX just return uint8_t
{
    let number: &[u8] = len_and_ptr_to_slice!(phone_number_length, phone_number);
    let system_params = deserialize_or_return!(SystemParameters,
                                               system_parameters_length,
                                               system_parameters);
    let roster_entry = deserialize_or_return!(RosterEntryCommitment,
                                              roster_entry_commitment_length,
                                              roster_entry_commitment);
    
    match roster_entry.open(&number, &system_params) {
        Ok(_)  => buf_t{ ptr: ptr::null(), len: 1 },
        Err(_) => buf_t{ ptr: ptr::null(), len: 0 },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const RISTRETTO_BASEPOINT_COMPRESSED: [uint8_t; 32] =
        [0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
         0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
         0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
         0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76];

    const SEED: [uint8_t; 32] = [  0,  1,  2,  3,  4,  5,  6,  7,
                                   8,  9, 10, 11, 12, 13, 14, 15,
                                  16, 17, 18, 19, 20, 21, 22, 23,
                                  24, 25, 26, 27, 28, 29, 30, 31, ];
    const PHONE_NUMBER: &'static [uint8_t] = &[ 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4 ];



    const SYSTEM_PARAMETERS: [uint8_t; 64] = [226, 242, 174, 10, 106, 188, 78, 113,
                                              168, 132, 169, 97, 197, 0, 81, 95, 88,
                                              227, 11, 106, 165, 130, 221, 141, 182,
                                              166, 89, 69, 224, 141, 45, 118, 106, 145,
                                              146, 226, 33, 103, 177, 113, 120, 62,
                                              220, 68, 45, 29, 235, 234, 53, 200, 198,
                                              44, 210, 123, 226, 92, 205, 208, 203,
                                              136, 127, 196, 27, 83];

    const ISSUER_PARAMETERS: [uint8_t; 32] = [
        46, 15, 59, 90, 231, 240, 71, 218, 133, 156, 242, 69, 166, 177, 88, 83, 243,
        194, 130, 14, 169, 80, 206, 142, 125, 241, 187, 64, 51, 107, 169, 47];

    const ISSUER_KEYPAIR: [uint8_t; 96] = [
        46, 15, 59, 90, 231, 240, 71, 218, 133, 156, 242, 69, 166, 177, 88, 83, 243, 194, 130,
        14, 169, 80, 206, 142, 125, 241, 187, 64, 51, 107, 169, 47, 54, 229, 180, 52, 25, 85, 26,
        146, 200, 9, 169, 149, 163, 210, 200, 23, 168, 108, 232, 245, 221, 151, 59, 6, 254, 156,
        181, 163, 240, 18, 135, 11, 97, 2, 57, 142, 254, 227, 59, 136, 111, 75, 183, 4, 43, 137,
        125, 131, 219, 89, 183, 26, 5, 175, 247, 110, 155, 99, 59, 135, 202, 222, 125, 0];

    const USER_WITH_CREDENTIAL: [uint8_t; 288] = [
        15, 15, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4, 15, 15, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88,
        227, 11, 106, 165, 130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118, 106, 145, 146, 226,
        33, 103, 177, 113, 120, 62, 220, 68, 45, 29, 235, 234, 53, 200, 198, 44, 210, 123, 226,
        92, 205, 208, 203, 136, 127, 196, 27, 83, 46, 15, 59, 90, 231, 240, 71, 218, 133, 156,
        242, 69, 166, 177, 88, 83, 243, 194, 130, 14, 169, 80, 206, 142, 125, 241, 187, 64, 51,
        107, 169, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 122, 76, 107, 20, 1, 73, 138, 242, 56, 18, 121, 38, 199, 0,
        206, 64, 243, 30, 78, 222, 189, 130, 97, 186, 212, 114, 87, 90, 66, 210, 80, 63, 116, 170,
        255, 227, 219, 207, 210, 31, 147, 76, 130, 38, 159, 252, 57, 29, 98, 221, 229, 146, 76,
        226, 65, 134, 228, 8, 25, 134, 11, 151, 89, 60, 15, 15, 1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4,
        15, 15, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    const ISSUANCE: [uint8_t; 328] = [
        244, 21, 196, 237, 191, 59, 210, 143, 229, 70, 189, 0, 157, 125, 163, 254, 183, 147, 38, 37,
        34, 117, 65, 172, 102, 134, 221, 10, 12, 146, 206, 72, 122, 76, 107, 20, 1, 73, 138, 242, 56,
        18, 121, 38, 199, 0, 206, 64, 243, 30, 78, 222, 189, 130, 97, 186, 212, 114, 87, 90, 66, 210,
        80, 63, 116, 170, 255, 227, 219, 207, 210, 31, 147, 76, 130, 38, 159, 252, 57, 29, 98, 221,
        229, 146, 76, 226, 65, 134, 228, 8, 25, 134, 11, 151, 89, 60, 15, 15, 1, 4, 1, 5, 5, 5, 5, 1,
        2, 3, 4, 15, 15, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
        49, 60, 77, 112, 78, 178, 70, 94, 208, 141, 192, 221, 54, 143, 148, 248, 125, 149, 135, 97,
        163, 47, 126, 63, 133, 73, 107, 70, 210, 157, 147, 0, 32, 0, 0, 0, 0, 0, 0, 0, 175, 231, 41,
        99, 155, 44, 234, 165, 190, 113, 68, 166, 29, 229, 114, 89, 30, 244, 86, 146, 57, 160, 55,
        60, 246, 67, 19, 131, 109, 235, 31, 14, 32, 0, 0, 0, 0, 0, 0, 0, 92, 205, 217, 18, 252, 133,
        24, 164, 240, 216, 36, 26, 203, 198, 13, 61, 102, 226, 144, 117, 172, 219, 69, 101, 101, 250,
        45, 85, 83, 74, 85, 2, 32, 0, 0, 0, 0, 0, 0, 0, 237, 173, 233, 127, 230, 246, 150, 185, 10,
        112, 234, 213, 120, 72, 210, 70, 172, 194, 30, 94, 21, 54, 221, 238, 55, 98, 33, 92, 111,
        205, 12, 1, 32, 0, 0, 0, 0, 0, 0, 0, 141, 162, 73, 78, 206, 121, 204, 87, 103, 81, 19, 230,
        107, 24, 14, 85, 111, 11, 16, 146, 127, 238, 28, 47, 42, 16, 213, 67, 85, 27, 117, 3];

    const PRESENTATION: [uint8_t; 448] = [
        248, 163, 151, 99, 15, 211, 184, 146, 98, 185, 185, 234, 81, 11, 77, 29, 213, 18, 4, 44, 126,
        117, 2, 56, 30, 52, 155, 212, 181, 85, 242, 38, 146, 66, 44, 178, 12, 119, 96, 57, 105, 194,
        58, 97, 59, 14, 109, 79, 103, 202, 97, 128, 134, 167, 190, 207, 115, 50, 142, 173, 50, 115,
        247, 34, 112, 66, 255, 34, 60, 11, 103, 241, 75, 146, 145, 252, 141, 140, 82, 77, 206, 158,
        248, 3, 171, 214, 36, 163, 123, 131, 100, 206, 191, 139, 201, 31, 142, 174, 47, 99, 85, 191,
        79, 157, 165, 214, 12, 190, 34, 126, 148, 132, 249, 199, 75, 153, 9, 28, 231, 135, 51, 234,
        170, 230, 186, 150, 209, 14, 32, 0, 0, 0, 0, 0, 0, 0, 120, 163, 143, 235, 243, 2, 155, 102,
        176, 140, 150, 9, 153, 105, 159, 250, 250, 94, 98, 243, 67, 121, 36, 137, 203, 181, 181, 219,
        79, 50, 185, 5, 32, 0, 0, 0, 0, 0, 0, 0, 238, 78, 222, 45, 89, 12, 191, 163, 207, 28, 202,
        80, 156, 68, 200, 50, 216, 123, 52, 56, 60, 21, 233, 87, 26, 189, 195, 45, 68, 212, 211, 0,
        32, 0, 0, 0, 0, 0, 0, 0, 22, 146, 55, 27, 75, 245, 255, 137, 5, 176, 171, 130, 19, 123, 165,
        21, 155, 165, 71, 208, 110, 205, 10, 212, 123, 96, 164, 253, 24, 22, 189, 3, 32, 0, 0, 0, 0,
        0, 0, 0, 87, 20, 92, 136, 108, 106, 141, 15, 237, 51, 82, 220, 125, 61, 252, 67, 133, 1, 26,
        82, 201, 73, 111, 33, 224, 19, 84, 18, 229, 155, 240, 9, 32, 0, 0, 0, 0, 0, 0, 0, 246, 227,
        44, 155, 172, 20, 30, 125, 6, 203, 95, 202, 118, 205, 113, 106, 246, 92, 227, 123, 180, 154,
        248, 191, 236, 114, 170, 164, 232, 49, 133, 2, 32, 0, 0, 0, 0, 0, 0, 0, 30, 34, 247, 213, 5,
        244, 20, 7, 13, 165, 187, 252, 119, 205, 2, 187, 16, 171, 230, 150, 136, 2, 10, 29, 137, 166,
        211, 167, 22, 175, 194, 4, 32, 0, 0, 0, 0, 0, 0, 0, 184, 204, 213, 5, 200, 136, 130, 26, 21,
        94, 3, 236, 24, 242, 209, 196, 244, 148, 250, 147, 10, 155, 25, 111, 4, 220, 1, 67, 2, 160,
        61, 15, 32, 0, 0, 0, 0, 0, 0, 0, 135, 114, 45, 215, 51, 118, 253, 18, 35, 42, 124, 109, 164,
        181, 48, 152, 22, 58, 145, 48, 181, 75, 151, 186, 49, 133, 213, 98, 138, 99, 83, 11];

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
        let system_parameters = system_parameters_create(SEED.as_ptr());

        assert!(system_parameters.len != 0);
        assert!(system_parameters.len == LENGTH_SYSTEM_PARAMETERS);

        let deserialized: SystemParameters = assert_deserialized!(SystemParameters,
                                                                  system_parameters.len,
                                                                  system_parameters.ptr);
        assert!(deserialized.g.compress().to_bytes() == RISTRETTO_BASEPOINT_COMPRESSED);
    }

    #[test]
    fn test_issuer_create() {
        let keypair = issuer_create(SYSTEM_PARAMETERS.as_ptr(),
                                    SYSTEM_PARAMETERS.len() as uint64_t,
                                    SEED.as_ptr());

        assert!(keypair.len != 0);
        assert!(keypair.len == LENGTH_ISSUER_KEYPAIR, "issuer keypair length was {}", keypair.len);

        assert_deserialized!(AmacsKeypair, keypair.len, keypair.ptr);
    }

    #[test]
    fn test_issuer_new() {
        let issuer = issuer_new(SYSTEM_PARAMETERS.as_ptr(),
                                SYSTEM_PARAMETERS.len() as uint64_t,
                                ISSUER_KEYPAIR.as_ptr(),
                                ISSUER_KEYPAIR.len() as uint64_t);

        assert!(issuer.len != 0);
        assert!(issuer.len == LENGTH_ISSUER, "issuer length was {}", issuer.len);

        let deserialized = assert_deserialized!(SignalIssuer, issuer.len, issuer.ptr);

        assert!(deserialized.issuer.system_parameters.g.compress().to_bytes() == RISTRETTO_BASEPOINT_COMPRESSED,
                "deserialized was {:?}, original was {:?}",
                deserialized.issuer.system_parameters.h.compress().to_bytes(), RISTRETTO_BASEPOINT_COMPRESSED);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_issuer_get_issuer_parameters() {
        let issuer = issuer_new(SYSTEM_PARAMETERS.as_ptr(),
                                SYSTEM_PARAMETERS.len() as uint64_t,
                                ISSUER_KEYPAIR.as_ptr(),
                                ISSUER_KEYPAIR.len() as uint64_t);
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
    fn test_issuer_issue() {
        let issuer = issuer_new(SYSTEM_PARAMETERS.as_ptr(),
                                SYSTEM_PARAMETERS.len() as uint64_t,
                                ISSUER_KEYPAIR.as_ptr(),
                                ISSUER_KEYPAIR.len() as uint64_t);
        let issuance = issuer_issue(issuer.ptr,
                                    issuer.len,
                                    PHONE_NUMBER.as_ptr(),
                                    PHONE_NUMBER.len() as uint64_t,
                                    SEED.as_ptr());

        assert!(issuance.len != 0);
        assert!(issuance.len == LENGTH_CREDENTIAL_ISSUANCE,
                "issuance length was {}", issuance.len);
    }


    #[test]
    fn test_issuer_verify() {
        let issuer = issuer_new(SYSTEM_PARAMETERS.as_ptr(),
                                SYSTEM_PARAMETERS.len() as uint64_t,
                                ISSUER_KEYPAIR.as_ptr(),
                                ISSUER_KEYPAIR.len() as uint64_t);
        let verified = issuer_verify(issuer.ptr, issuer.len,
                                     PRESENTATION.as_ptr(), PRESENTATION.len() as uint64_t);

        assert!(verified.len != 0);
        assert!(verified.len == LENGTH_VERIFIED_CREDENTIAL,
                "verified length was {}", verified.len);

        assert_deserialized!(VerifiedSignalCredential, verified.len, verified.ptr);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_user_obtain_finish() {
        let user = user_obtain_finish(PHONE_NUMBER.as_ptr(),
                                      PHONE_NUMBER.len() as uint64_t,
                                      SYSTEM_PARAMETERS.as_ptr(),
                                      SYSTEM_PARAMETERS.len() as uint64_t,
                                      ISSUER_PARAMETERS.as_ptr(),
                                      ISSUER_PARAMETERS.len() as uint64_t,
                                      ISSUANCE.as_ptr(),
                                      ISSUANCE.len() as uint64_t);

        assert!(user.len != 0);
        assert!(user.len == LENGTH_USER,
                "user length was {}", user.len);
    }

    #[test]
    fn test_user_show() {
        let entry = roster_entry_commitment_create(PHONE_NUMBER.as_ptr(),
                                                   PHONE_NUMBER.len() as uint64_t,
                                                   SYSTEM_PARAMETERS.as_ptr(),
                                                   SYSTEM_PARAMETERS.len() as uint64_t,
                                                   SEED.as_ptr());
        let presentation = user_show(USER_WITH_CREDENTIAL.as_ptr(),
                                     USER_WITH_CREDENTIAL.len() as uint64_t,
                                     entry.ptr,
                                     entry.len,
                                     SEED.as_ptr());

        assert!(presentation.len != 0);
        assert!(presentation.len == LENGTH_CREDENTIAL_PRESENTATION,
                "presentation length was {}", presentation.len);

        assert_deserialized!(SignalCredentialPresentation, presentation.len, presentation.ptr);
    }
}
