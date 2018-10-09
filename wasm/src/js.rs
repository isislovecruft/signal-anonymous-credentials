// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use ffi;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct buf_t {
    pub len: u64,
    pub ptr: *const u8,
}

#[wasm_bindgen]
pub fn system_parameters_create(
    H: *const u8,  // should be 32 bytes exactly
) -> buf_t
{
    ffi::c::system_parameters_create(H)
}

}

#[wasm_bindgen]
pub fn issuer_create(
    system_parameters: *const u8,
    system_parameters_length: u64,
    seed: *const u8,
) -> buf_t
{
    ffi::c::issuer_create(system_parameters,
                          system_parameters_length,
                          seed)
}

#[wasm_bindgen]
pub fn issuer_new(
    system_parameters: *const u8,
    system_parameters_length: u64,
    keypair: *const u8,
    keypair_length: u64,
) -> buf_t
{
    ffi::c::issuer_new(system_parameters,
                       system_parameters_length,
                       keypair,
                       keypair_length)
}

#[wasm_bindgen]
pub fn issuer_get_issuer_parameters(
    issuer: *const u8,
    issuer_length: u64,
) -> buf_t
{
    ffi::c::issuer_get_issuer_parameters(issuer,
                                         issuer_length)
}

#[wasm_bindgen]
pub fn issuer_issue(
    issuer: *const u8,
    issuer_length: u64,
    seed: *const u8, // must be 32 bytes exactly
    request: *const u8,
    request_length: u64,
    phone_number: *const u8,
    phone_number_length: u64,
) -> buf_t
{
    ffi::c::issuer_issue(issuer,
                         issuer_length,
                         seed,
                         request,
                         request_length,
                         phone_number,
                         phone_number_length)
}

#[wasm_bindgen]
pub fn issuer_verify(
    issuer: *const u8,
    issuer_length: u64,
    presentation: *const u8,
    presentation_length: u64,
) -> buf_t
{
    ffi::c::issuer_verify(issuer,
                          issuer_length,
                          presentation,
                          presentation_length)
}

#[wasm_bindgen]
pub fn issuer_verify_roster_membership_owner(
    issuer: *const u8,
    issuer_length: u64,
    verified_credential: *const u8,
    verified_credential_length: u64,
    roster: *const u8,
    roster_length: u64,
) -> buf_t
{
    ffi::c::issuer_verify_roster_membership_owner(issuer,
                                                  issuer_length,
                                                  verified_credential,
                                                  verified_credential_length,
                                                  roster,
                                                  roster_length)
}

#[wasm_bindgen]
pub fn issuer_verify_roster_membership_admin(
    issuer: *const u8,
    issuer_length: u64,
    verified_credential: *const u8,
    verified_credential_length: u64,
    roster: *const u8,
    roster_length: u64,
) -> buf_t
{
    ffi::c::issuer_verify_roster_membership_admin(issuer,
                                                  issuer_length,
                                                  verified_credential,
                                                  verified_credential_length,
                                                  roster, roster_length)
}

#[wasm_bindgen]
pub fn issuer_verify_roster_membership_user(
    issuer: *const u8,
    issuer_length: u64,
    verified_credential: *const u8,
    verified_credential_length: u64,
    roster: *const u8,
    roster_length: u64,
) -> buf_t
{
    ffi::c::issuer_verify_roster_membership_user(issuer,
                                                 issuer_length,
                                                 verified_credential,
                                                 verified_credential_length,
                                                 roster, roster_length)
}

#[wasm_bindgen]
pub fn user_new(
    system_parameters: *const u8,
    system_parameters_length: u64,
    keypair: *const u8, // may optionally be a NULL pointer
    keypair_length: u64,
    phone_number: *const u8,
    phone_number_length: u64,
    issuer_parameters: *const u8,
    issuer_parameters_length: u64,
    seed: *const u8, // must be 32 bytes exactly
) -> buf_t
{
    ffi::c::user_new(system_parameters,
                     system_parameters_length,
                     keypair,
                     keypair_length,
                     phone_number,
                     phone_number_length,
                     issuer_parameters,
                     issuer_parameters_length,
                     seed)
}

#[wasm_bindgen]
pub fn user_obtain(
    user: *const u8,
    user_length: u64,
) -> buf_t
{
    ffi::c::user_obtain(user,
                        user_length)
}

#[wasm_bindgen]
pub fn user_obtain_finish(
    user: *const u8,
    user_length: u64,
    issuance: *const u8,
    issuance_length: u64,
) -> buf_t
{
    ffi::c::user_obtain_finish(user,
                               user_length,
                               issuance,
                               issuance_length)
}

#[wasm_bindgen]
pub fn user_show(
    user: *const u8,
    user_length: u64,
    seed: *const u8, // must be 32 bytes exactly
) -> buf_t
{
    ffi::c::user_show(user,
                      user_length,
                      seeed)
}
