// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#include <stdint.h>

const uint LENGTH_SEED = 32;
const uint LENGTH_SYSTEM_PARAMETERS = 64;
const uint LENGTH_ISSUER = 160;
const uint LENGTH_ISSUER_PARAMETERS = 32;
const uint LENGTH_ISSUER_KEYPAIR = 96;
const uint LENGTH_USER = 416;
const uint LENGTH_CREDENTIAL_REQUEST = 248;
const uint LENGTH_CREDENTIAL_ISSUANCE = 328;
const uint LENGTH_CREDENTIAL_PRESENTATION = 512;
const uint LENGTH_VERIFIED_CREDENTIAL = 512;

// RUST_C_COUPLED: ffi/src/c.rs buf_t
typedef struct buf_s {
  const uint64_t len;
  const uint8_t* ptr;
} buf_t;

buf_t system_parameters_create(const uint8_t* H);
buf_t issuer_create(const uint8_t* system_parameters,
                    const uint64_t system_parameters_length,
                    const uint8_t* seed);
buf_t issuer_new(const uint8_t* system_parameters,
                 const uint64_t system_parameters_length,
                 const uint8_t* keypair,
                 const uint64_t keypair_length);
buf_t issuer_get_issuer_parameters(const uint8_t* issuer,
                                   const uint64_t issuer_length);
buf_t issuer_issue(const uint8_t* issuer,
                   const uint64_t issuer_length,
                   const uint8_t* seed,
                   const uint8_t* request,
                   const uint64_t request_len,
                   const uint8_t* phone_number,
                   const uint64_t phone_number_length);
buf_t issuer_verify(const uint8_t* issuer,
                    const uint64_t issuer_length,
                    const uint8_t* presentation,
                    const uint64_t presentation_length);
buf_t issuer_verify_roster_membership_owner(const uint8_t* issuer,
                                            const uint64_t issuer_length,
                                            const uint8_t* verified_credential,
                                            const uint64_t verified_credential_length,
                                            const uint8_t* roster,
                                            const uint64_t roster_length);
buf_t issuer_verify_roster_membership_admin(const uint8_t* issuer,
                                            const uint64_t issuer_length,
                                            const uint8_t* verified_credential,
                                            const uint64_t verified_credential_length,
                                            const uint8_t* roster,
                                            const uint64_t roster_length);
buf_t issuer_verify_roster_membership_user(const uint8_t* issuer,
                                           const uint64_t issuer_length,
                                           const uint8_t* verified_credential,
                                           const uint64_t verified_credential_length,
                                           const uint8_t* roster,
                                           const uint64_t roster_length);
buf_t user_new(const uint8_t* system_parameters,
               const uint64_t system_parameters_length,
               const uint8_t* keypair,
               const uint64_t keypair_length,
               const uint8_t* phone_number,
               const uint64_t phone_number_length,
               const uint8_t* issuer_parameters,
               const uint64_t issuer_parameters_length,
               const uint8_t* seed);
buf_t user_obtain(const uint8_t* user,
                  const uint64_t user_len);
buf_t user_obtain_finish(const uint8_t* user,
                         const uint64_t user_length,
                         const uint8_t* issuance,
                         const uint64_t issuance_length);
buf_t user_show(const uint8_t* user,
                const uint64_t user_length,
                const uint8_t* seed);
