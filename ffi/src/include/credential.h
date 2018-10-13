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
const uint LENGTH_USER = 288;
const uint LENGTH_CREDENTIAL_ISSUANCE = 328;
const uint LENGTH_CREDENTIAL_PRESENTATION = 448;
const uint LENGTH_VERIFIED_CREDENTIAL = 448;

// RUST_C_COUPLED: ffi/src/c.rs buf_t
typedef struct buf_s {
  const uint64_t len;
  const uint8_t* ptr;
} buf_t;

buf_t system_parameters_create(const uint8_t* seed);
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
                   const uint8_t* phone_number,
                   const uint64_t phone_number_length,
                   const uint8_t* seed);
buf_t issuer_verify(const uint8_t* issuer,
                    const uint64_t issuer_length,
                    const uint8_t* presentation,
                    const uint64_t presentation_length);
buf_t issuer_verify_roster_membership(const uint8_t* issuer,
                                      const uint64_t issuer_length,
                                      const uint8_t* verified_credential,
                                      const uint64_t verified_credential_length);
buf_t user_obtain_finish(const uint8_t* phone_number,
                         const uint64_t phone_number_length,
                         const uint8_t* system_parameters,
                         const uint64_t system_parameters_length,
                         const uint8_t* issuer_parameters,
                         const uint64_t issuer_parameters_length,
                         const uint8_t* issuance,
                         const uint64_t issuance_length);
buf_t user_show(const uint8_t* user,
                const uint64_t user_length,
                const uint8_t* roster_entry_commitment,
                const uint64_t roster_entry_commitment_length,
                const uint8_t* seed);
buf_t roster_entry_commitment_create(const uint8_t* phone_number,
                                     const uint64_t phone_number_length,
                                     const uint8_t* system_parameters,
                                     const uint64_t system_parameters_length,
                                     const uint8_t* seed);
buf_t roster_entry_commitment_open(const uint8_t* roster_entry_commitment, // also contains the opening
                                     const uint64_t roster_entry_commitment_length,
                                     const uint8_t* phone_number,
                                     const uint64_t phone_number_length,
                                     const uint8_t* system_parameters,
                                     const uint64_t system_parameters_length);
