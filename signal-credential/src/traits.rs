// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use amacs::IssuerParameters;
use amacs::SecretKey;

use elgamal;

use credential::SignalCredentialBlindIssuance;
use credential::SignalCredentialBlindRequest;
use credential::SignalCredentialPresentation;
use errors::CredentialError;
use parameters::SystemParameters;

// XXX these aren't generic at all :(
pub trait CredentialIssuer {
    type Credential;

    fn new(system: SystemParameters, secret_key: Option<SecretKey>) -> Self;
    fn blind_issue(&self, request: SignalCredentialBlindRequest)
        -> Result<SignalCredentialBlindIssuance, CredentialError>;
    fn verify_proof(&self, proof: &Self::Credential) -> Result<(), CredentialError>;
}

pub trait CredentialUser {
    type Issuer: CredentialIssuer;
    type Credential;

    fn new(system_parameters: SystemParameters,issuer_parameters: IssuerParameters, key: Option<elgamal::Keypair>) -> Self;
    fn register_phone_number(&mut self, phone_number: &String) -> Result<(), CredentialError>;
    fn blind_obtain(&self) -> Result<SignalCredentialBlindRequest, CredentialError>;
    fn blind_obtain_finish(&mut self, issuance: Option<SignalCredentialBlindIssuance>)
        -> Result<(), CredentialError>;
    fn show_proof(&self) -> Result<SignalCredentialPresentation, CredentialError>;
}
