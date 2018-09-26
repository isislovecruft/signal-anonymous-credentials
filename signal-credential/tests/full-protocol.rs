// -*- mode: rust; -*-
//
// This file is part of signal-credential.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

extern crate aeonflux;
extern crate rand;
extern crate signal_credential;

use aeonflux::issuer::IssuerParameters;
use aeonflux::parameters::SystemParameters;
use rand::thread_rng;
use signal_credential::credential::*;
use signal_credential::issuer::*;
use signal_credential::roster::GroupMembershipLevel;
use signal_credential::roster::GroupMembershipRoster;
use signal_credential::roster::GroupRosterKey;
use signal_credential::roster::RosterEntry;
use signal_credential::user::SignalUser;

const H: [u8; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                      93, 125, 218,  60,  36, 165, 166, 178,
                      118, 188,  77,  27, 133, 146, 193, 133,
                      234,  95,  69, 227, 213, 197,  84,  98, ];

#[test]
fn credential_issuance_and_presentation() {
    // Create RNGs for each party.
    let mut issuer_rng = thread_rng();
    let mut alice_rng = thread_rng();
    let mut bob_rng = thread_rng();

    // Create an issuer
    let system_parameters: SystemParameters = SystemParameters::from(H);
    let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES, &mut issuer_rng);
    let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key), &mut issuer_rng);

    // Get the issuer's parameters so we can advertise them to new users:
    let issuer_parameters: IssuerParameters = issuer.issuer.issuer_parameters.clone();

    // Create a couple users
    let alice_phone_number_input: String = String::from("14155551234");
    let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                issuer_parameters.clone(),
                                                None, // no encrypted attributes so the key isn't needed
                                                alice_phone_number_input.clone());

    let bob_phone_number_input: String = String::from("14155556666");
    let mut bob: SignalUser = SignalUser::new(system_parameters,
                                              issuer_parameters.clone(),
                                              None, // no encrypted attributes so the key isn't needed
                                              bob_phone_number_input.clone());

    // Form a request for a credential
    let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();

    // Try to get the issuer to give Alice a new credential
    let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request,
                                                                &alice_phone_number_input,
                                                                &mut issuer_rng).unwrap();

    // Give the result back to Alice for processing
    alice.obtain_finish(Some(&alice_issuance));
        
    // And the same for Bob:
    let bob_request: SignalCredentialRequest = bob.obtain(&mut bob_rng).unwrap();
    let bob_issuance: SignalCredentialIssuance = issuer.issue(&bob_request,
                                                              &bob_phone_number_input,
                                                              &mut issuer_rng).unwrap();

    bob.obtain_finish(Some(&bob_issuance));

    let alice_roster_entry: RosterEntry = alice.roster_entry.unwrap();
    let bob_roster_entry: RosterEntry = bob.roster_entry.unwrap();

    // Pretend that Bob had previously made a Signal group with a key:
    let group_roster_key: GroupRosterKey = GroupRosterKey([0u8; 32]);
    let mut roster: GroupMembershipRoster = GroupMembershipRoster::new(42, bob_roster_entry,
                                                                       group_roster_key);

    // Now Bob adds Alice:
    let _ = roster.add_user(alice_roster_entry); // XXX that api is bad

    // Alice wants to prove they're in the roster:
    let alice_presentation: SignalCredentialPresentation = alice.show(&mut alice_rng).unwrap();

    let verified_credential: VerifiedSignalCredential = issuer.verify(&alice_presentation).unwrap();

    let user_proof = issuer.verify_roster_membership(&verified_credential, &roster,
                                                     &GroupMembershipLevel::User);
    assert!(user_proof.is_ok());

    let admin_proof = issuer.verify_roster_membership(&verified_credential, &roster,
                                                      &GroupMembershipLevel::Admin);
    assert!(admin_proof.is_err());
}
