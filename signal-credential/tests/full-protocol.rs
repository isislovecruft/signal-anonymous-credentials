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
use signal_credential::phone_number::CommittedPhoneNumber;
use signal_credential::user::SignalUser;

#[test]
fn credential_issuance_and_presentation() {
    // Create RNGs for each party.
    let mut issuer_rng = thread_rng();
    let mut alice_rng = thread_rng();
    let mut bob_rng = thread_rng();

    // Create an issuer
    let system_parameters: SystemParameters = SystemParameters::hunt_and_peck(&mut issuer_rng);
    let issuer: SignalIssuer = SignalIssuer::create(system_parameters, &mut issuer_rng);

    // Get the issuer's parameters so we can advertise them to new users:
    let issuer_parameters: IssuerParameters = issuer.issuer.keypair.public.clone();

    // Create a couple users
    let alice_phone_number_input: &[u8] = &[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4];
    let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                issuer_parameters.clone(),
                                                None, // no encrypted attributes so the key isn't needed
                                                alice_phone_number_input.clone()).unwrap();

    let bob_phone_number_input: &[u8] = &[1, 4, 1, 5, 5, 5, 5, 6, 6, 6, 6];
    let mut bob: SignalUser = SignalUser::new(system_parameters,
                                              issuer_parameters.clone(),
                                              None, // no encrypted attributes so the key isn't needed
                                              bob_phone_number_input.clone()).unwrap();

    // Try to get the issuer to give Alice a new credential
    let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_phone_number_input,
                                                                &mut issuer_rng).unwrap();

    // Give the result back to Alice for processing
    alice.obtain_finish(Some(&alice_issuance)).unwrap();
        
    // And the same for Bob:
    let bob_issuance: SignalCredentialIssuance = issuer.issue(&bob_phone_number_input,
                                                              &mut issuer_rng).unwrap();

    bob.obtain_finish(Some(&bob_issuance)).unwrap();

    let (bob_roster_entry_commitment,
         _bob_roster_entry_commitment_opening) = bob.create_roster_entry_commitment(&mut bob_rng);

    // Pretend that Bob had previously made a Signal group with a key:
    let mut roster_admins: Vec<CommittedPhoneNumber> = Vec::new();
    let mut roster_users: Vec<CommittedPhoneNumber> = Vec::new();

    roster_admins.push(bob_roster_entry_commitment);

    let (alice_roster_entry_commitment,
         alice_roster_entry_commitment_opening) = alice.create_roster_entry_commitment(&mut alice_rng);

    // Now Bob adds Alice:
    roster_users.push(alice_roster_entry_commitment);

    // Alice wants to prove they're in the roster:
    let alice_presentation: SignalCredentialPresentation = alice.show(&mut alice_rng,
                                                                      &alice_roster_entry_commitment,
                                                                      &alice_roster_entry_commitment_opening).unwrap();

    let verified_credential: VerifiedSignalCredential = issuer.verify(alice_presentation).unwrap();

    let user_proof = issuer.verify_roster_membership(&verified_credential);
    assert!(user_proof.is_ok());

    let server_copy_alice_roster_entry_commitment = user_proof.unwrap();

    // Now the issuer can check whether Alice was an admin or a user:
    assert!(! roster_admins.contains(&server_copy_alice_roster_entry_commitment));
    assert!(roster_users.contains(&server_copy_alice_roster_entry_commitment));
}
