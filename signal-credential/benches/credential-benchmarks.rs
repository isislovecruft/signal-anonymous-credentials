#![allow(non_snake_case)]
#![allow(unused_must_use)]

#[macro_use]
extern crate criterion;
extern crate signal_credential;
extern crate rand;

use criterion::Criterion;

use rand::thread_rng;

use signal_credential::GroupRosterKey;
use signal_credential::GroupMembershipLevel;
use signal_credential::GroupMembershipRoster;
use signal_credential::IssuerSecretKey;
use signal_credential::IssuerParameters;
use signal_credential::RosterEntry;
use signal_credential::SignalCredentialIssuance;
use signal_credential::SignalCredentialPresentation;
use signal_credential::SignalCredentialRequest;
use signal_credential::SignalIssuer;
use signal_credential::SignalUser;
use signal_credential::SystemParameters;
use signal_credential::VerifiedSignalCredential;
use signal_credential::NUMBER_OF_ATTRIBUTES;

const H: [u8; 32] = [ 184, 238, 220,  64,   5, 247,  91, 135,
                      93, 125, 218,  60,  36, 165, 166, 178,
                      118, 188,  77,  27, 133, 146, 193, 133,
                      234,  95,  69, 227, 213, 197,  84,  98, ];

mod credential_benches {
    use super::*;

    fn credential_request_client(c: &mut Criterion) {
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: String = String::new("14155551234");
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    alice_phone_number_input);

        c.bench_function("step 0: credential request from client", move |b| {
            b.iter(|| alice.obtain(&mut alice_rng))
        });
    }

    fn credential_issuance_server(c: &mut Criterion) {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: String = String::new("14155551234");
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    alice_phone_number_input);
        let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();

        c.bench_function("step 1: credential issuance by server", move |b| {
            b.iter(|| issuer.issue(&alice_request, &mut issuer_rng))
        });
    }

    fn credential_obtain_client(c: &mut Criterion) {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: String = String::new("14155551234");
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    alice_phone_number_input);
        let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request,
                                                                    &alice_phone_number_input,
                                                                    &mut issuer_rng).unwrap();

        c.bench_function("step 2: credential obtain by client", move |b| {
            b.iter(|| alice.obtain_finish(Some(&alice_issuance)))
        });
    }

    fn credential_presentation_client(c: &mut Criterion) {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: String = String::new("14155551234");
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    alice_phone_number_input);
        let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request,
                                                                    &alice_phone_number_input,
                                                                    &mut issuer_rng).unwrap();

        alice.obtain_finish(Some(&alice_issuance));

        c.bench_function("step 3: credential presentation by client", move |b| {
            b.iter(|| alice.show(&mut alice_rng))
        });
    }

    fn credential_verification_server(c: &mut Criterion) {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: String = String::new("14155551234");
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    alice_phone_number_input);
        let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request,
                                                                    &alice_phone_number_input,
                                                                    &mut issuer_rng).unwrap();

        alice.obtain_finish(Some(&alice_issuance));

        let alice_presentation: SignalCredentialPresentation = alice.show(&mut alice_rng).unwrap();

        c.bench_function("step 4: credential verification by server", move |b| {
            b.iter(|| issuer.verify(&alice_presentation))
        });
    }

    fn group_membership_server(c: &mut Criterion) {
        let mut issuer_rng = thread_rng();
        let mut alice_rng = thread_rng();
        let mut bob_rng = thread_rng();

        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: String = String::new("14155551234");
        let mut alice: SignalUser = SignalUser::new(system_parameters,
                                                    issuer_parameters.clone(),
                                                    None, // no encrypted attributes so the key isn't needed
                                                    alice_phone_number_input);
        let alice_request: SignalCredentialRequest = alice.obtain(&mut alice_rng).unwrap();
        let alice_issuance: SignalCredentialIssuance = issuer.issue(&alice_request,
                                                                    &alice_phone_number_input,
                                                                    &mut issuer_rng).unwrap();

        alice.obtain_finish(Some(&alice_issuance));

        // Pretend that Bob had previously made a Signal group with a key:
        let bob_phone_number_input: String = String::new("14155556666");
        let mut bob: SignalUser = SignalUser::new(system_parameters,
                                                  issuer_parameters.clone(),
                                                  None, // no encrypted attributes so the key isn't needed
                                                  bob_phone_number_input);
        let bob_request: SignalCredentialRequest = bob.obtain(&mut bob_rng).unwrap();
        let bob_issuance: SignalCredentialIssuance = issuer.issue(&bob_request,
                                                                  &bob_phone_number_input,
                                                                  &mut issuer_rng).unwrap();

        bob.obtain_finish(Some(&bob_issuance));

        let alice_roster_entry: RosterEntry = alice.roster_entry.unwrap();
        let bob_roster_entry: RosterEntry = bob.roster_entry.unwrap();
        let group_roster_key: GroupRosterKey = GroupRosterKey([0u8; 32]);
        let mut roster: GroupMembershipRoster = GroupMembershipRoster::new(42, bob_roster_entry,
                                                                           group_roster_key);
        roster.add_user(alice_roster_entry);

        c.bench_function("step 4: group membership verification by server", move |b| {
            let alice_presentation: SignalCredentialPresentation = alice.show(&mut alice_rng).unwrap();
            let verified_credential: VerifiedSignalCredential = issuer.verify(&alice_presentation).unwrap().clone();

            b.iter(|| issuer.verify_roster_membership(&verified_credential, &roster,
                                                      &GroupMembershipLevel::User))
        });
    }

    criterion_group!{
        name = credential_benches;
        config = Criterion::default();
        targets =
            credential_request_client,
            credential_issuance_server,
            credential_obtain_client,
            credential_presentation_client,
            credential_verification_server,
            group_membership_server,
    }
}

criterion_main!(
    credential_benches::credential_benches,
);
