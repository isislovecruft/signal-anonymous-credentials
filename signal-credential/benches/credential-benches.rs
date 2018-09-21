#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;
extern crate rand;

use criterion::Criterion;

use rand::thread_rng;

use signal_credential::SystemParameters;
use signal_credential::IssuerSecretKey;
use signal_credential::SignalIssuer;
use signal_credential::IssuerParameters;

mod credential_benches {
    fn credential_request_client(c: &mut Criterion) {
        let system_parameters: SystemParameters = SystemParameters::from(H);
        let issuer_secret_key: IssuerSecretKey = IssuerSecretKey::new(NUMBER_OF_ATTRIBUTES);
        let issuer: SignalIssuer = SignalIssuer::new(system_parameters, Some(&issuer_secret_key));
        let issuer_parameters: IssuerParameters = issuer.issuer_parameters.clone();
        let alice_phone_number_input: &str = "14155551234";

        c.bench_function("Credential request client", move |b| {
            b.iter(|| SignalUser::new(system_parameters,
                                      issuer_parameters.clone(),
                                      None, // no encrypted attributes so the key isn't needed
                                      String::from(alice_phone_number_input)))
        });
    }

    criterion_group!{
        name = credential_benches;
        config = Criterion::default();
        targets =
            credential_request_client,
    }
}

criterion_main!(
    credential_benches::credential_benches,
);
