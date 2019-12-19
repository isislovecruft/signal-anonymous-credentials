common api
----------

    system_parameters_create(seed) -> system_parameters;

issuer api
----------

    issuer_create(system_parameters, seed) -> amacs_keypair;
    issuer_new(system_parameters, amacs_keypair) -> issuer;
    issuer_get_issuer_parameters(issuer) -> issuer_parameters;
    issuer_issue(issuer, phone_number, seed) -> issuance;

user api
--------

    user_obtain_finish(phone_number, system_parameters, issuer_parameters, issuance) -> user;
    user_show(user, commitment_and_opening, seed) -> presentation;
    user_create_roster_entry_commitment(phone_number, system_parametes, seed) -> commitment_and_opening;
    user_open_roster_entry_commitment(commitment_and_opening, system_parameters) -> bool;
