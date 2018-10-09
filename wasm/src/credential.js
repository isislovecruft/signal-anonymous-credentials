/* tslint:disable */
import * as wasm from './credential_bg';

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory;
}

function passArray8ToWasm(arg) {
    const ptr = wasm.__wbindgen_malloc(arg.length * 1);
    getUint8Memory().set(arg, ptr / 1);
    return [ptr, arg.length];
}

const stack = [];

const slab = [{ obj: undefined }, { obj: null }, { obj: true }, { obj: false }];

function getObject(idx) {
    if ((idx & 1) === 1) {
        return stack[idx >> 1];
    } else {
        const val = slab[idx >> 1];

        return val.obj;

    }
}

let slab_next = slab.length;

function dropRef(idx) {

    idx = idx >> 1;
    if (idx < 4) return;
    let obj = slab[idx];

    obj.cnt -= 1;
    if (obj.cnt > 0) return;

    // If we hit 0 then free up our space in the slab
    slab[idx] = slab_next;
    slab_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropRef(idx);
    return ret;
}
/**
* Create some globally-agreed upon `SystemParameters` from a distinguished
* basepoint, `H`.
*
* # Inputs
*
* * `H` an array of 32 bytes, which should represent a valid
*  `curve25519_dalek::ristretto::RistrettoPoint` chosen orthogonally to the
*  `curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT`, a.k.a `G`,
*  s.t. `log_G(H)` is intractible.
*
* # Returns
*
* The `aeonflux::parameters::SystemParameters` as a `JsValue`¹.
*
* ¹ Which, by the way, you won\'t be able to do much of anything with since
*   it\'s internally serialised to literal bytes, so best don\'t touch it.
*
* @param {Uint8Array} arg0
* @returns {any}
*/
export function system_parameters_create(arg0) {
    const [ptr0, len0] = passArray8ToWasm(arg0);
    try {
        return takeObject(wasm.system_parameters_create(ptr0, len0));

    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);

    }

}

function addHeapObject(obj) {
    if (slab_next === slab.length) slab.push(slab.length + 1);
    const idx = slab_next;
    const next = slab[idx];

    slab_next = next;

    slab[idx] = { obj, cnt: 1 };
    return idx << 1;
}
/**
* Create a new credential issuer.
*
* # Inputs
*
* * `system_parameters` are a globally agreed upon set of
*   `aeonflux::parameters::SystemParameters`, which may be obtained via
*   `system_parameters_create()`.
* * `seed` must be a byte array with length 32, containing random
*   bytes for seeding a CSPRNG.
*
* # Returns
*
* A `signal_credential::issuer::SignalIssuer` as a `JsValue`¹.
*
* ¹ Which, by the way, you won\'t be able to do much of anything with since
*   it\'s internally serialised to literal bytes, so best don\'t touch it.
*
* # Note
*
* After calling this function, you probably **really** want to call
* `issuer_get_keypair()` with the result, in order to retain the necessary
* data for re-instantiating this credential issuer with `issuer_new()` later.
*
* @param {any} arg0
* @param {Uint8Array} arg1
* @returns {any}
*/
export function issuer_create(arg0, arg1) {
    const [ptr1, len1] = passArray8ToWasm(arg1);
    try {
        return takeObject(wasm.issuer_create(addHeapObject(arg0), ptr1, len1));

    } finally {
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* Get an instantiated credential issuer\'s aMACs keypair.
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
*
* # Returns
*
* * An `aeonflux::amacs::Keypair` as a `JsValue`¹.
*
* ¹ Which, by the way, you won\'t be able to do much of anything with since
*   it\'s internally serialised to literal bytes, so best don\'t touch it.
*
* @param {any} arg0
* @returns {any}
*/
export function issuer_get_keypair(arg0) {
    return takeObject(wasm.issuer_get_keypair(addHeapObject(arg0)));
}

/**
* Get this credential issuer\'s parameters (a.k.a their public key material).
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
*
* # Returns
*
* * An `aeonflux::amacs::PublicKey` as a `JsValue`¹.
*
* ¹ Which, by the way, you won\'t be able to do much of anything with since
*   it\'s internally serialised to literal bytes, so best don\'t touch it.
*
* @param {any} arg0
* @returns {any}
*/
export function issuer_get_issuer_parameters(arg0) {
    return takeObject(wasm.issuer_get_issuer_parameters(addHeapObject(arg0)));
}

/**
* Instantiate a previously generated credential issuer.
*
* # Inputs
*
* * `system_parameters` are a globally agreed upon set of
*   `aeonflux::parameters::SystemParameters`, which may be obtained via
*   `system_parameters_create()`.
* * `keypair` is an `aeonflux::amacs::Keypair` as a `JsValue`, as can be
*   obtained from `issuer_get_keypair()`.
*
* # Returns
*
* A `signal_credential::issuer::SignalIssuer` as a `JsValue`¹ if successful,
* otherwise a single byte set to `0`.
*
* ¹ Which, by the way, you won\'t be able to do much of anything with since
*   it\'s internally serialised to literal bytes, so best don\'t touch it.
*
* # Note
*
* This is merely an instantiation function.  If you\'d like to create a
* brand-new issuer (which generally should only be done on the Signal server),
* use `issuer_create()`.
*
* @param {any} arg0
* @param {any} arg1
* @returns {any}
*/
export function issuer_new(arg0, arg1) {
    return takeObject(wasm.issuer_new(addHeapObject(arg0), addHeapObject(arg1)));
}

/**
* Issue a new credential to a user.
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
* * `seed` must be a byte array with length 32, containing random bytes for
*   seeding a CSPRNG.
* * `request` is a `SignalCredentialRequest` as a `JsValue`, from a `SignalUser`.
* * `phone_number` is the `SignalUser`\'s phone number as bytes, e.g.
*   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
*
* # Returns
*
* A `SignalCredentialIssuance` as a `JsValue` if the credential issuance was
* successful, otherwise a single byte set to `0`.
*
* @param {any} arg0
* @param {Uint8Array} arg1
* @param {any} arg2
* @param {Uint8Array} arg3
* @returns {any}
*/
export function issuer_issue(arg0, arg1, arg2, arg3) {
    const [ptr1, len1] = passArray8ToWasm(arg1);
    const [ptr3, len3] = passArray8ToWasm(arg3);
    try {
        return takeObject(wasm.issuer_issue(addHeapObject(arg0), ptr1, len1, addHeapObject(arg2), ptr3, len3));

    } finally {
        wasm.__wbindgen_free(ptr1, len1 * 1);
        wasm.__wbindgen_free(ptr3, len3 * 1);

    }

}

/**
* Check a `presentation` of a `SignalUser`\'s credential.
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
* * `presentation` is a `SignalCredentialPresentation` as a `JsValue`.
*
* # Returns
*
* If successfullly verified, returns a `VerifiedSignalCredential` as a
* `JsValue`.  Otherwise, returns a single byte set to `0`.
*
* @param {any} arg0
* @param {any} arg1
* @returns {any}
*/
export function issuer_verify(arg0, arg1) {
    return takeObject(wasm.issuer_verify(addHeapObject(arg0), addHeapObject(arg1)));
}

/**
* Check if a user is an owner in a Signal group.
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
* * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
*   may be obtained via `issuer_verify()`.
* * `roster` is a `GroupMembershipRoster` as a `JsValue`.
*
* # Returns
*
* `true` if the user is an owner in the group, `false` otherwise.
* @param {any} arg0
* @param {any} arg1
* @param {any} arg2
* @returns {boolean}
*/
export function issuer_verify_roster_membership_owner(arg0, arg1, arg2) {
    return (wasm.issuer_verify_roster_membership_owner(addHeapObject(arg0), addHeapObject(arg1), addHeapObject(arg2))) !== 0;
}

/**
* Check if a user is an admin in a Signal group.
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
* * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
*   may be obtained via `issuer_verify()`.
* * `roster` is a `GroupMembershipRoster` as a `JsValue`.
*
* # Returns
*
* `true` if the user is an admin in the group, `false` otherwise.
* @param {any} arg0
* @param {any} arg1
* @param {any} arg2
* @returns {boolean}
*/
export function issuer_verify_roster_membership_admin(arg0, arg1, arg2) {
    return (wasm.issuer_verify_roster_membership_admin(addHeapObject(arg0), addHeapObject(arg1), addHeapObject(arg2))) !== 0;
}

/**
* Check if a user is a user-level member in a Signal group.
*
* # Inputs
*
* * `issuer` is a `SignalIssuer` as a `JsValue`.
* * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
*   may be obtained via `issuer_verify()`.
* * `roster` is a `GroupMembershipRoster` as a `JsValue`.
*
* # Returns
*
* `true` if the user is an user in the group, `false` otherwise.
* @param {any} arg0
* @param {any} arg1
* @param {any} arg2
* @returns {boolean}
*/
export function issuer_verify_roster_membership_user(arg0, arg1, arg2) {
    return (wasm.issuer_verify_roster_membership_user(addHeapObject(arg0), addHeapObject(arg1), addHeapObject(arg2))) !== 0;
}

/**
* Create a new `SignalUser`.
*
* # Inputs
*
* * `system_parameters` are a globally agreed upon set of
*   `aeonflux::parameters::SystemParameters`, which may be obtained via
*   `system_parameters_create()`.
* * `keypair` is optionally an `aeonflux::elgamal::Keypair` as a `JsValue` if
*   the credential issuer supports blinded issuance, otherwise it may be
*   `JsValue::from(0)` in order to signify that the user has no keypair.
* * `phone_number` is the `SignalUser`\'s phone number as bytes, e.g.
*   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
* * `issuer_parameters` is an `aeonflux::amacs::PublicKey` as a `JsValue`,
*   which can be obtained by calling `issuer_get_issuer_parameters()`.
* * `seed` must be a byte array with length 32, containing random bytes for
*   seeding a CSPRNG.
*
* # Returns
*
* A `SignalUser` as a `JsValue` if successful, otherwise a single byte set to `0`.
*
* @param {any} arg0
* @param {any} arg1
* @param {Uint8Array} arg2
* @param {any} arg3
* @param {Uint8Array} arg4
* @returns {any}
*/
export function user_new(arg0, arg1, arg2, arg3, arg4) {
    const [ptr2, len2] = passArray8ToWasm(arg2);
    const [ptr4, len4] = passArray8ToWasm(arg4);
    try {
        return takeObject(wasm.user_new(addHeapObject(arg0), addHeapObject(arg1), ptr2, len2, addHeapObject(arg3), ptr4, len4));

    } finally {
        wasm.__wbindgen_free(ptr2, len2 * 1);
        wasm.__wbindgen_free(ptr4, len4 * 1);

    }

}

/**
* Create a request for a new credential from the issuer.
*
* # Inputs
*
* * `user` a `SignalUser` as a `JsValue`.
*
* # Returns
*
* A `SignalCredentialRequest` as a `JsValue`.
*
* @param {any} arg0
* @returns {any}
*/
export function user_obtain(arg0) {
    return takeObject(wasm.user_obtain(addHeapObject(arg0)));
}

/**
* Check the proof of correct issuance on a credential issuance and potentially
* save the credential for later use.
*
* # Inputs
*
* * `user` a `SignalUser` as a `JsValue`.
* * `issuance` is a `SignalCredentialIssuance` as a `JsValue`, which is
*   obtainable via `issuer_issue()`.
*
* # Returns
*
* The updated `SignalUser` as a `JsValue` if successful, otherwise a single
* byte set to `0`.  (This new `SignalUser` should be used later, since it has
* the ability to present its credential.)
*
* @param {any} arg0
* @param {any} arg1
* @returns {any}
*/
export function user_obtain_finish(arg0, arg1) {
    return takeObject(wasm.user_obtain_finish(addHeapObject(arg0), addHeapObject(arg1)));
}

/**
* Present a user\'s credential to the issuer for verification.
*
* # Inputs
*
* * `user` a `SignalUser` as a `JsValue`.
* * `seed` must be a byte array with length 32, containing random bytes for
*   seeding a CSPRNG.
*
* # Returns
*
* A `SignalCredentialPresentation` as a `JsValue`.
*
* @param {any} arg0
* @param {Uint8Array} arg1
* @returns {any}
*/
export function user_show(arg0, arg1) {
    const [ptr1, len1] = passArray8ToWasm(arg1);
    try {
        return takeObject(wasm.user_show(addHeapObject(arg0), ptr1, len1));

    } finally {
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

export function __wbindgen_object_drop_ref(i) {
    dropRef(i);
}

export function __wbindgen_number_new(i) {
    return addHeapObject(i);
}

const lTextDecoder = typeof TextDecoder === 'undefined' ? require('util').TextDecoder : TextDecoder;

let cachedTextDecoder = new lTextDecoder('utf-8');

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}

export function __wbindgen_json_parse(ptr, len) {
    return addHeapObject(JSON.parse(getStringFromWasm(ptr, len)));
}

const lTextEncoder = typeof TextEncoder === 'undefined' ? require('util').TextEncoder : TextEncoder;

let cachedTextEncoder = new lTextEncoder('utf-8');

function passStringToWasm(arg) {

    const buf = cachedTextEncoder.encode(arg);
    const ptr = wasm.__wbindgen_malloc(buf.length);
    getUint8Memory().set(buf, ptr);
    return [ptr, buf.length];
}

let cachegetUint32Memory = null;
function getUint32Memory() {
    if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== wasm.memory.buffer) {
        cachegetUint32Memory = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory;
}

export function __wbindgen_json_serialize(idx, ptrptr) {
    const [ptr, len] = passStringToWasm(JSON.stringify(getObject(idx)));
    getUint32Memory()[ptrptr / 4] = ptr;
    return len;
}

export function __wbindgen_jsval_eq(a, b) {
    return getObject(a) === getObject(b) ? 1 : 0;
}

export function __wbindgen_throw(ptr, len) {
    throw new Error(getStringFromWasm(ptr, len));
}

