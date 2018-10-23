(function() {
    var wasm;
    const __exports = {};


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
    * * `seed` an array of 32 bytes, which will be used to seed an RNG.
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
    __exports.system_parameters_create = function(arg0) {
        const [ptr0, len0] = passArray8ToWasm(arg0);
        try {
            return takeObject(wasm.system_parameters_create(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    };

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
    * An `aeonflux::amacs::Keypair` as a `JsValue`¹.
    *
    * ¹ Which, by the way, you won\'t be able to do much of anything with since
    *   it\'s internally serialised to literal bytes, so best don\'t touch it.
    *
    * @param {any} arg0
    * @param {Uint8Array} arg1
    * @returns {any}
    */
    __exports.issuer_create = function(arg0, arg1) {
        const [ptr1, len1] = passArray8ToWasm(arg1);
        try {
            return takeObject(wasm.issuer_create(addHeapObject(arg0), ptr1, len1));

        } finally {
            wasm.__wbindgen_free(ptr1, len1 * 1);

        }

    };

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
    __exports.issuer_get_issuer_parameters = function(arg0) {
        return takeObject(wasm.issuer_get_issuer_parameters(addHeapObject(arg0)));
    };

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
    __exports.issuer_new = function(arg0, arg1) {
        return takeObject(wasm.issuer_new(addHeapObject(arg0), addHeapObject(arg1)));
    };

    /**
    * Issue a new credential to a user.
    *
    * # Inputs
    *
    * * `issuer` is a `SignalIssuer` as a `JsValue`.
    * * `seed` must be a byte array with length 32, containing random bytes for
    *   seeding a CSPRNG.
    * * `phone_number` is the `SignalUser`\'s phone number as bytes, e.g.
    *   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
    * * `seed` must be a byte array with length 32, containing random
    *   bytes for seeding a CSPRNG.
    *
    * # Returns
    *
    * A `SignalCredentialIssuance` as a `JsValue` if the credential issuance was
    * successful, otherwise a single byte set to `0`.
    *
    * @param {any} arg0
    * @param {Uint8Array} arg1
    * @param {Uint8Array} arg2
    * @returns {any}
    */
    __exports.issuer_issue = function(arg0, arg1, arg2) {
        const [ptr1, len1] = passArray8ToWasm(arg1);
        const [ptr2, len2] = passArray8ToWasm(arg2);
        try {
            return takeObject(wasm.issuer_issue(addHeapObject(arg0), ptr1, len1, ptr2, len2));

        } finally {
            wasm.__wbindgen_free(ptr1, len1 * 1);
            wasm.__wbindgen_free(ptr2, len2 * 1);

        }

    };

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
    __exports.issuer_verify = function(arg0, arg1) {
        return takeObject(wasm.issuer_verify(addHeapObject(arg0), addHeapObject(arg1)));
    };

    /**
    * Check if a user is an owner in a Signal group.
    *
    * # Inputs
    *
    * * `issuer` is a `SignalIssuer` as a `JsValue`.
    * * `verified_credential` is a `VerifiedSignalCredential` as a `JsValue`, as
    *   may be obtained via `issuer_verify()`.
    *
    * # Returns
    *
    * The roster entry commitment, if the user\'s credential has a committed value
    * which matches the value in the roster entry commitment, `false` otherwise.
    *
    * @param {any} arg0
    * @param {any} arg1
    * @returns {any}
    */
    __exports.issuer_verify_roster_membership = function(arg0, arg1) {
        return takeObject(wasm.issuer_verify_roster_membership(addHeapObject(arg0), addHeapObject(arg1)));
    };

    /**
    * Check the proof of correct issuance on a credential issuance and potentially
    * save the credential for later use.
    *
    * # Inputs
    *
    * * `phone_number` is the `SignalUser`\'s phone number as bytes, e.g.
    *   `[1, 4, 1, 5, 5, 5, 5, 1, 2, 3, 4]`.
    * * `system_parameters` are a globally agreed upon set of
    *   `aeonflux::parameters::SystemParameters`, which may be obtained via
    *   `system_parameters_create()`.
    * * `issuer_parameters` is an `aeonflux::amacs::PublicKey` as a `JsValue`,
    *   which can be obtained by calling `issuer_get_issuer_parameters()`.
    * * `issuance` is a `SignalCredentialIssuance` as a `JsValue`, which is
    *   obtainable via `issuer_issue()`.
    *
    * # Returns
    *
    * The `SignalUser` as a `JsValue` if successful, otherwise a single byte set
    * to `0`.
    *
    * @param {Uint8Array} arg0
    * @param {any} arg1
    * @param {any} arg2
    * @param {any} arg3
    * @returns {any}
    */
    __exports.user_obtain_finish = function(arg0, arg1, arg2, arg3) {
        const [ptr0, len0] = passArray8ToWasm(arg0);
        try {
            return takeObject(wasm.user_obtain_finish(ptr0, len0, addHeapObject(arg1), addHeapObject(arg2), addHeapObject(arg3)));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    };

    /**
    * Present a user\'s credential to the issuer for verification.
    *
    * # Inputs
    *
    * * `user` a `SignalUser` as a `JsValue`.
    * * `roster_entry_commitment` is a commitment to the user\'s phone number and
    *   an opening.
    * * `seed` must be a byte array with length 32, containing random bytes for
    *   seeding a CSPRNG.
    *
    * # Returns
    *
    * A `SignalCredentialPresentation` as a `JsValue`.
    *
    * @param {any} arg0
    * @param {any} arg1
    * @param {Uint8Array} arg2
    * @returns {any}
    */
    __exports.user_show = function(arg0, arg1, arg2) {
        const [ptr2, len2] = passArray8ToWasm(arg2);
        try {
            return takeObject(wasm.user_show(addHeapObject(arg0), addHeapObject(arg1), ptr2, len2));

        } finally {
            wasm.__wbindgen_free(ptr2, len2 * 1);

        }

    };

    __exports.__wbindgen_object_drop_ref = function(i) {
        dropRef(i);
    };

    __exports.__wbindgen_number_new = function(i) {
        return addHeapObject(i);
    };

    let cachedTextDecoder = new TextDecoder('utf-8');

    function getStringFromWasm(ptr, len) {
        return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
    }

    __exports.__wbindgen_json_parse = function(ptr, len) {
        return addHeapObject(JSON.parse(getStringFromWasm(ptr, len)));
    };

    let cachedTextEncoder = new TextEncoder('utf-8');

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

    __exports.__wbindgen_json_serialize = function(idx, ptrptr) {
        const [ptr, len] = passStringToWasm(JSON.stringify(getObject(idx)));
        getUint32Memory()[ptrptr / 4] = ptr;
        return len;
    };

    __exports.__wbindgen_throw = function(ptr, len) {
        throw new Error(getStringFromWasm(ptr, len));
    };

    function init(wasm_path) {
        const fetchPromise = fetch(wasm_path);
        let resultPromise;
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            resultPromise = WebAssembly.instantiateStreaming(fetchPromise, { './credential': __exports });
        } else {
            resultPromise = fetchPromise
            .then(response => response.arrayBuffer())
            .then(buffer => WebAssembly.instantiate(buffer, { './credential': __exports }));
        }
        return resultPromise.then(({instance}) => {
            wasm = init.wasm = instance.exports;
            return;
        });
    };
    self.wasm_bindgen = Object.assign(init, __exports);
})();
