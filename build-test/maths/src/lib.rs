// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

extern crate curve25519_dalek;
extern crate rand;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;

use rand::thread_rng;

pub fn do_things_with_maths() -> CompressedRistretto {
    let mut csprng = thread_rng();
    let phone_number: Scalar = 4155551234u64.into();
    let blinding: Scalar = Scalar::random(&mut csprng);
    let nonce: RistrettoPoint = &RISTRETTO_BASEPOINT_TABLE * &Scalar::random(&mut csprng);
    let exponent: Scalar = Scalar::one() + (blinding * phone_number);

    (nonce * exponent).compress()
}

#[cfg(test)]
mod test {
    use super::*;

    use curve25519_dalek::traits::Identity;

    #[test]
    fn test_do_things_with_maths() {
        let x: CompressedRistretto = do_things_with_maths();
        let id: CompressedRistretto = RistrettoPoint::identity().compress();

        assert!(x != id);

        println!("Hooray, it works! You did some maths and made a thing:\n{:?}", x);
    }
}
