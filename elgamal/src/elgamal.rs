// -*- mode: rust; -*-
//
// This file is part of elgamal.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(not(feature = "std"))]
use core::ops::Add;

#[cfg(feature = "std")]
use std::ops::Add;

use clear_on_drop::clear::Clear;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::CryptoRng;
use rand::Rng;


#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub(crate) RistrettoPoint);

#[derive(Clone, Debug)]
pub struct SecretKey(pub(crate) Scalar);

#[derive(Clone, Debug)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// A plaintext elGamal message.
///
/// ElGamal cryptosystems in the elliptic curve context require a canonical,
/// invertible, isomorphic mapping from messages as scalars to messages as group
/// elements.  One such construction is given in "Elliptic Curve Cryptosystems"
/// (1987) by Neal Koblitz.
///
/// Rather than dealing with mapping scalars to group elements, instead we
/// require that the user save their plaintext while giving the encryption to
/// the credential issuer.  Later, rather than decrypt and map back to the
/// original scalar, they simply use the original plaintext.  For this reason,
/// we are able to map scalars to group elements by simply multiplying them by
/// the basepoint, which is obviously not invertible but works for the
/// algebraic-MAC-based anonymous credential blind issuance use-case.
pub struct Message(pub(crate) RistrettoPoint);

impl<'a> From<&'a Scalar> for Message {
    fn from(source: &'a Scalar) -> Message {
        Message(source * &RISTRETTO_BASEPOINT_TABLE)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Encryption {
    pub commitment: RistrettoPoint,
    pub encryption: RistrettoPoint,
}

impl<'a, 'b> Add<&'b Encryption> for &'a Encryption {
    type Output = Encryption;

    fn add(self, other: &'b Encryption) -> Encryption {
        Encryption {
            commitment: self.commitment + other.commitment,
            encryption: self.encryption + other.encryption,
        }
    }
}

/// An ephemeral key or nonce, used in elGamal encryptions and then discarded.
///
/// # Note
///
/// The encapsulated `Scalar` is `pub` so that we can access it (by borrow) for
/// zero-knowledge proof creations, without copying or changing its type
/// (otherwise the `clear()` on `Drop` would never run).
#[derive(Default)]
pub struct Ephemeral(pub Scalar);

impl From<Scalar> for Ephemeral {
    fn from(source: Scalar) -> Ephemeral {
        Ephemeral(source)
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl PublicKey {
    pub fn encrypt(&self, message: &Message, nonce: &Ephemeral)
        -> Encryption
    {
        let commitment: RistrettoPoint = &RISTRETTO_BASEPOINT_TABLE * &nonce.0;
        // XXX The mapping to the point representing the message must be invertible
        let encryption: RistrettoPoint = &message.0 + (&self.0 * &nonce.0);

        Encryption{ commitment, encryption }
    }
}

impl From<PublicKey> for RistrettoPoint {
    fn from(public: PublicKey) -> RistrettoPoint {
        public.0
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey(&RISTRETTO_BASEPOINT_TABLE * &secret.0)
    }
}

impl SecretKey {
    pub fn generate<C>(csprng: &mut C) -> SecretKey
    where
        C: CryptoRng + Rng,
    {
        SecretKey(Scalar::random(csprng))
    }

    pub fn decrypt(&self, encryption: &Encryption) -> RistrettoPoint {
        let secret: RistrettoPoint = &encryption.commitment * &self.0;

        &encryption.encryption - &secret
    }
}

impl From<SecretKey> for Scalar {
    fn from(secret: SecretKey) -> Scalar {
        secret.0
    }
}

impl Keypair {
    pub fn generate<C>(csprng: &mut C) -> Keypair
    where 
        C: CryptoRng + Rng,
    {
        let secret: SecretKey = SecretKey::generate(csprng);
        let public: PublicKey = PublicKey::from(&secret);

        Keypair{ secret, public }
    }

    pub fn encrypt(&self, message: &Message, nonce: &Ephemeral) -> Encryption
    {
        self.public.encrypt(message, nonce)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn roundtrip() {
        let mut csprng = thread_rng();
        let msg = Message(&RISTRETTO_BASEPOINT_TABLE * &Scalar::random(&mut csprng));
        let keypair = Keypair::generate(&mut csprng);
        let enc = keypair.public.encrypt(&msg, &mut csprng);

        assert!(keypair.secret.decrypt(&enc) == msg.0);
    }
}
