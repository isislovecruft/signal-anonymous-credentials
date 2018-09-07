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
pub struct Message(pub(crate) RistrettoPoint);

/// ElGamal cryptosystems in the elliptic curve context require a canonical,
/// invertible, isomorphic mapping from messages as scalars to messages as group
/// elements.  Several such constructions are given in "Elliptic Curve
/// Cryptosystems" (1987) by Neal Koblitz.
///
/// One construction is, given an arbitrary `\ell` and an `n` s.t. `n = 2n'` is
/// even, and plaintexts as scalars mod `\ell^{n'}`, to encode the scalar as a
/// polynomial `m = m_0 p + m_1 p + … + m_{n'-1} p^{n'-1}, 0 ≤ m_j < p`.  We
/// then choose a convenient vector space basis of `GF(\ell^{n'})` over
/// `GF(\ell)` as `b_0, …,b_{n'-1}` and set the affine point coordinates as
///
///    x(m) = m_0 b_0 + m_1 b_1 + … m_{n'-1} b_{n'-1}
///    y(m) = sqrt(x^3 + ax + b)
///
/// Instead, to avoid the choice of efficient vector basis we assume an
/// order-of-magnitude limitation on `m`, which allows us to increase the order
/// of magnitude until a solution for `x` in the to the curve equation is found.
impl<'a> From<&'a Scalar> for Message {
    fn from(source: &'a Scalar) -> Message {
        let _bytes: [u8; 32] = source.to_bytes();

        unimplemented!()
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
