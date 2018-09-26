// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Encrypted membership rosters for Signal groups.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use errors::RosterError;

use phone_number::CommittedPhoneNumber;
use phone_number::PhoneNumber;

/// An AES key, used for encrypting and decrypting the commitment openings in a
/// `GroupRosterEntry`.
///
// XXX Fix me, this should be an AES-256 key, but I don't know what type it is
//     without figuring out which AES library to use.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct GroupRosterKey(pub [u8; 32]);

/// A single `SignalUser`'s roster entry in a `GroupMembershipRoster`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RosterEntry {
    pub committed_phone_number: CommittedPhoneNumber,
    /// The following are ciphertexts are required for other group members to
    /// open the above commitment, and they are encrypted symmetrically with an
    /// AES key, which in turn is encrypted to the shared group key.
    pub encrypted_phone_number: [u8; 32],  // XXX What size/type is this ciphertexts?
    pub encrypted_commitment_opening: [u8; 32],
}

impl RosterEntry {
    pub fn new(
        committed_phone_number: &CommittedPhoneNumber,
        phone_number: &PhoneNumber,
        nonce: &Scalar,
        _key: &GroupRosterKey,
    ) -> RosterEntry
    {
        // XXX Actually encrypt these with an AES key encrypted to the group key.
        let encrypted_phone_number: [u8; 32] = phone_number.0.to_bytes();
        let encrypted_commitment_opening: [u8; 32] = nonce.to_bytes();

        RosterEntry {
            committed_phone_number: committed_phone_number.clone(),
            encrypted_phone_number: encrypted_phone_number,
            encrypted_commitment_opening: encrypted_commitment_opening,
        }
    }

    pub fn open(&self, _key: &GroupRosterKey) {
        unimplemented!()
    }
}

/// A roster of members and privileges for a signal Signal group.
///
/// # Note
///
/// The basepoint used in the commitments here must be the system parameter `h`,
/// as used for the `SignalIssuer` and the `SignalUser` types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMembershipRoster {
    /// The `key` is an AES key which is encrypted to the shared group key.
    key: GroupRosterKey,
    // XXX Signal must currently have some form of id for group chats,
    //     right? What type is it?
    pub group_id: usize,
    pub owners: Vec<RosterEntry>,
    pub admins: Vec<RosterEntry>,
    pub users: Vec<RosterEntry>,
}

pub enum GroupMembershipLevel {
    Owner,
    Admin,
    User,
}

impl GroupMembershipRoster {
    pub fn new(group_id: usize, owner: RosterEntry, key: GroupRosterKey) -> GroupMembershipRoster {
        let mut roster = GroupMembershipRoster {
            key: key,
            group_id: group_id,
            owners: Vec::with_capacity(1),
            admins: Vec::with_capacity(1),
            users: Vec::with_capacity(1),
        };

        roster.add_owner(owner);
        roster
    }

    pub fn add_owner(&mut self, owner: RosterEntry) {
        self.owners.push(owner);
    }

    pub fn add_admin(&mut self, admin: RosterEntry) {
        self.admins.push(admin);
    }

    pub fn add_user(&mut self, user: RosterEntry) {
        self.users.push(user);
    }
}
