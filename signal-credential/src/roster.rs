// -*- mode: rust; -*-
//
// This file is part of groupzk.
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Encrypted membership rosters for Signal groups.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

// TODO We're using transmute just for serialising lengths (as u64s) to bytes so
//      that we can pass them to C. This isn't the best, and we could write a little
//      bit twiddly thing to do transmute::<u64, [u8; 8]> and vice versa manually.
#[cfg(feature = "std")]
use std::mem::transmute;
#[cfg(not(feature = "std"))]
use core::intrinsics::transmute;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use errors::RosterError;

use phone_number::SIZEOF_COMMITTED_PHONE_NUMBER;
use phone_number::SIZEOF_PHONE_NUMBER;
use phone_number::CommittedPhoneNumber;
use phone_number::PhoneNumber;

pub const SIZEOF_ROSTER_ENTRY: usize = SIZEOF_COMMITTED_PHONE_NUMBER + 32 + 32;

/// An AES key, used for encrypting and decrypting the commitment openings in a
/// `GroupRosterEntry`.
///
// XXX Fix me, this should be an AES-256 key, but I don't know what type it is
//     without figuring out which AES library to use.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct GroupRosterKey(pub [u8; 32]);

/// A single `SignalUser`'s roster entry in a `GroupMembershipRoster`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RosterEntry {
    pub committed_phone_number: CommittedPhoneNumber,
    /// The following are ciphertexts are required for other group members to
    /// open the above commitment, and they are encrypted symmetrically with an
    /// AES key, which in turn is encrypted to the shared group key.
    pub encrypted_phone_number: [u8; 32],  // XXX What size/type is this ciphertexts?
    pub encrypted_commitment_opening: [u8; 32],
}

impl RosterEntry {
    pub fn from_bytes(bytes: &[u8]) -> Result<RosterEntry, RosterError> {
        const PH: usize = SIZEOF_COMMITTED_PHONE_NUMBER;

        if bytes.len() != SIZEOF_ROSTER_ENTRY {
            return Err(RosterError::RosterEntryWrongSize);
        }

        let committed_phone_number = CommittedPhoneNumber::from_bytes(&bytes[00..PH])?;
        let mut encrypted_phone_number = [0u8; 32];
        let mut encrypted_commitment_opening = [0u8; 32];

        encrypted_phone_number.copy_from_slice(&bytes[PH..PH+32]);
        encrypted_commitment_opening.copy_from_slice(&bytes[PH+32..PH+64]);

        Ok(RosterEntry {
            committed_phone_number,
            encrypted_phone_number,
            encrypted_commitment_opening
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(SIZEOF_ROSTER_ENTRY);

        v.extend(self.committed_phone_number.to_bytes().iter());
        v.extend(self.encrypted_phone_number.iter());
        v.extend(self.encrypted_commitment_opening.iter());

        v
    }
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

    // TODO Decrypt the encrypted_phone_number and the
    //      encrypted_commitment_opening and use them to check the
    //      committed_phone_number.
    pub fn open(&self, _key: &GroupRosterKey) {
        unimplemented!()
    }
}

/// A roster of members and privileges for a Signal group.
///
/// # Note
///
/// The basepoint used in the commitments here must be the system parameter `h`,
/// as used for the `SignalIssuer` and the `SignalUser` types.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct GroupMembershipRoster {
    /// The `key` is an AES key which is encrypted to the shared group key.
    key: GroupRosterKey,
    // XXX Signal must currently have some form of id for group chats,
    //     right? What type is it?
    pub group_id: u64,
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
    pub fn from_bytes(bytes: &[u8]) -> Result<GroupMembershipRoster, RosterError> {
        let mut key_bytes: [u8; 32] = [0u8; 32];

        key_bytes.copy_from_slice(&bytes[00..32]);

        let key = GroupRosterKey(key_bytes);

        let mut tmp: [u8; 8] = [0u8; 8];

        tmp.copy_from_slice(&bytes[32..40]);
        let group_id = unsafe { transmute::<[u8; 8], u64>(tmp) };

        tmp.copy_from_slice(&bytes[40..48]);
        let owners_len = unsafe { transmute::<[u8; 8], u64>(tmp) } as usize;

        let mut owners: Vec<RosterEntry> = Vec::with_capacity(owners_len);
        let owners_offset = 48 + owners_len * SIZEOF_ROSTER_ENTRY;

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in (&bytes[48..owners_offset]).chunks(32) {
            let owner = RosterEntry::from_bytes(chunk)?;

            owners.push(owner);
        }

        tmp.copy_from_slice(&bytes[owners_offset..owners_offset+8]);
        let admins_len = unsafe { transmute::<[u8; 8], u64>(tmp) } as usize;

        let mut admins: Vec<RosterEntry> = Vec::with_capacity(admins_len);
        let admins_offset = owners_offset + 8 + admins_len * SIZEOF_ROSTER_ENTRY;

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in (&bytes[owners_offset+8..admins_offset]).chunks(32) {
            let admin = RosterEntry::from_bytes(chunk)?;

            admins.push(admin);
        }

        tmp.copy_from_slice(&bytes[admins_offset..admins_offset+8]);
        let users_len = unsafe { transmute::<[u8; 8], u64>(tmp) } as usize;

        let mut users: Vec<RosterEntry> = Vec::with_capacity(users_len);
        let users_offset = admins_offset + 8 + users_len * SIZEOF_ROSTER_ENTRY;

        // TODO When #![feature(chunk_exact)] stabilises we should use that instead
        for chunk in (&bytes[admins_offset+8..users_offset]).chunks(32) {
            let user = RosterEntry::from_bytes(chunk)?;

            users.push(user);
        }

        Ok(GroupMembershipRoster {
            key,
            group_id,
            owners,
            admins,
            users,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(32 + 8 + SIZEOF_ROSTER_ENTRY *
                                                (self.owners.len() + self.admins.len() + self.users.len()));

        v.extend(self.key.0.iter());
        v.extend(unsafe { transmute::<u64, [u8; 8]>(self.group_id) }.iter());
        v.extend(unsafe { transmute::<u64, [u8; 8]>(self.owners.len() as u64) }.iter());

        for member in self.owners.iter() {
            v.extend(member.to_bytes());
        }

        v.extend(unsafe { transmute::<u64, [u8; 8]>(self.admins.len() as u64) }.iter());

        for member in self.admins.iter() {
            v.extend(member.to_bytes());
        }

        v.extend(unsafe { transmute::<u64, [u8; 8]>(self.users.len() as u64) }.iter());

        for member in self.users.iter() {
            v.extend(member.to_bytes());
        }

        v
    }
}

impl GroupMembershipRoster {
    pub fn new(group_id: usize, owner: RosterEntry, key: GroupRosterKey) -> GroupMembershipRoster {
        let mut roster = GroupMembershipRoster {
            key: key,
            group_id: group_id as u64,
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

