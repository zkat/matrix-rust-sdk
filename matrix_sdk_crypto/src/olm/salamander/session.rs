// Copyright 2021 Damir Jelić
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code)]

use hkdf::Hkdf;
use hmac::{crypto_mac::MacError, Hmac, Mac, NewMac};
use rand::{thread_rng, RngCore};
use sha2::Sha256;

use ed25519_dalek::{
    ExpandedSecretKey, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature,
};
use x25519_dalek::{
    EphemeralSecret, PublicKey as Curve25591PublicKey, SharedSecret,
    StaticSecret as Curve25591SecretKey,
};

use dashmap::DashMap;

struct RatchetKey([u8; 32]);

impl RatchetKey {
    fn new() -> Self {
        let mut rng = thread_rng();
        let mut key = Self([0u8; 32]);
        rng.fill_bytes(&mut key.0);

        key
    }
}

pub(super) struct RootKey([u8; 32]);

impl RootKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

pub(super) struct ChainKey {
    key: [u8; 32],
    index: u64,
}

impl ChainKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self {
            key: bytes,
            index: 0,
        }
    }

    fn advance(&mut self) {
        let mut mac = Hmac::<Sha256>::new_varkey(&self.key).unwrap();
        mac.update(b"\x01");

        let output = mac.finalize().into_bytes();
        self.key.copy_from_slice(output.as_slice());
        self.index = self.index + 1;
    }

    fn create_message_key(&mut self) -> MessageKey {
        let mut mac = Hmac::<Sha256>::new_varkey(&self.key).unwrap();
        mac.update(b"\x01");

        let output = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        key.copy_from_slice(output.as_slice());

        let message_key = MessageKey {
            key,
            index: self.index,
        };

        self.advance();

        message_key
    }
}

struct MessageKey {
    key: [u8; 32],
    index: u64,
}

pub(super) struct SessionKeys {
    identity_key: Curve25591PublicKey,
    ephemeral_key: Curve25591PublicKey,
    one_time_key: Curve25591PublicKey,
}

impl SessionKeys {
    pub(super) fn new(
        identity_key: Curve25591PublicKey,
        ephemeral_key: Curve25591PublicKey,
        one_time_key: Curve25591PublicKey,
    ) -> Self {
        Self {
            identity_key,
            ephemeral_key,
            one_time_key,
        }
    }
}

pub struct Session {
    session_keys: SessionKeys,
    ratchet_key: RatchetKey,
    root_key: RootKey,
    chain_key: ChainKey,
}

impl Session {
    pub(super) fn new(session_keys: SessionKeys, root_key: RootKey, chain_key: ChainKey) -> Self {
        let ratchet_key = RatchetKey::new();

        Self {
            ratchet_key,
            session_keys,
            root_key,
            chain_key,
        }
    }
}
