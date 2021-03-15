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

mod chain_key;
mod message_key;
mod messages;
mod ratchet;
mod root_key;

use hkdf::Hkdf;
use sha2::Sha256;

use x25519_dalek::{PublicKey as Curve25591PublicKey, SharedSecret};

use chain_key::ChainKey;
use message_key::MessageKey;
use messages::{OlmMessage, PrekeyMessage};
use ratchet::{Ratchet, RatchetKey, RatchetPublicKey};
use root_key::RootKey;

pub(super) struct Shared3DHSecret([u8; 96]);

impl Shared3DHSecret {
    pub fn new(first: SharedSecret, second: SharedSecret, third: SharedSecret) -> Self {
        let mut secret = Self([0u8; 96]);

        secret.0[0..32].copy_from_slice(first.as_bytes());
        secret.0[32..64].copy_from_slice(second.as_bytes());
        secret.0[64..96].copy_from_slice(third.as_bytes());

        secret
    }

    fn expand_into_sub_keys(self) -> (RootKey, ChainKey) {
        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), &self.0);
        let mut root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];

        // TODO zeroize this.
        let mut expanded_keys = [0u8; 64];

        hkdf.expand(b"OLM_ROOT", &mut expanded_keys).unwrap();

        root_key.copy_from_slice(&expanded_keys[0..32]);
        chain_key.copy_from_slice(&expanded_keys[32..64]);

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        (root_key, chain_key)
    }
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
    ratchet: Ratchet,
    chain_key: ChainKey,
    established: bool,
}

impl Session {
    pub(super) fn new(session_keys: SessionKeys, shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand_into_sub_keys();

        let ratchet = Ratchet::new(root_key);

        Self {
            ratchet,
            session_keys,
            chain_key,
            established: false,
        }
    }

    fn ratchet_key(&self) -> RatchetPublicKey {
        RatchetPublicKey::from(self.ratchet.ratchet_key())
    }

    fn create_message_key(&mut self) -> MessageKey {
        self.chain_key.create_message_key(self.ratchet_key())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let message_key = self.create_message_key();
        let message = message_key.encrypt(plaintext);

        PrekeyMessage::from_parts_untyped_prost(
            self.session_keys.one_time_key.as_bytes().to_vec(),
            self.session_keys.ephemeral_key.as_bytes().to_vec(),
            self.session_keys.identity_key.as_bytes().to_vec(),
            message.to_vec(),
        )
        .inner
    }

    pub fn decrypt(&mut self, message: Vec<u8>) -> Vec<u8> {
        let message = OlmMessage::from(message);
        let (ratchet_key, index, ciphertext) = message.decode().unwrap();

        println!("{:?} {:?}", ratchet_key, index);

        let mut chain_key = self.ratchet.advance(ratchet_key);
        let ratchet_key = RatchetKey::new();

        let message_key = chain_key.create_message_key(RatchetPublicKey::from(&ratchet_key));

        message_key.decrypt(ciphertext)
    }
}
