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

use chain_key::{ChainKey, RemoteChainKey};
use message_key::MessageKey;
use messages::{OlmMessage, PrekeyMessage};
use ratchet::{Ratchet, RatchetPublicKey, RemoteRatchet};
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
    sending_ratchet: Ratchet,
    chain_key: ChainKey,
    receiving_ratchet: Option<RemoteRatchet>,
    receiving_chain_key: Option<RemoteChainKey>,
    established: bool,
}

impl Session {
    pub(super) fn new(session_keys: SessionKeys, shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand_into_sub_keys();

        let ratchet = Ratchet::new(root_key);

        Self {
            session_keys,
            sending_ratchet: ratchet,
            chain_key,
            receiving_ratchet: None,
            receiving_chain_key: None,
            established: false,
        }
    }

    fn ratchet_key(&self) -> RatchetPublicKey {
        RatchetPublicKey::from(self.sending_ratchet.ratchet_key())
    }

    fn create_message_key(&mut self) -> MessageKey {
        self.chain_key.create_message_key(self.ratchet_key())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let message_key = self.create_message_key();
        let message = message_key.encrypt(plaintext);

        if !self.established {
            PrekeyMessage::from_parts_untyped_prost(
                self.session_keys.one_time_key.as_bytes().to_vec(),
                self.session_keys.ephemeral_key.as_bytes().to_vec(),
                self.session_keys.identity_key.as_bytes().to_vec(),
                message.into_vec(),
            )
            .inner
        } else {
            message.into_vec()
        }
    }

    pub fn decrypt(&mut self, message: Vec<u8>) -> Vec<u8> {
        let message = OlmMessage::from(message);
        let (ratchet_key, _index, ciphertext) = message.decode().unwrap();

        // TODO try to use existing message keys.

        if !self
            .receiving_ratchet
            .as_ref()
            .map_or(false, |r| r.belongs_to(&ratchet_key))
        {
            let (sending_ratchet, chain_key, receiving_ratchet, mut receiving_chain_key) =
                self.sending_ratchet.advance(ratchet_key);

            let message_key = receiving_chain_key.create_message_key();

            // TODO don't update the state if the message doesn't decrypt
            let plaintext = message_key.decrypt(ciphertext);

            self.sending_ratchet = sending_ratchet;
            self.chain_key = chain_key;
            self.receiving_ratchet = Some(receiving_ratchet);
            self.receiving_chain_key = Some(receiving_chain_key);
            self.established = true;

            plaintext
        } else if let Some(ref mut remote_chain_key) = self.receiving_chain_key {
            let message_key = remote_chain_key.create_message_key();
            message_key.decrypt(ciphertext)
        } else {
            todo!()
        }
    }
}
