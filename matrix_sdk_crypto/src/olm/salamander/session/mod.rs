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
mod shared_secret;

use x25519_dalek::PublicKey as Curve25591PublicKey;

use chain_key::{ChainKey, RemoteChainKey};
use message_key::MessageKey;
pub(super) use messages::{OlmMessage, PrekeyMessage};
use ratchet::{Ratchet, RatchetPublicKey, RemoteRatchet};

pub(super) use shared_secret::{RemoteShared3DHSecret, Shared3DHSecret};

use self::ratchet::RemoteRatchetKey;

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
    session_keys: Option<SessionKeys>,
    sending_ratchet: Ratchet,
    chain_key: ChainKey,
    receiving_ratchet: Option<RemoteRatchet>,
    receiving_chain_key: Option<RemoteChainKey>,
}

impl Session {
    pub(super) fn new(shared_secret: Shared3DHSecret, session_keys: SessionKeys) -> Self {
        let (root_key, chain_key) = shared_secret.expand();

        let local_ratchet = Ratchet::new(root_key);

        Self {
            session_keys: Some(session_keys),
            sending_ratchet: local_ratchet,
            chain_key,
            receiving_ratchet: None,
            receiving_chain_key: None,
        }
    }

    pub(super) fn new_remote(
        shared_secret: RemoteShared3DHSecret,
        remote_ratchet_key: RemoteRatchetKey,
    ) -> Self {
        let (root_key, remote_chain_key) = shared_secret.expand();

        let (root_key, chain_key, ratchet_key) = root_key.advance(&remote_ratchet_key);
        let local_ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);

        let remote_ratchet = RemoteRatchet::new(remote_ratchet_key);

        Self {
            session_keys: None,
            sending_ratchet: local_ratchet,
            chain_key,
            receiving_ratchet: Some(remote_ratchet),
            receiving_chain_key: Some(remote_chain_key),
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

        if let Some(session_keys) = &self.session_keys {
            PrekeyMessage::from_parts_untyped_prost(
                session_keys.one_time_key.as_bytes().to_vec(),
                session_keys.ephemeral_key.as_bytes().to_vec(),
                session_keys.identity_key.as_bytes().to_vec(),
                message.into_vec(),
            )
            .inner
        } else {
            message.into_vec()
        }
    }

    pub fn decrypt_prekey(&mut self, message: Vec<u8>) -> Vec<u8> {
        let message = PrekeyMessage::from(message);
        let (_, _, _, message) = message.decode().unwrap();

        self.decrypt(message)
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
            self.session_keys = None;

            plaintext
        } else if let Some(ref mut remote_chain_key) = self.receiving_chain_key {
            let message_key = remote_chain_key.create_message_key();
            message_key.decrypt(ciphertext)
        } else {
            todo!()
        }
    }
}
