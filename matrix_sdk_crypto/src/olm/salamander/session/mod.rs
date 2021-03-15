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

use hkdf::Hkdf;
use rand::thread_rng;
use sha2::Sha256;

use x25519_dalek::{
    PublicKey as Curve25591PublicKey, SharedSecret, StaticSecret as Curve25591SecretKey,
};

use chain_key::ChainKey;
use message_key::MessageKey;
use messages::{OlmMessage, PrekeyMessage};

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

struct RatchetKey(Curve25591SecretKey);

#[derive(Debug)]
pub(super) struct RatchetPublicKey(Curve25591PublicKey);

impl RatchetKey {
    fn new() -> Self {
        let rng = thread_rng();
        Self(Curve25591SecretKey::new(rng))
    }
}

impl RatchetPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl From<[u8; 32]> for RatchetPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        RatchetPublicKey(Curve25591PublicKey::from(bytes))
    }
}

impl From<&RatchetKey> for RatchetPublicKey {
    fn from(r: &RatchetKey) -> Self {
        RatchetPublicKey(Curve25591PublicKey::from(&r.0))
    }
}

struct Ratchet {
    root_key: RootKey,
    ratchet_key: RatchetKey,
}

impl Ratchet {
    fn advance(&mut self, other_ratchet_key: RatchetPublicKey) -> ChainKey {
        let (root_key, chain_key) = self.root_key.advance(&self.ratchet_key, other_ratchet_key);
        self.root_key = root_key;

        chain_key
    }
}

pub(super) struct RootKey([u8; 32]);

impl RootKey {
    const ADVANCEMENT_SEED: &'static [u8; 11] = b"OLM_RATCHET";

    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn advance(
        &self,
        old_ratchet_key: &RatchetKey,
        other_ratchet_key: RatchetPublicKey,
    ) -> (RootKey, ChainKey) {
        let shared_secret = old_ratchet_key.0.diffie_hellman(&other_ratchet_key.0);
        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(self.0.as_ref()), shared_secret.as_bytes());
        let mut output = [0u8; 64];

        hkdf.expand(Self::ADVANCEMENT_SEED, &mut output)
            .expect("Can't expand");

        let mut chain_key = ChainKey::new([0u8; 32]);
        let mut root_key = RootKey([0u8; 32]);

        root_key.0.copy_from_slice(&output[..32]);
        chain_key.fill(&output[32..]);

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

        let ratchet = Ratchet {
            root_key,
            ratchet_key: RatchetKey::new(),
        };

        Self {
            ratchet,
            session_keys,
            chain_key,
            established: false,
        }
    }

    fn ratchet_key(&self) -> RatchetPublicKey {
        RatchetPublicKey::from(&self.ratchet.ratchet_key)
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
