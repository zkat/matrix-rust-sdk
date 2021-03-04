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

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

use ed25519_dalek::{
    ExpandedSecretKey, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature,
};
use x25519_dalek::{
    EphemeralSecret, PublicKey as Curve25591PublicKey, SharedSecret,
    StaticSecret as Curve25591SecretKey,
};

use dashmap::DashMap;

use crate::utilities::{decode, encode};

use super::messages::{OlmMessage, PrekeyMessage};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct RatchetKey(Curve25591SecretKey);
pub(super) struct RatchetPublicKey(Curve25591PublicKey);

impl RatchetKey {
    fn new() -> Self {
        let rng = thread_rng();
        Self(Curve25591SecretKey::new(rng))
    }
}

impl RatchetPublicKey {
    pub fn base64_encode(&self) -> String {
        encode(self.0.as_bytes())
    }
}

impl From<&RatchetKey> for RatchetPublicKey {
    fn from(r: &RatchetKey) -> Self {
        RatchetPublicKey(Curve25591PublicKey::from(&r.0))
    }
}

pub(super) struct RootKey([u8; 32]);

impl RootKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn advance(&mut self) {
        todo!()
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
        mac.update(b"\x02");

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

impl MessageKey {
    fn encrypt(self, plaintext: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let hkdf: Hkdf<Sha256> = Hkdf::new(None, &self.key);

        // TODO zeroize this.
        let mut aes_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        let mut iv = [0u8; 16];

        // TODO zeroize this.
        let mut expanded_keys = [0u8; 80];

        hkdf.expand(b"OLM_KEYS", &mut expanded_keys).unwrap();

        aes_key.copy_from_slice(&expanded_keys[0..32]);
        hmac_key.copy_from_slice(&expanded_keys[32..64]);
        iv.copy_from_slice(&expanded_keys[64..80]);

        let cipher = Aes256Cbc::new_var(&aes_key, &iv).unwrap();

        let ciphertext = cipher.encrypt_vec(&plaintext);

        (ciphertext, hmac_key)
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
    ratchet_key: RatchetKey,
    root_key: RootKey,
    chain_key: ChainKey,
    established: bool,
}

impl Session {
    pub(super) fn new(session_keys: SessionKeys, root_key: RootKey, chain_key: ChainKey) -> Self {
        let ratchet_key = RatchetKey::new();

        Self {
            ratchet_key,
            session_keys,
            root_key,
            chain_key,
            established: false,
        }
    }

    fn construct_message(&self, ciphertext: Vec<u8>) -> OlmMessage {
        let ratchet_key = RatchetPublicKey::from(&self.ratchet_key);
        let chain_index = self.chain_key.index;

        OlmMessage::from_parts(ratchet_key, chain_index, &ciphertext)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let message_key = self.chain_key.create_message_key();
        let (ciphertext, hmac_key) = message_key.encrypt(plaintext);

        let message = self.construct_message(ciphertext);

        println!("HELLO");
        // let hmac_key = GenericArray::from_slice(&hmac_key);
        let mut hmac = Hmac::<Sha256>::new_varkey(&hmac_key).unwrap();
        println!("HELLO");
        hmac.update(message.as_bytes());

        let mac = hmac.finalize().into_bytes();

        let message = [message.as_bytes(), &mac.as_slice()[0..8]].concat();

        PrekeyMessage::from_parts_untyped(
            self.session_keys.one_time_key.as_bytes(),
            self.session_keys.ephemeral_key.as_bytes(),
            self.session_keys.identity_key.as_bytes(),
            message.as_slice(),
        )
        .inner
    }
}
