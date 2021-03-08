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

use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::thread_rng;
use sha2::Sha256;
use zeroize::Zeroize;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

use x25519_dalek::{PublicKey as Curve25591PublicKey, StaticSecret as Curve25591SecretKey};

use super::messages::{OlmMessage, PrekeyMessage};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct RatchetKey(Curve25591SecretKey);
pub(super) struct RatchetPublicKey(Curve25591PublicKey);

struct Aes256Key([u8; 32]);
struct Aes256IV([u8; 16]);
struct HmacSha256Key([u8; 32]);

impl Aes256Key {
    fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl HmacSha256Key {
    fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Aes256IV {
    fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

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

        hkdf.expand(Self::ADVANCEMENT_SEED, &mut output).expect("Can't expand");

        let mut chain_key = ChainKey::new([0u8; 32]);
        let mut root_key = RootKey([0u8; 32]);

        root_key.0.copy_from_slice(&output[..32]);
        chain_key.key.copy_from_slice(&output[32..]);

        (root_key, chain_key)
    }
}

pub(super) struct ChainKey {
    key: [u8; 32],
    index: u64,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: &'static [u8; 1] = b"\x01";
    const ADVANCEMENT_SEED: &'static [u8; 1] = b"\x02";

    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self {
            key: bytes,
            index: 0,
        }
    }

    fn advance(&mut self) {
        let mut mac = Hmac::<Sha256>::new_varkey(&self.key).unwrap();
        mac.update(Self::ADVANCEMENT_SEED);

        let output = mac.finalize().into_bytes();
        self.key.copy_from_slice(output.as_slice());
        self.index += 1;
    }

    fn create_message_key(&mut self, ratchet_key: RatchetPublicKey) -> MessageKey {
        let mut mac = Hmac::<Sha256>::new_varkey(&self.key).unwrap();
        mac.update(Self::MESSAGE_KEY_SEED);

        let output = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        key.copy_from_slice(output.as_slice());

        let message_key = MessageKey {
            key,
            ratchet_key,
            index: self.index,
        };

        self.advance();

        message_key
    }
}

struct MessageKey {
    key: [u8; 32],
    ratchet_key: RatchetPublicKey,
    index: u64,
}

impl MessageKey {
    fn construct_message(&self, ciphertext: Vec<u8>) -> OlmMessage {
        OlmMessage::from_parts(&self.ratchet_key, self.index, &ciphertext)
    }

    fn expand_keys(&self) -> (Aes256Key, HmacSha256Key, Aes256IV) {
        #[derive(Clone, Zeroize)]
        struct ExpandedKeys([u8; 80]);

        impl Drop for ExpandedKeys {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl ExpandedKeys {
            const HMAC_INFO: &'static [u8] = b"OLM_KEYS";

            fn new(message_key: &MessageKey) -> Self {
                let mut expanded_keys = [0u8; 80];
                let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), &message_key.key);
                hkdf.expand(Self::HMAC_INFO, &mut expanded_keys).unwrap();

                Self(expanded_keys)
            }

            fn split(self) -> (Aes256Key, HmacSha256Key, Aes256IV) {
                let mut aes_key = Aes256Key([0u8; 32]);
                let mut hmac_key = HmacSha256Key([0u8; 32]);
                let mut iv = Aes256IV([0u8; 16]);

                aes_key.0.copy_from_slice(&self.0[0..32]);
                hmac_key.0.copy_from_slice(&self.0[32..64]);
                iv.0.copy_from_slice(&self.0[64..80]);

                (aes_key, hmac_key, iv)
            }
        }

        let expanded_keys = ExpandedKeys::new(&self);
        expanded_keys.split()
    }

    fn encrypt(self, plaintext: &[u8]) -> OlmMessage {
        let (aes_key, hmac_key, iv) = self.expand_keys();

        let cipher = Aes256Cbc::new_var(&aes_key.to_bytes(), &iv.to_bytes()).unwrap();

        let ciphertext = cipher.encrypt_vec(&plaintext);
        let mut message = self.construct_message(ciphertext);

        let mut hmac = Hmac::<Sha256>::new_varkey(&hmac_key.to_bytes()).unwrap();
        hmac.update(message.as_payload_bytes());

        let mac = hmac.finalize().into_bytes();
        message.append_mac(&mac);

        message
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
    pub(super) fn new(session_keys: SessionKeys, root_key: RootKey, chain_key: ChainKey) -> Self {
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

        PrekeyMessage::from_parts_untyped(
            self.session_keys.one_time_key.as_bytes(),
            self.session_keys.ephemeral_key.as_bytes(),
            self.session_keys.identity_key.as_bytes(),
            message.as_bytes(),
        )
        .inner
    }

    pub fn decrypt(&mut self, message: OlmMessage) {
        let (ratchet_key, _, _) = message.decode().unwrap();

        let _ = self.ratchet.advance(ratchet_key);
    }
}
