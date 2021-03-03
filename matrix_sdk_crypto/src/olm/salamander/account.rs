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
use rand::thread_rng;
use sha2::Sha256;

use ed25519_dalek::{
    ExpandedSecretKey, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature,
};
use x25519_dalek::{
    EphemeralSecret, PublicKey as Curve25591PublicKey, SharedSecret,
    StaticSecret as Curve25591SecretKey,
};

use dashmap::DashMap;

use super::session::{Session, SessionKeys, RootKey, ChainKey};

struct Shared3DHSecret([u8; 96]);

impl Shared3DHSecret {
    fn new(first: SharedSecret, second: SharedSecret, third: SharedSecret) -> Self {
        let mut secret = [0u8; 96];

        secret[0..32].copy_from_slice(first.as_bytes());
        secret[32..64].copy_from_slice(second.as_bytes());
        secret[64..96].copy_from_slice(third.as_bytes());

        Self(secret)
    }

    fn expand_into_sub_keys(self) -> (RootKey, ChainKey) {
        let hkdf: Hkdf<Sha256> = Hkdf::new(None, &self.0);
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

struct Ed25519Keypair {
    secret_key: Ed25519SecretKey,
    public_key: Ed25519PublicKey,
    encoded_public_key: String,
}

struct Curve25519Keypair {
    secret_key: Curve25591SecretKey,
    public_key: Curve25591PublicKey,
    encoded_public_key: String,
}

struct OneTimeKeys {
    public_keys: DashMap<String, Curve25591PublicKey>,
    private_keys: DashMap<String, Curve25591SecretKey>,
}

impl OneTimeKeys {
    fn mark_as_published(&self) {
        self.public_keys.clear();
    }

    fn generate(&self, count: usize) {}
}

pub struct Account {
    signing_key: Ed25519Keypair,
    diffie_helman_key: Curve25519Keypair,
    one_time_keys: OneTimeKeys,
}

impl Account {
    pub fn new() -> Self {
        todo!()
    }

    pub fn from_pickle() -> Self {
        todo!()
    }

    pub fn from_libolm_pickle() -> Self {
        todo!()
    }

    pub fn pickle() {}

    /// Get a reference to the account's public ed25519 key
    pub fn ed25519_key(&self) -> &Ed25519PublicKey {
        &self.signing_key.public_key
    }

    fn calculate_shared_secret(
        &self,
        identity_key: &Curve25591PublicKey,
        one_time_key: &Curve25591PublicKey,
    ) -> (Shared3DHSecret, Curve25591PublicKey) {
        let rng = thread_rng();

        let ephemeral_key = Curve25591SecretKey::new(rng);
        let public_ephemeral_key = Curve25591PublicKey::from(&ephemeral_key);

        let first_secret = self
            .diffie_helman_key
            .secret_key
            .diffie_hellman(one_time_key);
        let second_secret = ephemeral_key.diffie_hellman(identity_key);
        let third_secret = ephemeral_key.diffie_hellman(one_time_key);

        let shared_secret = Shared3DHSecret::new(first_secret, second_secret, third_secret);

        (shared_secret, public_ephemeral_key)
    }

    pub fn tripple_diffie_hellman(
        &self,
        identity_key: &Curve25591PublicKey,
        one_time_key: Curve25591PublicKey,
    ) -> Session {
        let (shared_secret, ephemeral_key) =
            self.calculate_shared_secret(identity_key, &one_time_key);

        let session_keys = SessionKeys::new(
            self.curve25519_key().clone(),
            ephemeral_key,
            one_time_key,
        );

        let (root_key, chain_key) = shared_secret.expand_into_sub_keys();

        Session::new(session_keys, root_key, chain_key)
    }

    /// Get a reference to the account's public curve25519 key
    pub fn curve25519_key(&self) -> &Curve25591PublicKey {
        &self.diffie_helman_key.public_key
    }

    pub fn generate_one_time_keys(&self, count: usize) {
        self.one_time_keys.generate(count);
    }

    pub fn mark_keys_as_published(&self) {
        self.one_time_keys.mark_as_published();
    }
}
