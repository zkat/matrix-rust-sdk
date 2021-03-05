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
use rand::thread_rng;
use sha2::Sha256;

use ed25519_dalek::{Keypair, PublicKey as Ed25519PublicKey};
use x25519_dalek::{
    PublicKey as Curve25591PublicKey, SharedSecret, StaticSecret as Curve25591SecretKey,
};

use dashmap::DashMap;

use crate::utilities::encode;

use super::session::{ChainKey, RootKey, Session, SessionKeys};

struct Shared3DHSecret([u8; 96]);

impl Shared3DHSecret {
    fn new(first: SharedSecret, second: SharedSecret, third: SharedSecret) -> Self {
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

struct Ed25519Keypair {
    inner: Keypair,
    encoded_public_key: String,
}

impl Ed25519Keypair {
    fn new() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let encoded_public_key = encode(keypair.public.as_bytes());

        Self {
            inner: keypair,
            encoded_public_key,
        }
    }
}

struct Curve25519Keypair {
    secret_key: Curve25591SecretKey,
    public_key: Curve25591PublicKey,
    encoded_public_key: String,
}

impl Curve25519Keypair {
    fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = Curve25591SecretKey::new(&mut rng);
        let public_key = Curve25591PublicKey::from(&secret_key);
        let encoded_public_key = encode(public_key.as_bytes());

        Self {
            secret_key,
            public_key,
            encoded_public_key,
        }
    }
}

struct OneTimeKeys {
    public_keys: DashMap<String, Curve25591PublicKey>,
    private_keys: DashMap<String, Curve25591SecretKey>,
}

impl OneTimeKeys {
    fn new() -> Self {
        Self {
            public_keys: DashMap::new(),
            private_keys: DashMap::new(),
        }
    }

    fn mark_as_published(&self) {
        self.public_keys.clear();
    }

    fn generate(&self, _: usize) {
        todo!()
    }
}

pub struct Account {
    signing_key: Ed25519Keypair,
    diffie_helman_key: Curve25519Keypair,
    one_time_keys: OneTimeKeys,
}

impl Account {
    pub fn new() -> Self {
        Self {
            signing_key: Ed25519Keypair::new(),
            diffie_helman_key: Curve25519Keypair::new(),
            one_time_keys: OneTimeKeys::new(),
        }
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
        &self.signing_key.inner.public
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

        let session_keys =
            SessionKeys::new(self.curve25519_key().clone(), ephemeral_key, one_time_key);

        let (root_key, chain_key) = shared_secret.expand_into_sub_keys();

        Session::new(session_keys, root_key, chain_key)
    }

    /// Get a reference to the account's public curve25519 key
    pub fn curve25519_key(&self) -> &Curve25591PublicKey {
        &self.diffie_helman_key.public_key
    }

    /// Get a reference to the account's public curve25519 key as an unpadded
    /// base64 encoded string.
    pub fn curve25519_key_encoded(&self) -> &str {
        &self.diffie_helman_key.encoded_public_key
    }

    pub fn generate_one_time_keys(&self, count: usize) {
        self.one_time_keys.generate(count);
    }

    pub fn mark_keys_as_published(&self) {
        self.one_time_keys.mark_as_published();
    }
}

#[cfg(test)]
mod test {
    use super::{Account, Curve25591PublicKey};
    use crate::utilities::{decode, encode};
    use olm_rs::{account::OlmAccount, session::OlmMessage};

    #[test]
    fn test_encryption() {
        let alice = Account::new();
        let bob = OlmAccount::new();

        bob.generate_one_time_keys(1);

        let one_time_key = bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .cloned()
            .next()
            .unwrap();

        let one_time_key_raw = decode(one_time_key).unwrap();
        let mut one_time_key = [0u8; 32];
        one_time_key.copy_from_slice(&one_time_key_raw);

        let identity_key_raw = decode(bob.parsed_identity_keys().curve25519()).unwrap();
        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&identity_key_raw);

        let one_time_key = Curve25591PublicKey::from(one_time_key);
        let identity_key = Curve25591PublicKey::from(identity_key);

        let mut alice_session = alice.tripple_diffie_hellman(&identity_key, one_time_key);

        let message = "It's a secret to everybody";

        let olm_message = alice_session.encrypt(message.as_bytes());
        let olm_message = encode(olm_message);
        let olm_message = OlmMessage::from_type_and_ciphertext(0, olm_message).unwrap();
        bob.mark_keys_as_published();

        if let OlmMessage::PreKey(m) = olm_message.clone() {
            let session = bob
                .create_inbound_session_from(alice.curve25519_key_encoded(), m)
                .expect("Can't create an Olm session");
            let plaintext = session
                .decrypt(olm_message)
                .expect("Can't decrypt ciphertext");
            assert_eq!(message, plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(&second_text.as_bytes());
            let olm_message = encode(olm_message);
            let olm_message = OlmMessage::from_type_and_ciphertext(0, olm_message).unwrap();

            let plaintext = session
                .decrypt(olm_message)
                .expect("Can't decrypt second ciphertext");
            assert_eq!(second_text, plaintext);
        } else {
            unreachable!();
        }
    }
}
