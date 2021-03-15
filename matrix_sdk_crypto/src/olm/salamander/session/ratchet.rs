use rand::thread_rng;

use x25519_dalek::{
    PublicKey as Curve25591PublicKey, SharedSecret, StaticSecret as Curve25591SecretKey,
};

use super::{chain_key::ChainKey, root_key::RootKey};

pub(super) struct RatchetKey(Curve25591SecretKey);

#[derive(Debug)]
pub(super) struct RatchetPublicKey(Curve25591PublicKey);

impl RatchetKey {
    pub fn new() -> Self {
        let rng = thread_rng();
        Self(Curve25591SecretKey::new(rng))
    }

    pub fn diffie_hellman(&self, other: &RatchetPublicKey) -> SharedSecret {
        self.0.diffie_hellman(&other.0)
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

pub(super) struct Ratchet {
    root_key: RootKey,
    ratchet_key: RatchetKey,
}

impl Ratchet {
    pub fn new(root_key: RootKey) -> Self {
        let ratchet_key = RatchetKey::new();

        Self {
            root_key,
            ratchet_key,
        }
    }

    pub fn advance(&mut self, other_ratchet_key: RatchetPublicKey) -> ChainKey {
        let (root_key, chain_key) = self.root_key.advance(&self.ratchet_key, other_ratchet_key);
        self.root_key = root_key;

        chain_key
    }

    pub fn ratchet_key(&self) -> &RatchetKey {
        &self.ratchet_key
    }
}
