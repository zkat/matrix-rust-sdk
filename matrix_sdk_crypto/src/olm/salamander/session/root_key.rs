use hkdf::Hkdf;
use sha2::Sha256;

use super::{
    chain_key::ChainKey,
    ratchet::{RatchetKey, RemoteRatchetKey},
};

pub(super) struct RootKey([u8; 32]);

impl RootKey {
    const ADVANCEMENT_SEED: &'static [u8; 11] = b"OLM_RATCHET";

    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn advance(
        &self,
        old_ratchet_key: &RatchetKey,
        other_ratchet_key: RemoteRatchetKey,
    ) -> (RootKey, ChainKey) {
        let shared_secret = old_ratchet_key.diffie_hellman(&other_ratchet_key);
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
