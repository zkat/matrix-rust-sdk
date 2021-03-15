use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

use super::{ratchet::RatchetPublicKey, MessageKey};

pub(super) struct ChainKey {
    key: [u8; 32],
    index: u64,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: &'static [u8; 1] = b"\x01";
    const ADVANCEMENT_SEED: &'static [u8; 1] = b"\x02";

    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            key: bytes,
            index: 0,
        }
    }

    pub fn fill(&mut self, key: &[u8]) {
        self.key.copy_from_slice(&key);
    }

    fn advance(&mut self) {
        let mut mac = Hmac::<Sha256>::new_varkey(&self.key).unwrap();
        mac.update(Self::ADVANCEMENT_SEED);

        let output = mac.finalize().into_bytes();
        self.key.copy_from_slice(output.as_slice());
        self.index += 1;
    }

    pub fn create_message_key(&mut self, ratchet_key: RatchetPublicKey) -> MessageKey {
        let mut mac = Hmac::<Sha256>::new_varkey(&self.key).unwrap();
        mac.update(Self::MESSAGE_KEY_SEED);

        let output = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        key.copy_from_slice(output.as_slice());

        let message_key = MessageKey::new(key, ratchet_key, self.index);

        self.advance();

        message_key
    }
}
