use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    root_key::{RemoteRootKey, RootKey},
};

pub(crate) struct Shared3DHSecret([u8; 96]);
pub(crate) struct RemoteShared3DHSecret([u8; 96]);

fn expand(shared_secret: [u8; 96]) -> ([u8; 32], [u8; 32]) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), &shared_secret);
    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];

    // TODO zeroize this.
    let mut expanded_keys = [0u8; 64];

    hkdf.expand(b"OLM_ROOT", &mut expanded_keys).unwrap();

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    (root_key, chain_key)
}

impl RemoteShared3DHSecret {
    pub fn new(first: SharedSecret, second: SharedSecret, third: SharedSecret) -> Self {
        let mut secret = Self([0u8; 96]);

        secret.0[0..32].copy_from_slice(first.as_bytes());
        secret.0[32..64].copy_from_slice(second.as_bytes());
        secret.0[64..96].copy_from_slice(third.as_bytes());

        secret
    }

    pub(super) fn expand(self) -> (RemoteRootKey, RemoteChainKey) {
        let (root_key, chain_key) = expand(self.0);
        let root_key = RemoteRootKey::new(root_key);
        let chain_key = RemoteChainKey::new(chain_key);

        (root_key, chain_key)
    }
}

impl Shared3DHSecret {
    pub fn new(first: SharedSecret, second: SharedSecret, third: SharedSecret) -> Self {
        let mut secret = Self([0u8; 96]);

        secret.0[0..32].copy_from_slice(first.as_bytes());
        secret.0[32..64].copy_from_slice(second.as_bytes());
        secret.0[64..96].copy_from_slice(third.as_bytes());

        secret
    }

    pub(super) fn expand(self) -> (RootKey, ChainKey) {
        let (root_key, chain_key) = expand(self.0);

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        (root_key, chain_key)
    }
}
