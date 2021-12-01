use std::collections::BTreeMap;

use ruma::{serde::Raw, DeviceKeyId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::{value::to_raw_value, Value};

/// Signatures for a `SignedKey` object.
pub type SignedKeySignatures = BTreeMap<Box<UserId>, BTreeMap<Box<DeviceKeyId>, String>>;

/// A key for the SignedCurve25519 algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedKey {
    /// Base64-encoded 32-byte Curve25519 public key.
    key: String,

    /// Signatures for the key object.
    signatures: SignedKeySignatures,

    /// Is the key considered to be a fallback key.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "double_option")]
    fallback: Option<Option<bool>>,

    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}

fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

impl SignedKey {
    /// Creates a new `SignedKey` with the given key and signatures.
    pub fn new(key: String, signatures: SignedKeySignatures) -> Self {
        Self { key, signatures, fallback: None, other: BTreeMap::new() }
    }

    /// Creates a new `SignedKey`, that represents a fallback key, with the
    /// given key and signatures.
    pub fn new_fallback(key: String, signatures: SignedKeySignatures) -> Self {
        Self { key, signatures, fallback: Some(Some(true)), other: BTreeMap::new() }
    }

    /// Base64-encoded 32-byte Curve25519 public key.
    pub fn key(&self) -> &str {
        &self.key
    }

    // /// Signatures for the key object.
    // pub fn signatures(&self) -> &SignedKeySignatures {
    //     &self.signatures
    // }

    // /// Is the key considered to be a fallback key.
    // pub fn fallback(&self) -> bool {
    //     self.fallback.map(|f| f.unwrap_or_default()).unwrap_or_default()
    // }

    pub fn to_raw(self) -> Raw<ruma::encryption::OneTimeKey> {
        let key = OneTimeKey::SignedKey(self);
        Raw::from_json(to_raw_value(&key).expect("Coulnd't serialize one-time key"))
    }
}

/// A one-time public key for "pre-key" messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneTimeKey {
    /// A key containing signatures, for the SignedCurve25519 algorithm.
    SignedKey(SignedKey),

    /// A string-valued key, for the Ed25519 and Curve25519 algorithms.
    Key(String),

    /// An unknown one-time key type.
    Other(Value),
}
