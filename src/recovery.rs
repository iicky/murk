use bech32::{FromBase32, ToBase32, Variant};

/// Errors that can occur during recovery phrase operations.
#[derive(Debug)]
pub enum RecoveryError {
    Bip39(String),
    InvalidKey(String),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::Bip39(msg) => write!(f, "BIP39 error: {msg}"),
            RecoveryError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
        }
    }
}

/// The Bech32 human-readable prefix for age secret keys.
/// age uses lowercase internally, then uppercases the full string for display.
const AGE_SECRET_KEY_HRP: &str = "age-secret-key-";

/// Generate a new age keypair and return the BIP39 24-word mnemonic,
/// secret key string, and public key string.
///
/// 24 BIP39 words encode 256 bits (32 bytes) — exactly the size of an
/// age x25519 secret key. The mnemonic is a direct encoding of the key
/// bytes with no derivation step. Same words, same key, always.
pub fn generate() -> Result<(String, String, String), RecoveryError> {
    let entropy: [u8; 32] = rand::random();
    let mnemonic =
        bip39::Mnemonic::from_entropy(&entropy).map_err(|e| RecoveryError::Bip39(e.to_string()))?;

    let secret_key = bytes_to_age_key(&entropy)?;

    let identity = crate::crypto::parse_identity(&secret_key)
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;
    let pubkey = identity.to_public().to_string();

    Ok((mnemonic.to_string(), secret_key, pubkey))
}

/// Re-derive the BIP39 24-word mnemonic from an existing MURK_KEY.
/// Decodes the Bech32 key back to raw bytes, then encodes as a mnemonic.
pub fn phrase_from_key(secret_key: &str) -> Result<String, RecoveryError> {
    // age keys are uppercase; bech32 decoding requires lowercase.
    let lowercase = secret_key.to_lowercase();
    let (_, data, _) =
        bech32::decode(&lowercase).map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;
    let key_bytes = Vec::<u8>::from_base32(&data)
        .map_err(|e: bech32::Error| RecoveryError::InvalidKey(e.to_string()))?;
    let mnemonic = bip39::Mnemonic::from_entropy(&key_bytes)
        .map_err(|e| RecoveryError::Bip39(e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Recover an age secret key from a BIP39 24-word mnemonic phrase.
/// Returns the same MURK_KEY that was originally generated.
#[allow(dead_code)]
pub fn recover(phrase: &str) -> Result<String, RecoveryError> {
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
        .map_err(|e| RecoveryError::Bip39(e.to_string()))?;

    let entropy = mnemonic.to_entropy();
    bytes_to_age_key(&entropy)
}

/// Bech32-encode raw key bytes as an AGE-SECRET-KEY-1... string.
/// This matches exactly how the age crate encodes keys internally.
fn bytes_to_age_key(key_bytes: &[u8]) -> Result<String, RecoveryError> {
    let encoded = bech32::encode(AGE_SECRET_KEY_HRP, key_bytes.to_base32(), Variant::Bech32)
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;

    let key_str = encoded.to_uppercase();

    // Validate by round-tripping through the age crate.
    crate::crypto::parse_identity(&key_str)
        .map_err(|e| RecoveryError::InvalidKey(e.to_string()))?;

    Ok(key_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_mnemonic_and_key() {
        let (phrase, secret_key, pubkey) = generate().unwrap();

        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(secret_key.starts_with("AGE-SECRET-KEY-1"));
        assert!(pubkey.starts_with("age1"));
    }

    #[test]
    fn recover_roundtrip() {
        let (phrase, original_key, _) = generate().unwrap();
        let recovered_key = recover(&phrase).unwrap();
        assert_eq!(original_key, recovered_key);
    }

    #[test]
    fn same_phrase_same_key() {
        let (phrase, key1, _) = generate().unwrap();
        let key2 = recover(&phrase).unwrap();
        let key3 = recover(&phrase).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key2, key3);
    }

    #[test]
    fn different_phrases_different_keys() {
        let (_, key1, _) = generate().unwrap();
        let (_, key2, _) = generate().unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn phrase_from_key_roundtrip() {
        let (original_phrase, secret_key, _) = generate().unwrap();
        let recovered_phrase = phrase_from_key(&secret_key).unwrap();
        assert_eq!(original_phrase, recovered_phrase);
    }

    #[test]
    fn invalid_phrase_fails() {
        assert!(recover("amet sed ut sit dolor et magna vita ipsum quasi nemo enim ad ex in id est non vel rem sint cum").is_err());
    }
}
