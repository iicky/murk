use std::io::{Read, Write};

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};

/// Errors that can occur during crypto operations.
#[derive(Debug)]
pub enum CryptoError {
    Generate(String),
    Encrypt(String),
    Decrypt(String),
    InvalidKey(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Generate(msg) => write!(f, "key generation failed: {msg}"),
            CryptoError::Encrypt(msg) => write!(f, "encryption failed: {msg}"),
            CryptoError::Decrypt(msg) => write!(f, "decryption failed: {msg}"),
            CryptoError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
        }
    }
}

/// Generate a new age keypair.
/// Returns (secret_key_string, public_key_string).
pub fn generate_keypair() -> (String, String) {
    let identity = Identity::generate();
    let secret = identity.to_string();
    let pubkey = identity.to_public().to_string();
    (secret.expose_secret().to_string(), pubkey)
}

/// Parse a public key from its string representation (age1...).
pub fn parse_recipient(pubkey: &str) -> Result<Recipient, CryptoError> {
    pubkey
        .parse::<Recipient>()
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

/// Parse a secret key from its string representation (AGE-SECRET-KEY-1...).
pub fn parse_identity(secret_key: &str) -> Result<Identity, CryptoError> {
    secret_key
        .parse::<Identity>()
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

/// Encrypt plaintext bytes to one or more recipients.
pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, CryptoError> {
    let recipient_refs: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r as &dyn age::Recipient)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    let mut ciphertext = vec![];
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    writer
        .write_all(plaintext)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    // finish() is critical — without it, the output is silently
    // truncated and undecryptable. No error, just broken data.
    writer
        .finish()
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    Ok(ciphertext)
}

/// Decrypt ciphertext using a secret key.
pub fn decrypt(ciphertext: &[u8], identity: &Identity) -> Result<Vec<u8>, CryptoError> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    let mut plaintext = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_recipient() {
        let (secret, pubkey) = generate_keypair();
        let recipient = parse_recipient(&pubkey).unwrap();
        let identity = parse_identity(&secret).unwrap();

        let plaintext = b"hello darkness";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &identity).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_multiple_recipients() {
        let (secret_a, pubkey_a) = generate_keypair();
        let (secret_b, pubkey_b) = generate_keypair();

        let recipients = vec![
            parse_recipient(&pubkey_a).unwrap(),
            parse_recipient(&pubkey_b).unwrap(),
        ];

        let plaintext = b"sharing is caring";
        let ciphertext = encrypt(plaintext, &recipients).unwrap();

        // Both recipients can decrypt
        let id_a = parse_identity(&secret_a).unwrap();
        let id_b = parse_identity(&secret_b).unwrap();
        assert_eq!(decrypt(&ciphertext, &id_a).unwrap(), plaintext);
        assert_eq!(decrypt(&ciphertext, &id_b).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let (_secret, pubkey) = generate_keypair();
        let (wrong_secret, _) = generate_keypair();

        let recipient = parse_recipient(&pubkey).unwrap();
        let wrong_identity = parse_identity(&wrong_secret).unwrap();

        let ciphertext = encrypt(b"none of your business", &[recipient]).unwrap();
        assert!(decrypt(&ciphertext, &wrong_identity).is_err());
    }

    #[test]
    fn invalid_key_strings() {
        assert!(parse_recipient("sine-loco").is_err());
        assert!(parse_identity("nihil-et-nemo").is_err());
    }
}
