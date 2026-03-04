use std::io::{Read, Write};

/// Errors that can occur during crypto operations.
#[derive(Debug)]
pub enum CryptoError {
    Encrypt(String),
    Decrypt(String),
    InvalidKey(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Encrypt(msg) => write!(f, "encryption failed: {msg}"),
            CryptoError::Decrypt(msg) => write!(f, "decryption failed: {msg}"),
            CryptoError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
        }
    }
}

/// A recipient that can receive age-encrypted data.
///
/// Wraps either an age x25519 recipient or an SSH public key recipient.
#[derive(Clone)]
pub enum MurkRecipient {
    Age(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
}

impl MurkRecipient {
    /// Borrow as a trait object for passing to age's encryptor.
    pub fn as_dyn(&self) -> &dyn age::Recipient {
        match self {
            MurkRecipient::Age(r) => r,
            MurkRecipient::Ssh(r) => r,
        }
    }
}

/// An identity that can decrypt age-encrypted data.
///
/// Wraps either an age x25519 identity or an SSH private key identity.
#[derive(Clone)]
pub enum MurkIdentity {
    Age(age::x25519::Identity),
    Ssh(age::ssh::Identity),
}

impl MurkIdentity {
    /// Return the public key string for this identity.
    ///
    /// For age keys: `age1...`
    /// For SSH keys: `ssh-ed25519 AAAA...` or `ssh-rsa AAAA...`
    pub fn pubkey_string(&self) -> Result<String, CryptoError> {
        match self {
            MurkIdentity::Age(id) => Ok(id.to_public().to_string()),
            MurkIdentity::Ssh(id) => {
                let recipient = age::ssh::Recipient::try_from(id.clone()).map_err(|e| {
                    CryptoError::InvalidKey(format!("cannot derive SSH public key: {e:?}"))
                })?;
                Ok(recipient.to_string())
            }
        }
    }

    /// Borrow as a trait object for passing to age's decryptor.
    fn as_dyn(&self) -> &dyn age::Identity {
        match self {
            MurkIdentity::Age(id) => id,
            MurkIdentity::Ssh(id) => id,
        }
    }
}

/// Parse a public key string into a `MurkRecipient`.
///
/// Tries x25519 (`age1...`) first, then SSH (`ssh-ed25519 ...` / `ssh-rsa ...`).
pub fn parse_recipient(pubkey: &str) -> Result<MurkRecipient, CryptoError> {
    // Try age x25519 first.
    if let Ok(r) = pubkey.parse::<age::x25519::Recipient>() {
        return Ok(MurkRecipient::Age(r));
    }

    // Try SSH.
    if let Ok(r) = pubkey.parse::<age::ssh::Recipient>() {
        return Ok(MurkRecipient::Ssh(r));
    }

    Err(CryptoError::InvalidKey(format!(
        "not a valid age or SSH public key: {pubkey}"
    )))
}

/// Parse a secret key string into a `MurkIdentity`.
///
/// Tries age (`AGE-SECRET-KEY-1...`) first, then SSH PEM format.
/// Encrypted SSH keys are rejected with a clear error.
pub fn parse_identity(secret_key: &str) -> Result<MurkIdentity, CryptoError> {
    // Try age x25519 first.
    if let Ok(id) = secret_key.parse::<age::x25519::Identity>() {
        return Ok(MurkIdentity::Age(id));
    }

    // Try SSH PEM.
    let reader = std::io::BufReader::new(secret_key.as_bytes());
    match age::ssh::Identity::from_buffer(reader, None) {
        Ok(id) => match &id {
            age::ssh::Identity::Unencrypted(_) => Ok(MurkIdentity::Ssh(id)),
            age::ssh::Identity::Encrypted(_) => Err(CryptoError::InvalidKey(
                "encrypted SSH keys are not yet supported — use an unencrypted key or an age key"
                    .into(),
            )),
            age::ssh::Identity::Unsupported(k) => Err(CryptoError::InvalidKey(format!(
                "unsupported SSH key type: {k:?}"
            ))),
        },
        Err(_) => Err(CryptoError::InvalidKey(
            "not a valid age secret key or SSH private key".into(),
        )),
    }
}

/// Encrypt plaintext bytes to one or more recipients.
pub fn encrypt(plaintext: &[u8], recipients: &[MurkRecipient]) -> Result<Vec<u8>, CryptoError> {
    let recipient_refs: Vec<&dyn age::Recipient> =
        recipients.iter().map(MurkRecipient::as_dyn).collect();

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

/// Decrypt ciphertext using an identity (age or SSH key).
pub fn decrypt(ciphertext: &[u8], identity: &MurkIdentity) -> Result<Vec<u8>, CryptoError> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    let mut plaintext = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(identity.as_dyn()))
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn generate_keypair() -> (String, String) {
        let identity = age::x25519::Identity::generate();
        let secret = identity.to_string();
        let pubkey = identity.to_public().to_string();
        (secret.expose_secret().to_string(), pubkey)
    }

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

    // ── New edge-case tests ──

    #[test]
    fn encrypt_empty_plaintext() {
        let (secret, pubkey) = generate_keypair();
        let recipient = parse_recipient(&pubkey).unwrap();
        let identity = parse_identity(&secret).unwrap();

        let ciphertext = encrypt(b"", &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &identity).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn decrypt_corrupted_ciphertext() {
        let (secret, _) = generate_keypair();
        let identity = parse_identity(&secret).unwrap();
        assert!(decrypt(b"this is not valid ciphertext", &identity).is_err());
    }

    #[test]
    fn parse_recipient_ssh_ed25519() {
        // A valid ssh-ed25519 public key (without comment)
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";
        let r = parse_recipient(key);
        assert!(r.is_ok());
        assert!(matches!(r.unwrap(), MurkRecipient::Ssh(_)));
    }

    #[test]
    fn parse_recipient_age_key() {
        let (_, pubkey) = generate_keypair();
        let r = parse_recipient(&pubkey);
        assert!(r.is_ok());
        assert!(matches!(r.unwrap(), MurkRecipient::Age(_)));
    }

    #[test]
    fn pubkey_string_age() {
        let (secret, pubkey) = generate_keypair();
        let id = parse_identity(&secret).unwrap();
        assert_eq!(id.pubkey_string().unwrap(), pubkey);
    }

    #[test]
    fn parse_identity_ssh_unencrypted() {
        // Unencrypted ed25519 SSH key from age's test suite.
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk);
        assert!(id.is_ok());
        assert!(matches!(id.unwrap(), MurkIdentity::Ssh(_)));
    }

    #[test]
    fn ssh_identity_pubkey_roundtrip() {
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk).unwrap();
        let pubkey = id.pubkey_string().unwrap();
        assert!(pubkey.starts_with("ssh-ed25519 "));

        // The derived pubkey should be parseable as a recipient.
        let recipient = parse_recipient(&pubkey);
        assert!(recipient.is_ok());
    }

    #[test]
    fn ssh_encrypt_decrypt_roundtrip() {
        let sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let id = parse_identity(sk).unwrap();
        let pubkey = id.pubkey_string().unwrap();
        let recipient = parse_recipient(&pubkey).unwrap();

        let plaintext = b"ssh secrets";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &id).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn mixed_age_and_ssh_recipients() {
        // Age keypair.
        let (age_secret, age_pubkey) = generate_keypair();

        // SSH keypair.
        let ssh_sk = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
        let ssh_id = parse_identity(ssh_sk).unwrap();
        let ssh_pubkey = ssh_id.pubkey_string().unwrap();

        // Encrypt to both.
        let recipients = vec![
            parse_recipient(&age_pubkey).unwrap(),
            parse_recipient(&ssh_pubkey).unwrap(),
        ];
        let plaintext = b"shared between age and ssh";
        let ciphertext = encrypt(plaintext, &recipients).unwrap();

        // Both can decrypt.
        let age_id = parse_identity(&age_secret).unwrap();
        assert_eq!(decrypt(&ciphertext, &age_id).unwrap(), plaintext);
        assert_eq!(decrypt(&ciphertext, &ssh_id).unwrap(), plaintext);
    }
}
