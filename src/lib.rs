//! Encrypted secrets manager for developers — one file, age encryption, git-friendly.
//!
//! This library provides the core functionality for murk: vault I/O, age encryption,
//! BIP39 key recovery, and secret management. The CLI binary wraps this library.

#![warn(clippy::pedantic)]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::too_many_arguments,
    clippy::implicit_hasher
)]

// Domain modules — pub(crate) unless main.rs needs direct path access.
pub(crate) mod codename;
pub mod crypto;
pub(crate) mod env;
pub mod error;
pub(crate) mod export;
pub(crate) mod git;
pub mod github;
pub(crate) mod info;
pub(crate) mod init;
pub(crate) mod merge;
pub(crate) mod recipients;
pub mod recovery;
pub(crate) mod secrets;
pub mod types;
pub mod vault;

// Shared test utilities
#[cfg(test)]
pub mod testutil;

// Re-exports: keep the flat murk_cli::foo() API for main.rs
pub use env::{
    EnvrcStatus, dotenv_has_murk_key, key_file_path, parse_env, read_key_from_dotenv, resolve_key,
    warn_env_permissions, write_envrc, write_key_ref_to_dotenv, write_key_to_dotenv,
    write_key_to_file,
};
pub use error::MurkError;
pub use export::{
    DiffEntry, DiffKind, decrypt_vault_values, diff_secrets, export_secrets, format_diff_lines,
    parse_and_decrypt_values, resolve_secrets,
};
pub use git::{MergeDriverSetupStep, setup_merge_driver};
pub use github::{GitHubError, fetch_keys};
pub use info::{InfoEntry, VaultInfo, format_info_lines, vault_info};
pub use init::{DiscoveredKey, InitStatus, check_init_status, create_vault, discover_existing_key};
pub use merge::{MergeDriverOutput, run_merge_driver};
pub use recipients::{
    RecipientEntry, RevokeResult, authorize_recipient, format_recipient_lines, key_type_label,
    list_recipients, revoke_recipient, truncate_pubkey,
};
pub use secrets::{add_secret, describe_key, get_secret, import_secrets, list_keys, remove_secret};

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Check whether a key name is a valid shell identifier (safe for `export KEY=...`).
/// Must start with a letter or underscore, and contain only `[A-Za-z0-9_]`.
pub fn is_valid_key_name(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

use age::secrecy::ExposeSecret;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

// Re-export polymorphic types for consumers.
pub use crypto::{MurkIdentity, MurkRecipient};

/// Decrypt the meta blob from a vault, returning the deserialized Meta if possible.
pub(crate) fn decrypt_meta(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Option<types::Meta> {
    if vault.meta.is_empty() {
        return None;
    }
    let plaintext = decrypt_value(&vault.meta, identity).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Parse a list of pubkey strings into recipients (age or SSH).
pub(crate) fn parse_recipients(
    pubkeys: &[String],
) -> Result<Vec<crypto::MurkRecipient>, MurkError> {
    pubkeys
        .iter()
        .map(|pk| crypto::parse_recipient(pk).map_err(MurkError::from))
        .collect()
}

/// Encrypt a value and return base64-encoded ciphertext.
pub fn encrypt_value(
    plaintext: &[u8],
    recipients: &[crypto::MurkRecipient],
) -> Result<String, MurkError> {
    let ciphertext = crypto::encrypt(plaintext, recipients)?;
    Ok(BASE64.encode(&ciphertext))
}

/// Decrypt a base64-encoded ciphertext and return plaintext bytes.
pub fn decrypt_value(encoded: &str, identity: &crypto::MurkIdentity) -> Result<Vec<u8>, MurkError> {
    let ciphertext = BASE64.decode(encoded).map_err(|e| {
        MurkError::Crypto(crypto::CryptoError::Decrypt(format!("invalid base64: {e}")))
    })?;
    Ok(crypto::decrypt(&ciphertext, identity)?)
}

/// Read a vault file from disk.
///
/// This is a thin wrapper around `vault::read` for a convenient string-path API.
pub fn read_vault(vault_path: &str) -> Result<types::Vault, MurkError> {
    Ok(vault::read(Path::new(vault_path))?)
}

/// Decrypt a vault using the given identity. Verifies integrity, decrypts all
/// shared and scoped values, and returns the working state.
///
/// Use this when you already have a key (e.g. from a Python SDK or test harness).
/// For the common CLI case where the key comes from the environment, use `load_vault`.
pub fn decrypt_vault(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<types::Murk, MurkError> {
    let pubkey = identity.pubkey_string()?;

    // Decrypt shared values.
    let mut values = HashMap::new();
    for (key, entry) in &vault.secrets {
        let plaintext = decrypt_value(&entry.shared, identity).map_err(|_| {
            MurkError::Crypto(crypto::CryptoError::Decrypt(
                "you are not a recipient of this vault. Run `murk circle` to check, or ask a recipient to authorize you".into()
            ))
        })?;
        let value = String::from_utf8(plaintext)
            .map_err(|e| MurkError::Secret(format!("invalid UTF-8 in secret {key}: {e}")))?;
        values.insert(key.clone(), value);
    }

    // Decrypt our scoped (mote) overrides.
    let mut scoped = HashMap::new();
    for (key, entry) in &vault.secrets {
        if let Some(encoded) = entry.scoped.get(&pubkey)
            && let Ok(value) = decrypt_value(encoded, identity)
                .and_then(|pt| String::from_utf8(pt).map_err(|e| MurkError::Secret(e.to_string())))
        {
            scoped
                .entry(key.clone())
                .or_insert_with(HashMap::new)
                .insert(pubkey.clone(), value);
        }
    }

    // Decrypt meta for recipient names and validate integrity MAC.
    let (recipients, legacy_mac) = match decrypt_meta(vault, identity) {
        Some(meta) if !meta.mac.is_empty() => {
            let hmac_key = meta.hmac_key.as_deref().and_then(decode_hmac_key);
            if !verify_mac(vault, &meta.mac, hmac_key.as_ref()) {
                let expected = compute_mac(vault, hmac_key.as_ref());
                return Err(MurkError::Integrity(format!(
                    "vault may have been tampered with (expected {expected}, got {})",
                    meta.mac
                )));
            }
            let legacy = meta.mac.starts_with("sha256:") || meta.mac.starts_with("sha256v2:");
            (meta.recipients, legacy)
        }
        Some(meta) if vault.secrets.is_empty() => (meta.recipients, false),
        Some(_) => {
            return Err(MurkError::Integrity(
                "vault has secrets but MAC is empty — vault may have been tampered with".into(),
            ));
        }
        None if vault.secrets.is_empty() && vault.meta.is_empty() => (HashMap::new(), false),
        None => {
            return Err(MurkError::Integrity(
                "vault has secrets but no meta — vault may have been tampered with".into(),
            ));
        }
    };

    Ok(types::Murk {
        values,
        recipients,
        scoped,
        legacy_mac,
    })
}

/// Resolve the key from the environment, read the vault, and decrypt it.
///
/// Convenience wrapper combining `resolve_key` + `read_vault` + `decrypt_vault`.
pub fn load_vault(
    vault_path: &str,
) -> Result<(types::Vault, types::Murk, crypto::MurkIdentity), MurkError> {
    let secret_key = resolve_key().map_err(MurkError::Key)?;

    let identity = crypto::parse_identity(secret_key.expose_secret()).map_err(|e| {
        MurkError::Key(format!(
            "{e}. For age keys, set MURK_KEY. For SSH keys, set MURK_KEY_FILE=~/.ssh/id_ed25519"
        ))
    })?;

    let vault = read_vault(vault_path)?;
    let murk = decrypt_vault(&vault, &identity)?;

    Ok((vault, murk, identity))
}

/// Save the vault: compare against original state and only re-encrypt changed values.
/// Unchanged values keep their original ciphertext for minimal git diffs.
pub fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    let recipients = parse_recipients(&vault.recipients)?;

    // Check if recipient list changed — forces full re-encryption of shared values.
    let recipients_changed = {
        let mut current_pks: Vec<&str> = vault.recipients.iter().map(String::as_str).collect();
        let mut original_pks: Vec<&str> = original.recipients.keys().map(String::as_str).collect();
        current_pks.sort_unstable();
        original_pks.sort_unstable();
        current_pks != original_pks
    };

    let mut new_secrets = BTreeMap::new();

    for (key, value) in &current.values {
        let shared = if !recipients_changed && original.values.get(key) == Some(value) {
            if let Some(existing) = vault.secrets.get(key) {
                existing.shared.clone()
            } else {
                encrypt_value(value.as_bytes(), &recipients)?
            }
        } else {
            encrypt_value(value.as_bytes(), &recipients)?
        };

        let mut scoped = vault
            .secrets
            .get(key)
            .map(|e| e.scoped.clone())
            .unwrap_or_default();

        if let Some(key_scoped) = current.scoped.get(key) {
            for (pk, val) in key_scoped {
                let original_val = original.scoped.get(key).and_then(|m| m.get(pk));
                if original_val == Some(val) {
                    // Unchanged — keep original ciphertext.
                } else {
                    let recipient = crypto::parse_recipient(pk)?;
                    scoped.insert(pk.clone(), encrypt_value(val.as_bytes(), &[recipient])?);
                }
            }
        }

        if let Some(orig_key_scoped) = original.scoped.get(key) {
            for pk in orig_key_scoped.keys() {
                let still_present = current.scoped.get(key).is_some_and(|m| m.contains_key(pk));
                if !still_present {
                    scoped.remove(pk);
                }
            }
        }

        new_secrets.insert(key.clone(), types::SecretEntry { shared, scoped });
    }

    vault.secrets = new_secrets;

    // Update meta — always generate a fresh BLAKE3 key on save.
    let hmac_key_hex = generate_hmac_key();
    let hmac_key = decode_hmac_key(&hmac_key_hex).unwrap();
    let mac = compute_mac(vault, Some(&hmac_key));
    let meta = types::Meta {
        recipients: current.recipients.clone(),
        mac,
        hmac_key: Some(hmac_key_hex),
    };
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &recipients)?;

    Ok(vault::write(Path::new(vault_path), vault)?)
}

/// Compute an integrity MAC over the vault's secrets, scoped entries, and recipients.
///
/// If an HMAC key is provided, uses BLAKE3 keyed hash (written as `blake3:`).
/// Otherwise falls back to unkeyed SHA-256 v2 for legacy compatibility.
pub(crate) fn compute_mac(vault: &types::Vault, hmac_key: Option<&[u8; 32]>) -> String {
    match hmac_key {
        Some(key) => compute_mac_v3(vault, key),
        None => compute_mac_v2(vault),
    }
}

/// Legacy MAC: covers key names, shared ciphertext, and recipients (no scoped).
fn compute_mac_v1(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    for key in vault.secrets.keys() {
        hasher.update(key.as_bytes());
        hasher.update(b"\x00");
    }

    for entry in vault.secrets.values() {
        hasher.update(entry.shared.as_bytes());
        hasher.update(b"\x00");
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        hasher.update(pk.as_bytes());
        hasher.update(b"\x00");
    }

    let digest = hasher.finalize();
    format!(
        "sha256:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    )
}

/// V2 MAC: covers key names, shared ciphertext, scoped entries, and recipients.
fn compute_mac_v2(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Hash sorted key names.
    for key in vault.secrets.keys() {
        hasher.update(key.as_bytes());
        hasher.update(b"\x00");
    }

    // Hash encrypted shared values (as stored).
    for entry in vault.secrets.values() {
        hasher.update(entry.shared.as_bytes());
        hasher.update(b"\x00");

        // Hash scoped entries (sorted by pubkey for determinism).
        let mut scoped_pks: Vec<&String> = entry.scoped.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            hasher.update(pk.as_bytes());
            hasher.update(b"\x01");
            hasher.update(entry.scoped[pk].as_bytes());
            hasher.update(b"\x00");
        }
    }

    // Hash sorted recipient pubkeys.
    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        hasher.update(pk.as_bytes());
        hasher.update(b"\x00");
    }

    let digest = hasher.finalize();
    format!(
        "sha256v2:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    )
}

/// V3 MAC: BLAKE3 keyed hash over the same inputs as v2.
fn compute_mac_v3(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.scoped.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.scoped[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3:{hash}")
}

/// Verify a stored MAC against the vault, accepting v1, v2, and blake3 schemes.
pub(crate) fn verify_mac(
    vault: &types::Vault,
    stored_mac: &str,
    hmac_key: Option<&[u8; 32]>,
) -> bool {
    use constant_time_eq::constant_time_eq;

    let expected = if stored_mac.starts_with("blake3:") {
        match hmac_key {
            Some(key) => compute_mac_v3(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("sha256v2:") {
        compute_mac_v2(vault)
    } else if stored_mac.starts_with("sha256:") {
        compute_mac_v1(vault)
    } else {
        return false;
    };
    constant_time_eq(stored_mac.as_bytes(), expected.as_bytes())
}

/// Generate a random 32-byte BLAKE3 MAC key, returned as hex.
pub(crate) fn generate_hmac_key() -> String {
    let key: [u8; 32] = rand::random();
    key.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Decode a hex-encoded 32-byte key.
pub(crate) fn decode_hmac_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(key)
}

/// Generate an ISO-8601 UTC timestamp.
pub(crate) fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Mutex;

    /// Tests that mutate MURK_KEY env var must hold this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn encrypt_decrypt_value_roundtrip() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let encoded = encrypt_value(b"hello world", &[recipient]).unwrap();
        let decrypted = decrypt_value(&encoded, &identity).unwrap();
        assert_eq!(decrypted, b"hello world");
    }

    #[test]
    fn decrypt_value_invalid_base64() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);

        let result = decrypt_value("not!valid!base64!!!", &identity);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid base64"));
    }

    #[test]
    fn encrypt_value_multiple_recipients() {
        let (secret_a, pubkey_a) = generate_keypair();
        let (secret_b, pubkey_b) = generate_keypair();

        let recipients = vec![make_recipient(&pubkey_a), make_recipient(&pubkey_b)];
        let encoded = encrypt_value(b"shared secret", &recipients).unwrap();

        // Both can decrypt.
        let id_a = make_identity(&secret_a);
        let id_b = make_identity(&secret_b);
        assert_eq!(decrypt_value(&encoded, &id_a).unwrap(), b"shared secret");
        assert_eq!(decrypt_value(&encoded, &id_b).unwrap(), b"shared secret");
    }

    #[test]
    fn decrypt_value_wrong_key_fails() {
        let (_, pubkey) = generate_keypair();
        let (wrong_secret, _) = generate_keypair();

        let recipient = make_recipient(&pubkey);
        let wrong_identity = make_identity(&wrong_secret);

        let encoded = encrypt_value(b"secret", &[recipient]).unwrap();
        assert!(decrypt_value(&encoded, &wrong_identity).is_err());
    }

    #[test]
    fn compute_mac_deterministic() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac1 = compute_mac(&vault, Some(&key));
        let mac2 = compute_mac(&vault, Some(&key));
        assert_eq!(mac1, mac2);
        assert!(mac1.starts_with("blake3:"));

        // Without key, falls back to sha256v2
        let mac_legacy = compute_mac(&vault, None);
        assert!(mac_legacy.starts_with("sha256v2:"));
    }

    #[test]
    fn compute_mac_changes_with_different_secrets() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac_empty = compute_mac(&vault, Some(&key));

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                scoped: BTreeMap::new(),
            },
        );

        let mac_with_secret = compute_mac(&vault, Some(&key));
        assert_ne!(mac_empty, mac_with_secret);
    }

    #[test]
    fn compute_mac_changes_with_different_recipients() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac1 = compute_mac(&vault, Some(&key));
        vault.recipients.push("age1xyz".into());
        let mac2 = compute_mac(&vault, Some(&key));
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn save_vault_preserves_unchanged_ciphertext() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_save_unchanged");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"original", &[recipient.clone()]).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: shared.clone(),
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "original".into())]),
            recipients: recipients_map.clone(),
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        let current = original.clone();
        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert_eq!(vault.secrets["KEY1"].shared, shared);

        let mut changed = current.clone();
        changed.values.insert("KEY1".into(), "modified".into());
        save_vault(path.to_str().unwrap(), &mut vault, &original, &changed).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        let decrypted = decrypt_value(&vault.secrets["KEY1"].shared, &identity).unwrap();
        assert_eq!(decrypted, b"modified");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_adds_new_secret() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_add");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"val1", &[recipient.clone()]).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared,
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map.clone(),
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        let mut current = original.clone();
        current.values.insert("KEY2".into(), "val2".into());

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets.contains_key("KEY1"));
        assert!(vault.secrets.contains_key("KEY2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_removes_deleted_secret() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_remove");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient.clone()]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val2", &[recipient.clone()]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([
                ("KEY1".into(), "val1".into()),
                ("KEY2".into(), "val2".into()),
            ]),
            recipients: recipients_map.clone(),
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        let mut current = original.clone();
        current.values.remove("KEY2");

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets.contains_key("KEY1"));
        assert!(!vault.secrets.contains_key("KEY2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_reencrypts_all_on_recipient_change() {
        let (secret1, pubkey1) = generate_keypair();
        let (_, pubkey2) = generate_keypair();
        let recipient1 = make_recipient(&pubkey1);

        let dir = std::env::temp_dir().join("murk_test_save_reencrypt");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"val1", &[recipient1.clone()]).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey1.clone(), pubkey2.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: shared.clone(),
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey1.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        let mut current_recipients = HashMap::new();
        current_recipients.insert(pubkey1.clone(), "alice".into());
        current_recipients.insert(pubkey2.clone(), "bob".into());
        let current = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: current_recipients,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        let identity1 = make_identity(&secret1);
        let decrypted = decrypt_value(&vault.secrets["KEY1"].shared, &identity1).unwrap();
        assert_eq!(decrypted, b"val1");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_scoped_entry_lifecycle() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_save_scoped");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"shared_val", &[recipient.clone()]).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared,
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "shared_val".into())]),
            recipients: recipients_map.clone(),
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        // Add a scoped override.
        let mut current = original.clone();
        let mut key_scoped = HashMap::new();
        key_scoped.insert(pubkey.clone(), "my_override".into());
        current.scoped.insert("KEY1".into(), key_scoped);

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets["KEY1"].scoped.contains_key(&pubkey));
        let scoped_val = decrypt_value(&vault.secrets["KEY1"].scoped[&pubkey], &identity).unwrap();
        assert_eq!(scoped_val, b"my_override");

        // Now remove the scoped override.
        let original_with_scoped = current.clone();
        let mut current_no_scoped = original_with_scoped.clone();
        current_no_scoped.scoped.remove("KEY1");

        save_vault(
            path.to_str().unwrap(),
            &mut vault,
            &original_with_scoped,
            &current_no_scoped,
        )
        .unwrap();

        assert!(vault.secrets["KEY1"].scoped.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_validates_mac() {
        let _lock = ENV_LOCK.lock().unwrap();

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let _identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_load_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret, save it (computes valid MAC).
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient.clone()]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        // save_vault needs MURK_KEY set to encrypt meta.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Now tamper: change the ciphertext in the saved vault file.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.secrets.get_mut("KEY1").unwrap().shared =
            encrypt_value(b"tampered", &[recipient]).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Load should fail MAC validation.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.err().expect("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_succeeds_with_valid_mac() {
        let _lock = ENV_LOCK.lock().unwrap();

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_valid_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Load should succeed.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(result.is_ok());
        let (_, murk, _) = result.unwrap();
        assert_eq!(murk.values["KEY1"], "val1");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_not_a_recipient() {
        let _lock = ENV_LOCK.lock().unwrap();

        let (secret, _pubkey) = generate_keypair();
        let (other_secret, other_pubkey) = generate_keypair();
        let other_recipient = make_recipient(&other_pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_not_recipient");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault encrypted to `other`, not to `secret`.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![other_pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[other_recipient]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );

        // Save via save_vault (needs the other key for re-encryption).
        let mut recipients_map = HashMap::new();
        recipients_map.insert(other_pubkey.clone(), "other".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        unsafe { std::env::set_var("MURK_KEY", &other_secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Now try to load with a key that is NOT a recipient.
        unsafe { std::env::set_var("MURK_KEY", secret) };
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected load_vault to fail for non-recipient"),
        };
        assert!(
            err.to_string().contains("decryption failed"),
            "expected decryption failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_zero_secrets() {
        let _lock = ENV_LOCK.lock().unwrap();

        let (secret, pubkey) = generate_keypair();

        let dir = std::env::temp_dir().join("murk_test_load_zero_secrets");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with no secrets at all.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::new(),
            recipients: recipients_map,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(result.is_ok());
        let (_, murk, _) = result.unwrap();
        assert!(murk.values.is_empty());
        assert!(murk.scoped.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_stripped_meta_with_secrets_fails() {
        let _lock = ENV_LOCK.lock().unwrap();

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_stripped_meta");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret and a valid MAC via save_vault.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map,
            scoped: HashMap::new(),
            legacy_mac: false,
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Tamper: strip meta field entirely.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.meta = String::new();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Load should fail: secrets present but no meta.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.err().expect("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_empty_mac_with_secrets_fails() {
        let _lock = ENV_LOCK.lock().unwrap();

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_empty_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient.clone()]).unwrap(),
                scoped: BTreeMap::new(),
            },
        );

        // Manually create meta with empty MAC and encrypt it.
        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let meta = types::Meta {
            recipients: recipients_map,
            mac: String::new(),
            hmac_key: None,
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        vault.meta = encrypt_value(&meta_json, &[recipient]).unwrap();

        // Write the vault to disk.
        crate::vault::write(Path::new(path.to_str().unwrap()), &vault).unwrap();

        // Load should fail: secrets present but MAC is empty.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.err().expect("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compute_mac_changes_with_scoped_entries() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                scoped: BTreeMap::new(),
            },
        );

        let key = [0u8; 32];
        let mac_no_scoped = compute_mac(&vault, Some(&key));

        vault
            .secrets
            .get_mut("KEY")
            .unwrap()
            .scoped
            .insert("age1bob".into(), "scoped-ct".into());

        let mac_with_scoped = compute_mac(&vault, Some(&key));
        assert_ne!(mac_no_scoped, mac_with_scoped);
    }

    #[test]
    fn verify_mac_accepts_v1_prefix() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let v1_mac = compute_mac_v1(&vault);
        let v2_mac = compute_mac_v2(&vault);
        let v3_mac = compute_mac_v3(&vault, &key);
        assert!(verify_mac(&vault, &v1_mac, None));
        assert!(verify_mac(&vault, &v2_mac, None));
        assert!(verify_mac(&vault, &v3_mac, Some(&key)));
        assert!(!verify_mac(&vault, "sha256:bogus", None));
        assert!(!verify_mac(&vault, "blake3:bogus", Some(&key)));
        assert!(!verify_mac(&vault, "unknown:prefix", None));
    }

    #[test]
    fn hmac_key_roundtrip() {
        let hex = generate_hmac_key();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let key = decode_hmac_key(&hex).expect("valid hex should decode");
        // Re-encode and compare.
        let rehex = key.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, rehex);
    }

    #[test]
    fn decode_hmac_key_rejects_bad_input() {
        assert!(decode_hmac_key("").is_none());
        assert!(decode_hmac_key("tooshort").is_none());
        assert!(decode_hmac_key(&"zz".repeat(32)).is_none()); // invalid hex
        assert!(decode_hmac_key(&"aa".repeat(31)).is_none()); // 31 bytes
        assert!(decode_hmac_key(&"aa".repeat(33)).is_none()); // 33 bytes
    }

    #[test]
    fn blake3_mac_different_key_different_mac() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let mac1 = compute_mac(&vault, Some(&key1));
        let mac2 = compute_mac(&vault, Some(&key2));
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn valid_key_names() {
        assert!(is_valid_key_name("DATABASE_URL"));
        assert!(is_valid_key_name("_PRIVATE"));
        assert!(is_valid_key_name("A"));
        assert!(is_valid_key_name("key123"));
    }

    #[test]
    fn invalid_key_names() {
        assert!(!is_valid_key_name(""));
        assert!(!is_valid_key_name("123_START"));
        assert!(!is_valid_key_name("KEY-NAME"));
        assert!(!is_valid_key_name("KEY NAME"));
        assert!(!is_valid_key_name("FOO$(bar)"));
        assert!(!is_valid_key_name("KEY=VAL"));
    }

    #[test]
    fn now_utc_format() {
        let ts = now_utc();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
