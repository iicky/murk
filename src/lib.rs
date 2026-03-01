//! Encrypted secrets manager for developers — one file, age encryption, git-friendly.
//!
//! This library provides the core functionality for murk: vault I/O, age encryption,
//! BIP39 key recovery, and secret management. The CLI binary wraps this library.

#![warn(clippy::pedantic)]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::unreadable_literal
)]

pub mod crypto;
pub mod integrity;
pub mod recovery;
pub mod types;
pub mod vault;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use age::secrecy::{ExposeSecret, SecretString};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

/// Encrypt a value and return base64-encoded ciphertext.
pub fn encrypt_value(
    plaintext: &[u8],
    recipients: &[age::x25519::Recipient],
) -> Result<String, String> {
    let ciphertext = crypto::encrypt(plaintext, recipients).map_err(|e| e.to_string())?;
    Ok(BASE64.encode(&ciphertext))
}

/// Decrypt a base64-encoded ciphertext and return plaintext bytes.
pub fn decrypt_value(encoded: &str, identity: &age::x25519::Identity) -> Result<Vec<u8>, String> {
    let ciphertext = BASE64
        .decode(encoded)
        .map_err(|e| format!("invalid base64: {e}"))?;
    crypto::decrypt(&ciphertext, identity).map_err(|e| e.to_string())
}

/// Resolve the secret key from `MURK_KEY` or `MURK_KEY_FILE`.
/// `MURK_KEY` takes priority; `MURK_KEY_FILE` reads the key from a file.
/// Returns the key wrapped in `SecretString` so it is zeroized on drop.
pub fn resolve_key() -> Result<SecretString, String> {
    if let Ok(k) = env::var("MURK_KEY") {
        return Ok(SecretString::from(k));
    }
    if let Ok(path) = env::var("MURK_KEY_FILE") {
        return fs::read_to_string(&path)
            .map(|contents| SecretString::from(contents.trim().to_string()))
            .map_err(|e| format!("cannot read MURK_KEY_FILE ({path}): {e}"));
    }
    Err("MURK_KEY not set. Add it to .env and load with direnv or `eval $(cat .env)`. Alternatively, set MURK_KEY_FILE to a path containing the key".into())
}

/// Load the vault: read JSON, decrypt all values, return working state.
/// Returns the raw vault (for preserving unchanged ciphertext on save),
/// the decrypted murk, and the identity.
pub fn load_vault(
    vault_path: &str,
) -> Result<(types::Vault, types::Murk, age::x25519::Identity), String> {
    let path = Path::new(vault_path);
    let secret_key = resolve_key()?;

    let identity =
        crypto::parse_identity(secret_key.expose_secret()).map_err(|e| {
            format!("invalid MURK_KEY (expected AGE-SECRET-KEY-1...): {e}. Run `murk restore` to recover from your 24-word phrase")
        })?;

    let vault = vault::read(path).map_err(|e| e.to_string())?;
    let pubkey = identity.to_public().to_string();

    // Decrypt shared values.
    let mut values = HashMap::new();
    for (key, entry) in &vault.secrets {
        let plaintext = decrypt_value(&entry.shared, &identity).map_err(|_| {
            "decryption failed — your MURK_KEY may not be a recipient of this vault. Check with `murk recipients`".to_string()
        })?;
        let value = String::from_utf8(plaintext)
            .map_err(|e| format!("invalid UTF-8 in secret {key}: {e}"))?;
        values.insert(key.clone(), value);
    }

    // Decrypt our own scoped (mote) values.
    let mut scoped = HashMap::new();
    for (key, entry) in &vault.secrets {
        if let Some(encoded) = entry.scoped.get(&pubkey) {
            if let Ok(plaintext) = decrypt_value(encoded, &identity) {
                if let Ok(value) = String::from_utf8(plaintext) {
                    scoped
                        .entry(key.clone())
                        .or_insert_with(HashMap::new)
                        .insert(pubkey.clone(), value);
                }
            }
        }
    }

    // Decrypt meta for recipient names.
    let recipients = if vault.meta.is_empty() {
        HashMap::new()
    } else if let Ok(plaintext) = decrypt_value(&vault.meta, &identity) {
        let meta: types::Meta =
            serde_json::from_slice(&plaintext).unwrap_or_else(|_| types::Meta {
                recipients: HashMap::new(),
                mac: String::new(),
            });
        meta.recipients
    } else {
        HashMap::new()
    };

    let murk = types::Murk {
        values,
        recipients,
        scoped,
    };

    Ok((vault, murk, identity))
}

/// Save the vault: compare against original state and only re-encrypt changed values.
/// Unchanged values keep their original ciphertext for minimal git diffs.
pub fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), String> {
    let recipients: Vec<age::x25519::Recipient> = vault
        .recipients
        .iter()
        .map(|pk| crypto::parse_recipient(pk).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    // Check if recipient list changed — forces full re-encryption of shared values.
    // Compare current vault.recipients against the original meta recipients (which
    // reflects the recipient list at load time). If they differ, re-encrypt everything.
    let recipients_changed = {
        let mut current_pks: Vec<&str> = vault.recipients.iter().map(String::as_str).collect();
        let mut original_pks: Vec<&str> = original.recipients.keys().map(String::as_str).collect();
        current_pks.sort_unstable();
        original_pks.sort_unstable();
        current_pks != original_pks
    };

    let mut new_secrets = std::collections::BTreeMap::new();

    for (key, value) in &current.values {
        // Determine shared ciphertext.
        let shared = if !recipients_changed && original.values.get(key) == Some(value) {
            // Value unchanged and recipients unchanged — keep original ciphertext.
            if let Some(existing) = vault.secrets.get(key) {
                existing.shared.clone()
            } else {
                encrypt_value(value.as_bytes(), &recipients)?
            }
        } else {
            encrypt_value(value.as_bytes(), &recipients)?
        };

        // Handle scoped (mote) entries.
        // Start with existing scoped entries from the vault (includes other recipients' entries).
        let mut scoped = vault
            .secrets
            .get(key)
            .map(|e| e.scoped.clone())
            .unwrap_or_default();

        // Update/add/remove entries for recipients in current.scoped.
        if let Some(key_scoped) = current.scoped.get(key) {
            for (pk, val) in key_scoped {
                let original_val = original.scoped.get(key).and_then(|m| m.get(pk));
                if original_val == Some(val) {
                    // Unchanged — keep original ciphertext (already in scoped from vault).
                } else {
                    // Changed or new — re-encrypt to this recipient only.
                    let recipient = crypto::parse_recipient(pk).map_err(|e| e.to_string())?;
                    scoped.insert(pk.clone(), encrypt_value(val.as_bytes(), &[recipient])?);
                }
            }
        }

        // Remove scoped entries for pubkeys no longer in current.scoped for this key.
        // But only for pubkeys we can see (our own). Others' entries are preserved.
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

    // Remove secrets that were deleted (in original but not in current).
    // (They simply won't be in new_secrets.)

    vault.secrets = new_secrets;

    // Update meta.
    let mac = compute_mac(vault);
    let meta = types::Meta {
        recipients: current.recipients.clone(),
        mac,
    };
    let meta_json = serde_json::to_vec(&meta).map_err(|e| e.to_string())?;
    vault.meta = encrypt_value(&meta_json, &recipients)?;

    vault::write(Path::new(vault_path), vault).map_err(|e| e.to_string())
}

/// Compute an integrity MAC over the vault's secrets and schema.
/// Covers: sorted key names, encrypted shared values, recipient pubkeys.
fn compute_mac(vault: &types::Vault) -> String {
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
        "sha256:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        })
    )
}

/// Generate an ISO-8601 UTC timestamp.
pub fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn generate_keypair() -> (String, String) {
        let identity = age::x25519::Identity::generate();
        let secret = identity.to_string();
        let pubkey = identity.to_public().to_string();
        (secret.expose_secret().to_string(), pubkey)
    }

    fn make_recipient(pubkey: &str) -> age::x25519::Recipient {
        crypto::parse_recipient(pubkey).unwrap()
    }

    fn make_identity(secret: &str) -> age::x25519::Identity {
        crypto::parse_identity(secret).unwrap()
    }

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
        assert!(result.unwrap_err().contains("invalid base64"));
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
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let mac1 = compute_mac(&vault);
        let mac2 = compute_mac(&vault);
        assert_eq!(mac1, mac2);
        assert!(mac1.starts_with("sha256:"));
    }

    #[test]
    fn compute_mac_changes_with_different_secrets() {
        let mut vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let mac_empty = compute_mac(&vault);

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                scoped: BTreeMap::new(),
            },
        );

        let mac_with_secret = compute_mac(&vault);
        assert_ne!(mac_empty, mac_with_secret);
    }

    #[test]
    fn compute_mac_changes_with_different_recipients() {
        let mut vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let mac1 = compute_mac(&vault);
        vault.recipients.push("age1xyz".into());
        let mac2 = compute_mac(&vault);
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

        // Build a vault with one secret.
        let shared = encrypt_value(b"original", &[recipient.clone()]).unwrap();
        let mut vault = types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
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
        };

        // Save with same values — ciphertext should be preserved.
        let current = original.clone();
        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        // The shared ciphertext for KEY1 should be the same as the original.
        assert_eq!(vault.secrets["KEY1"].shared, shared);

        // Now change the value — ciphertext should differ.
        let mut changed = current.clone();
        changed.values.insert("KEY1".into(), "modified".into());
        save_vault(path.to_str().unwrap(), &mut vault, &original, &changed).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        // Verify the new ciphertext decrypts to the changed value.
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
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
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
        };

        // Add a second secret.
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
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
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
        };

        // Remove KEY2.
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
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
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

        // Original only had pubkey1 as recipient.
        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey1.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: recipients_map,
            scoped: HashMap::new(),
        };

        // Current is the same values — but vault.recipients now has pubkey2 too.
        let mut current_recipients = HashMap::new();
        current_recipients.insert(pubkey1.clone(), "alice".into());
        current_recipients.insert(pubkey2.clone(), "bob".into());
        let current = types::Murk {
            values: HashMap::from([("KEY1".into(), "val1".into())]),
            recipients: current_recipients,
            scoped: HashMap::new(),
        };

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        // Ciphertext must change because recipients changed.
        assert_ne!(vault.secrets["KEY1"].shared, shared);

        // Both recipients can decrypt.
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
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
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
        };

        // Add a scoped override.
        let mut current = original.clone();
        let mut key_scoped = HashMap::new();
        key_scoped.insert(pubkey.clone(), "my_override".into());
        current.scoped.insert("KEY1".into(), key_scoped);

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        // Scoped entry should exist.
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

        // Scoped entry should be gone.
        assert!(vault.secrets["KEY1"].scoped.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn now_utc_format() {
        let ts = now_utc();
        // Should be ISO-8601 format: YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}

/// Warn if `.env` has loose permissions (Unix only).
pub fn warn_env_permissions() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let env_path = Path::new(".env");
        if env_path.exists()
            && let Ok(meta) = fs::metadata(env_path)
        {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "\x1b[1;33mwarning:\x1b[0m .env is readable by others (mode {:o}). Run: \x1b[1mchmod 600 .env\x1b[0m",
                    mode & 0o777
                );
            }
        }
    }
}
