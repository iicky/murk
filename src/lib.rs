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
    clippy::unreadable_literal,
    clippy::too_many_arguments,
    clippy::implicit_hasher
)]

pub mod crypto;
pub mod integrity;
pub mod recovery;
pub mod types;
pub mod vault;

use std::collections::{BTreeMap, HashMap};
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

// ── Command logic (extracted from main.rs for testability) ──

/// Keys to skip when importing from a .env file.
const IMPORT_SKIP: &[&str] = &["MURK_KEY", "MURK_KEY_FILE", "MURK_VAULT"];

/// Parse a .env file into key-value pairs.
/// Skips comments, blank lines, `MURK_*` keys, and strips quotes and `export` prefixes.
pub fn parse_env(contents: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();

    for line in contents.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        // Strip surrounding quotes.
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);

        if key.is_empty() || IMPORT_SKIP.contains(&key) {
            continue;
        }

        pairs.push((key.into(), value.into()));
    }

    pairs
}

/// Add or update a secret in the working state.
/// If `private` is true, stores in scoped (encrypted to self only).
/// Returns true if the key was new (no existing schema entry).
pub fn add_secret(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    key: &str,
    value: &str,
    desc: Option<&str>,
    private: bool,
    tags: &[String],
    identity: &age::x25519::Identity,
) -> bool {
    if private {
        let pubkey = identity.to_public().to_string();
        murk.scoped
            .entry(key.into())
            .or_default()
            .insert(pubkey, value.into());
    } else {
        murk.values.insert(key.into(), value.into());
    }

    let is_new = !vault.schema.contains_key(key);

    if let Some(entry) = vault.schema.get_mut(key) {
        if let Some(d) = desc {
            entry.description = d.into();
        }
        if !tags.is_empty() {
            for t in tags {
                if !entry.tags.contains(t) {
                    entry.tags.push(t.clone());
                }
            }
        }
    } else {
        vault.schema.insert(
            key.into(),
            types::SchemaEntry {
                description: desc.unwrap_or("").into(),
                example: None,
                tags: tags.to_vec(),
            },
        );
    }

    is_new && desc.is_none()
}

/// Remove a secret from the working state and schema.
pub fn remove_secret(vault: &mut types::Vault, murk: &mut types::Murk, key: &str) {
    murk.values.remove(key);
    murk.scoped.remove(key);
    vault.schema.remove(key);
}

/// Look up a decrypted value. Scoped overrides take priority over shared values.
pub fn get_secret<'a>(murk: &'a types::Murk, key: &str, pubkey: &str) -> Option<&'a str> {
    if let Some(value) = murk.scoped.get(key).and_then(|m| m.get(pubkey)) {
        return Some(value.as_str());
    }
    murk.values.get(key).map(String::as_str)
}

/// Return key names from the vault schema, optionally filtered by tags.
pub fn list_keys<'a>(vault: &'a types::Vault, tags: &[String]) -> Vec<&'a str> {
    vault
        .schema
        .iter()
        .filter(|(_, entry)| tags.is_empty() || entry.tags.iter().any(|t| tags.contains(t)))
        .map(|(key, _)| key.as_str())
        .collect()
}

/// Update or create a schema entry for a key.
pub fn describe_key(
    vault: &mut types::Vault,
    key: &str,
    description: &str,
    example: Option<&str>,
    tags: &[String],
) {
    if let Some(entry) = vault.schema.get_mut(key) {
        entry.description = description.into();
        entry.example = example.map(Into::into);
        if !tags.is_empty() {
            entry.tags = tags.to_vec();
        }
    } else {
        vault.schema.insert(
            key.into(),
            types::SchemaEntry {
                description: description.into(),
                example: example.map(Into::into),
                tags: tags.to_vec(),
            },
        );
    }
}

/// Build export key-value pairs: merge scoped overrides over shared values,
/// filter by tag, and shell-escape values (single-quote wrapping).
pub fn export_secrets(
    vault: &types::Vault,
    murk: &types::Murk,
    pubkey: &str,
    tags: &[String],
) -> BTreeMap<String, String> {
    let mut values = murk.values.clone();

    // Apply scoped overrides.
    for (key, scoped_map) in &murk.scoped {
        if let Some(value) = scoped_map.get(pubkey) {
            values.insert(key.clone(), value.clone());
        }
    }

    // Filter by tag.
    let allowed_keys: Option<std::collections::HashSet<&str>> = if tags.is_empty() {
        None
    } else {
        Some(
            vault
                .schema
                .iter()
                .filter(|(_, e)| e.tags.iter().any(|t| tags.contains(t)))
                .map(|(k, _)| k.as_str())
                .collect(),
        )
    };

    let mut result = BTreeMap::new();
    for (k, v) in &values {
        if let Some(ref allowed) = allowed_keys {
            if !allowed.contains(k.as_str()) {
                continue;
            }
        }
        // Shell-escape: wrap in single quotes, escape embedded single quotes.
        let escaped = v.replace('\'', "'\\''");
        result.insert(k.clone(), escaped);
    }
    result
}

/// The kind of change in a diff entry.
#[derive(Debug, PartialEq, Eq)]
pub enum DiffKind {
    Added,
    Removed,
    Changed,
}

/// A single entry in a secret diff.
#[derive(Debug)]
pub struct DiffEntry {
    pub key: String,
    pub kind: DiffKind,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Compare two sets of secret values and return the differences.
pub fn diff_secrets(
    old: &HashMap<String, String>,
    new: &HashMap<String, String>,
) -> Vec<DiffEntry> {
    let mut all_keys: Vec<&str> = old
        .keys()
        .chain(new.keys())
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    all_keys.sort_unstable();

    let mut entries = Vec::new();
    for key in all_keys {
        match (old.get(key), new.get(key)) {
            (None, Some(v)) => entries.push(DiffEntry {
                key: key.into(),
                kind: DiffKind::Added,
                old_value: None,
                new_value: Some(v.clone()),
            }),
            (Some(v), None) => entries.push(DiffEntry {
                key: key.into(),
                kind: DiffKind::Removed,
                old_value: Some(v.clone()),
                new_value: None,
            }),
            (Some(old_v), Some(new_v)) if old_v != new_v => entries.push(DiffEntry {
                key: key.into(),
                kind: DiffKind::Changed,
                old_value: Some(old_v.clone()),
                new_value: Some(new_v.clone()),
            }),
            _ => {}
        }
    }
    entries
}

/// Add a recipient to the vault. Returns an error if the pubkey is invalid or already present.
pub fn authorize_recipient(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    pubkey: &str,
    name: Option<&str>,
) -> Result<(), String> {
    if crypto::parse_recipient(pubkey).is_err() {
        return Err(format!("invalid public key: {pubkey}"));
    }

    if vault.recipients.contains(&pubkey.to_string()) {
        return Err(format!("{pubkey} is already a recipient"));
    }

    vault.recipients.push(pubkey.into());

    if let Some(n) = name {
        murk.recipients.insert(pubkey.into(), n.into());
    }

    Ok(())
}

/// Result of revoking a recipient.
#[derive(Debug)]
pub struct RevokeResult {
    /// The display name of the revoked recipient, if known.
    pub display_name: Option<String>,
    /// Keys the revoked recipient had access to (for rotation warnings).
    pub exposed_keys: Vec<String>,
}

/// Remove a recipient from the vault. `recipient` can be a pubkey or a display name.
/// Returns an error if the recipient is not found or is the last one.
pub fn revoke_recipient(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    recipient: &str,
) -> Result<RevokeResult, String> {
    // Resolve to pubkey.
    let pubkey = if vault.recipients.contains(&recipient.to_string()) {
        recipient.to_string()
    } else {
        murk.recipients
            .iter()
            .find(|(_, name)| name.as_str() == recipient)
            .map(|(pk, _)| pk.clone())
            .ok_or_else(|| format!("recipient not found: {recipient}"))?
    };

    if vault.recipients.len() == 1 {
        return Err(
            "cannot revoke last recipient — vault would become permanently inaccessible".into(),
        );
    }

    vault.recipients.retain(|pk| pk != &pubkey);

    let display_name = murk.recipients.remove(&pubkey);

    // Remove their scoped entries.
    for scoped_map in murk.scoped.values_mut() {
        scoped_map.remove(&pubkey);
    }
    for entry in vault.secrets.values_mut() {
        entry.scoped.remove(&pubkey);
    }

    let exposed_keys = vault.schema.keys().cloned().collect();

    Ok(RevokeResult {
        display_name,
        exposed_keys,
    })
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

    // ── parse_env tests ──

    #[test]
    fn parse_env_empty() {
        assert!(parse_env("").is_empty());
    }

    #[test]
    fn parse_env_comments_and_blanks() {
        let input = "# comment\n\n  # another\n";
        assert!(parse_env(input).is_empty());
    }

    #[test]
    fn parse_env_basic() {
        let input = "FOO=bar\nBAZ=qux\n";
        let pairs = parse_env(input);
        assert_eq!(
            pairs,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into())]
        );
    }

    #[test]
    fn parse_env_double_quotes() {
        let pairs = parse_env("KEY=\"hello world\"\n");
        assert_eq!(pairs, vec![("KEY".into(), "hello world".into())]);
    }

    #[test]
    fn parse_env_single_quotes() {
        let pairs = parse_env("KEY='hello world'\n");
        assert_eq!(pairs, vec![("KEY".into(), "hello world".into())]);
    }

    #[test]
    fn parse_env_export_prefix() {
        let pairs = parse_env("export FOO=bar\n");
        assert_eq!(pairs, vec![("FOO".into(), "bar".into())]);
    }

    #[test]
    fn parse_env_skips_murk_keys() {
        let input = "MURK_KEY=secret\nMURK_KEY_FILE=/path\nMURK_VAULT=.murk\nKEEP=yes\n";
        let pairs = parse_env(input);
        assert_eq!(pairs, vec![("KEEP".into(), "yes".into())]);
    }

    #[test]
    fn parse_env_equals_in_value() {
        let pairs = parse_env("URL=postgres://host?opt=1\n");
        assert_eq!(pairs, vec![("URL".into(), "postgres://host?opt=1".into())]);
    }

    #[test]
    fn parse_env_no_equals_skipped() {
        let pairs = parse_env("not-a-valid-line\nKEY=val\n");
        assert_eq!(pairs, vec![("KEY".into(), "val".into())]);
    }

    // ── add_secret tests ──

    fn empty_vault() -> types::Vault {
        types::Vault {
            version: "2.0".into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            recipients: vec![],
            schema: BTreeMap::new(),
            secrets: BTreeMap::new(),
            meta: String::new(),
        }
    }

    fn empty_murk() -> types::Murk {
        types::Murk {
            values: HashMap::new(),
            recipients: HashMap::new(),
            scoped: HashMap::new(),
        }
    }

    #[test]
    fn add_secret_shared() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let needs_hint = add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "value",
            None,
            false,
            &[],
            &identity,
        );

        assert!(needs_hint); // new key, no desc
        assert_eq!(murk.values["KEY"], "value");
        assert!(vault.schema.contains_key("KEY"));
        assert!(vault.schema["KEY"].description.is_empty());
    }

    #[test]
    fn add_secret_with_description() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let needs_hint = add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "value",
            Some("a desc"),
            false,
            &[],
            &identity,
        );

        assert!(!needs_hint); // has desc
        assert_eq!(vault.schema["KEY"].description, "a desc");
    }

    #[test]
    fn add_secret_private() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "private_val",
            None,
            true,
            &[],
            &identity,
        );

        assert!(!murk.values.contains_key("KEY")); // not in shared
        assert_eq!(murk.scoped["KEY"][&pubkey], "private_val");
    }

    #[test]
    fn add_secret_merges_tags() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let tags1 = vec!["db".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v1", None, false, &tags1, &identity,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db"]);

        // Add again with another tag — should merge, not replace.
        let tags2 = vec!["backend".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v2", None, false, &tags2, &identity,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db", "backend"]);

        // Adding duplicate tag should not create duplicates.
        let tags3 = vec!["db".into()];
        add_secret(
            &mut vault, &mut murk, "KEY", "v3", None, false, &tags3, &identity,
        );
        assert_eq!(vault.schema["KEY"].tags, vec!["db", "backend"]);
    }

    #[test]
    fn add_secret_updates_existing_desc() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "v1",
            Some("old"),
            false,
            &[],
            &identity,
        );
        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "v2",
            Some("new"),
            false,
            &[],
            &identity,
        );
        assert_eq!(vault.schema["KEY"].description, "new");
    }

    // ── remove_secret tests ──

    #[test]
    fn remove_secret_clears_all() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "desc".into(),
                example: None,
                tags: vec![],
            },
        );
        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), "val".into());
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), "scoped_val".into());
        murk.scoped.insert("KEY".into(), scoped);

        remove_secret(&mut vault, &mut murk, "KEY");

        assert!(!murk.values.contains_key("KEY"));
        assert!(!murk.scoped.contains_key("KEY"));
        assert!(!vault.schema.contains_key("KEY"));
    }

    // ── get_secret tests ──

    #[test]
    fn get_secret_shared_value() {
        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), "shared_val".into());

        assert_eq!(get_secret(&murk, "KEY", "age1pk"), Some("shared_val"));
    }

    #[test]
    fn get_secret_scoped_overrides_shared() {
        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), "shared_val".into());
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), "scoped_val".into());
        murk.scoped.insert("KEY".into(), scoped);

        assert_eq!(get_secret(&murk, "KEY", "age1pk"), Some("scoped_val"));
    }

    #[test]
    fn get_secret_missing_returns_none() {
        let murk = empty_murk();
        assert_eq!(get_secret(&murk, "NONEXISTENT", "age1pk"), None);
    }

    // ── list_keys tests ──

    #[test]
    fn list_keys_no_filter() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );

        let keys = list_keys(&vault, &[]);
        assert_eq!(keys, vec!["A", "B"]);
    }

    #[test]
    fn list_keys_with_tag_filter() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["db".into()],
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["api".into()],
            },
        );
        vault.schema.insert(
            "C".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );

        let keys = list_keys(&vault, &["db".into()]);
        assert_eq!(keys, vec!["A"]);
    }

    #[test]
    fn list_keys_no_matches() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["db".into()],
            },
        );

        let keys = list_keys(&vault, &["nonexistent".into()]);
        assert!(keys.is_empty());
    }

    // ── describe_key tests ──

    #[test]
    fn describe_key_creates_new() {
        let mut vault = empty_vault();
        describe_key(
            &mut vault,
            "KEY",
            "a description",
            Some("example"),
            &["tag".into()],
        );

        assert_eq!(vault.schema["KEY"].description, "a description");
        assert_eq!(vault.schema["KEY"].example.as_deref(), Some("example"));
        assert_eq!(vault.schema["KEY"].tags, vec!["tag"]);
    }

    #[test]
    fn describe_key_updates_existing() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "old".into(),
                example: Some("old_ex".into()),
                tags: vec!["old_tag".into()],
            },
        );

        describe_key(&mut vault, "KEY", "new", None, &["new_tag".into()]);

        assert_eq!(vault.schema["KEY"].description, "new");
        assert_eq!(vault.schema["KEY"].example, None);
        assert_eq!(vault.schema["KEY"].tags, vec!["new_tag"]);
    }

    #[test]
    fn describe_key_preserves_tags_if_empty() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "old".into(),
                example: None,
                tags: vec!["keep".into()],
            },
        );

        describe_key(&mut vault, "KEY", "new desc", None, &[]);

        assert_eq!(vault.schema["KEY"].tags, vec!["keep"]);
    }

    // ── export_secrets tests ──

    #[test]
    fn export_secrets_basic() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "FOO".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("FOO".into(), "bar".into());

        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports["FOO"], "bar");
    }

    #[test]
    fn export_secrets_scoped_override() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), "shared".into());
        let mut scoped = HashMap::new();
        scoped.insert("age1pk".into(), "override".into());
        murk.scoped.insert("KEY".into(), scoped);

        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(exports["KEY"], "override");
    }

    #[test]
    fn export_secrets_tag_filter() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["db".into()],
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["api".into()],
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("A".into(), "val_a".into());
        murk.values.insert("B".into(), "val_b".into());

        let exports = export_secrets(&vault, &murk, "age1pk", &["db".into()]);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports["A"], "val_a");
    }

    #[test]
    fn export_secrets_shell_escaping() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );

        let mut murk = empty_murk();
        murk.values.insert("KEY".into(), "it's a test".into());

        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(exports["KEY"], "it'\\''s a test");
    }

    // ── diff_secrets tests ──

    #[test]
    fn diff_secrets_no_changes() {
        let old = HashMap::from([("K".into(), "V".into())]);
        let new = old.clone();
        assert!(diff_secrets(&old, &new).is_empty());
    }

    #[test]
    fn diff_secrets_added() {
        let old = HashMap::new();
        let new = HashMap::from([("KEY".into(), "val".into())]);
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Added);
        assert_eq!(entries[0].key, "KEY");
        assert_eq!(entries[0].new_value.as_deref(), Some("val"));
    }

    #[test]
    fn diff_secrets_removed() {
        let old = HashMap::from([("KEY".into(), "val".into())]);
        let new = HashMap::new();
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Removed);
        assert_eq!(entries[0].old_value.as_deref(), Some("val"));
    }

    #[test]
    fn diff_secrets_changed() {
        let old = HashMap::from([("KEY".into(), "old_val".into())]);
        let new = HashMap::from([("KEY".into(), "new_val".into())]);
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, DiffKind::Changed);
        assert_eq!(entries[0].old_value.as_deref(), Some("old_val"));
        assert_eq!(entries[0].new_value.as_deref(), Some("new_val"));
    }

    #[test]
    fn diff_secrets_mixed() {
        let old = HashMap::from([
            ("KEEP".into(), "same".into()),
            ("REMOVE".into(), "gone".into()),
            ("CHANGE".into(), "old".into()),
        ]);
        let new = HashMap::from([
            ("KEEP".into(), "same".into()),
            ("ADD".into(), "new".into()),
            ("CHANGE".into(), "new".into()),
        ]);
        let entries = diff_secrets(&old, &new);
        assert_eq!(entries.len(), 3); // ADD, CHANGE, REMOVE

        let kinds: Vec<&DiffKind> = entries.iter().map(|e| &e.kind).collect();
        assert!(kinds.contains(&&DiffKind::Added));
        assert!(kinds.contains(&&DiffKind::Removed));
        assert!(kinds.contains(&&DiffKind::Changed));
    }

    #[test]
    fn diff_secrets_sorted_by_key() {
        let old = HashMap::new();
        let new = HashMap::from([
            ("Z".into(), "z".into()),
            ("A".into(), "a".into()),
            ("M".into(), "m".into()),
        ]);
        let entries = diff_secrets(&old, &new);
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["A", "M", "Z"]);
    }

    // ── authorize_recipient tests ──

    #[test]
    fn authorize_recipient_success() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let result = authorize_recipient(&mut vault, &mut murk, &pubkey, Some("alice"));
        assert!(result.is_ok());
        assert!(vault.recipients.contains(&pubkey));
        assert_eq!(murk.recipients[&pubkey], "alice");
    }

    #[test]
    fn authorize_recipient_no_name() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        authorize_recipient(&mut vault, &mut murk, &pubkey, None).unwrap();
        assert!(vault.recipients.contains(&pubkey));
        assert!(!murk.recipients.contains_key(&pubkey));
    }

    #[test]
    fn authorize_recipient_duplicate_fails() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients.push(pubkey.clone());
        let mut murk = empty_murk();

        let result = authorize_recipient(&mut vault, &mut murk, &pubkey, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already a recipient"));
    }

    #[test]
    fn authorize_recipient_invalid_key_fails() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let result = authorize_recipient(&mut vault, &mut murk, "not-a-valid-key", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid public key"));
    }

    // ── revoke_recipient tests ──

    #[test]
    fn revoke_recipient_by_pubkey() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
            },
        );
        let mut murk = empty_murk();
        murk.recipients.insert(pk2.clone(), "bob".into());

        let result = revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();
        assert_eq!(result.display_name.as_deref(), Some("bob"));
        assert!(!vault.recipients.contains(&pk2));
        assert!(vault.recipients.contains(&pk1));
        assert_eq!(result.exposed_keys, vec!["KEY"]);
    }

    #[test]
    fn revoke_recipient_by_name() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        let mut murk = empty_murk();
        murk.recipients.insert(pk2.clone(), "bob".into());

        let result = revoke_recipient(&mut vault, &mut murk, "bob").unwrap();
        assert_eq!(result.display_name.as_deref(), Some("bob"));
        assert!(!vault.recipients.contains(&pk2));
    }

    #[test]
    fn revoke_recipient_last_fails() {
        let (_, pk) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk.clone()];
        let mut murk = empty_murk();

        let result = revoke_recipient(&mut vault, &mut murk, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot revoke last recipient"));
    }

    #[test]
    fn revoke_recipient_unknown_fails() {
        let (_, pk) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk.clone()];
        let mut murk = empty_murk();

        let result = revoke_recipient(&mut vault, &mut murk, "nobody");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("recipient not found"));
    }

    #[test]
    fn revoke_recipient_removes_scoped() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ct".into(),
                scoped: BTreeMap::from([(pk2.clone(), "scoped_ct".into())]),
            },
        );
        let mut murk = empty_murk();
        let mut scoped = HashMap::new();
        scoped.insert(pk2.clone(), "scoped_val".into());
        murk.scoped.insert("KEY".into(), scoped);

        revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();

        // Scoped entries should be cleaned up in both vault and murk.
        assert!(vault.secrets["KEY"].scoped.is_empty());
        assert!(murk.scoped["KEY"].is_empty());
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
