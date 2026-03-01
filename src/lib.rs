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
