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

use std::env;
use std::fs;
use std::path::Path;

use age::secrecy::{ExposeSecret, SecretString};

/// Try to decrypt a personal mote for the given pubkey.
/// Returns None if no mote exists or decryption fails.
pub fn decrypt_mote(
    murk: &types::Murk,
    pubkey: &str,
    identity: &age::x25519::Identity,
) -> Option<types::Mote> {
    let encrypted_mote = murk.motes.get(pubkey)?;
    let mote_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_mote).ok()?;
    let plaintext = crypto::decrypt(&mote_bytes, identity).ok()?;
    serde_json::from_slice(&plaintext).ok()
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

/// Load the vault: read the file, decrypt the shared blob, return all parts.
pub fn load_vault(
    vault: &str,
) -> Result<(types::Header, types::Murk, age::x25519::Identity), String> {
    let path = Path::new(vault);
    let secret_key = resolve_key()?;

    let identity =
        crypto::parse_identity(secret_key.expose_secret()).map_err(|e| {
            format!("invalid MURK_KEY (expected AGE-SECRET-KEY-1...): {e}. Run `murk restore` to recover from your 24-word phrase")
        })?;

    let (header, encrypted) = vault::read(path).map_err(|e| e.to_string())?;

    let plaintext =
        crypto::decrypt(&encrypted, &identity).map_err(|_| {
            "decryption failed — your MURK_KEY may not be a recipient of this vault. Check with `murk recipients`".to_string()
        })?;

    let murk: types::Murk =
        serde_json::from_slice(&plaintext).map_err(|e| format!("invalid vault data: {e}"))?;

    Ok((header, murk, identity))
}

/// Re-encrypt the shared blob and write the vault back to disk.
pub fn save_vault(
    vault: &str,
    header: &mut types::Header,
    murk: &types::Murk,
) -> Result<(), String> {
    let murk_json = serde_json::to_vec(murk).map_err(|e| e.to_string())?;

    let recipients: Vec<age::x25519::Recipient> = header
        .recipients
        .iter()
        .map(|pk| crypto::parse_recipient(pk).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    let encrypted = crypto::encrypt(&murk_json, &recipients).map_err(|e| e.to_string())?;

    header.murk_hash = integrity::hash(&encrypted);

    vault::write(Path::new(vault), header, &encrypted).map_err(|e| e.to_string())
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
