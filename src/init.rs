//! Vault initialization logic.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::process::Command;

use crate::{crypto, encrypt_value, now_utc, types};

/// A key discovered from the environment or .env file.
#[derive(Debug)]
pub struct DiscoveredKey {
    pub secret_key: String,
    pub pubkey: String,
}

/// Try to find an existing age key: checks `MURK_KEY` env var first,
/// then falls back to `.env` file. Returns `None` if neither is set.
pub fn discover_existing_key() -> Result<Option<DiscoveredKey>, String> {
    let raw = env::var(crate::env::ENV_MURK_KEY)
        .ok()
        .filter(|k| !k.is_empty())
        .or_else(crate::read_key_from_dotenv);

    match raw {
        Some(key) => {
            let identity = crypto::parse_identity(&key).map_err(|e| e.to_string())?;
            let pubkey = identity.pubkey_string().map_err(|e| e.to_string())?;
            Ok(Some(DiscoveredKey {
                secret_key: key,
                pubkey,
            }))
        }
        None => Ok(None),
    }
}

/// Status of an existing vault relative to a given key.
#[derive(Debug)]
pub struct InitStatus {
    /// Whether the key's pubkey is in the vault's recipient list.
    pub authorized: bool,
    /// The public key derived from the secret key.
    pub pubkey: String,
    /// Display name from encrypted meta, if decryptable and present.
    pub display_name: Option<String>,
}

/// Check whether a secret key is authorized in an existing vault.
///
/// Parses the identity from `secret_key`, checks the recipient list, and
/// attempts to decrypt meta for the display name.
pub fn check_init_status(vault: &types::Vault, secret_key: &str) -> Result<InitStatus, String> {
    let identity = crypto::parse_identity(secret_key).map_err(|e| e.to_string())?;
    let pubkey = identity.pubkey_string().map_err(|e| e.to_string())?;
    let authorized = vault.recipients.contains(&pubkey);

    let display_name = if authorized {
        crate::decrypt_meta(vault, &identity)
            .and_then(|meta| meta.recipients.get(&pubkey).cloned())
            .filter(|name| !name.is_empty())
    } else {
        None
    };

    Ok(InitStatus {
        authorized,
        pubkey,
        display_name,
    })
}

/// Create a new vault with a single recipient.
///
/// Detects the git remote URL and builds the initial vault struct.
/// The caller is responsible for writing the vault to disk via `vault::write`.
pub fn create_vault(
    vault_name: &str,
    pubkey: &str,
    name: &str,
) -> Result<types::Vault, crate::error::MurkError> {
    use crate::error::MurkError;

    let mut recipient_names = HashMap::new();
    recipient_names.insert(pubkey.to_string(), name.to_string());

    let recipient = crypto::parse_recipient(pubkey)?;

    // Detect git repo URL.
    let repo = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let mut vault = types::Vault {
        version: types::VAULT_VERSION.into(),
        created: now_utc(),
        vault_name: vault_name.into(),
        repo,
        recipients: vec![pubkey.to_string()],
        schema: BTreeMap::new(),
        secrets: BTreeMap::new(),
        meta: String::new(),
    };

    let hmac_key_hex = crate::generate_hmac_key();
    let hmac_key = crate::decode_hmac_key(&hmac_key_hex).unwrap();
    let mac = crate::compute_mac(&vault, Some(&hmac_key));
    let meta = types::Meta {
        recipients: recipient_names,
        mac,
        hmac_key: Some(hmac_key_hex),
    };
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &[recipient])?;

    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::sync::Mutex;

    /// Tests that mutate MURK_KEY env var must hold this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // ── discover_existing_key tests ──

    #[test]
    fn discover_existing_key_from_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (secret, pubkey) = generate_keypair();
        unsafe { env::set_var("MURK_KEY", &secret) };
        let result = discover_existing_key();
        unsafe { env::remove_var("MURK_KEY") };

        let dk = result.unwrap().unwrap();
        assert_eq!(dk.secret_key, secret);
        assert_eq!(dk.pubkey, pubkey);
    }

    #[test]
    fn discover_existing_key_from_dotenv() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("MURK_KEY") };

        // Create a temp .env in a temp dir and chdir there.
        let dir = std::env::temp_dir().join("murk_test_discover_dotenv");
        std::fs::create_dir_all(&dir).unwrap();
        let (secret, pubkey) = generate_keypair();
        std::fs::write(dir.join(".env"), format!("MURK_KEY={secret}\n")).unwrap();

        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = discover_existing_key();
        std::env::set_current_dir(&orig_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        let dk = result.unwrap().unwrap();
        assert_eq!(dk.secret_key, secret);
        assert_eq!(dk.pubkey, pubkey);
    }

    #[test]
    fn discover_existing_key_neither_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("MURK_KEY") };

        // Use a dir with no .env.
        let dir = std::env::temp_dir().join("murk_test_discover_none");
        std::fs::create_dir_all(&dir).unwrap();
        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = discover_existing_key();
        std::env::set_current_dir(&orig_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn discover_existing_key_invalid_key() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::set_var("MURK_KEY", "not-a-valid-age-key") };
        let result = discover_existing_key();
        unsafe { env::remove_var("MURK_KEY") };

        assert!(result.is_err());
    }

    // ── check_init_status tests ──

    #[test]
    fn check_init_status_authorized() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        // Build a vault with this recipient in the list and encrypted meta.
        let mut names = HashMap::new();
        names.insert(pubkey.clone(), "Alice".to_string());
        let meta = types::Meta {
            recipients: names,
            mac: String::new(),
            hmac_key: None,
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        let meta_enc = encrypt_value(&meta_json, &[recipient]).unwrap();

        let vault = types::Vault {
            version: "2.0".into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: std::collections::BTreeMap::new(),
            secrets: std::collections::BTreeMap::new(),
            meta: meta_enc,
        };

        let status = check_init_status(&vault, &secret).unwrap();
        assert!(status.authorized);
        assert_eq!(status.pubkey, pubkey);
        assert_eq!(status.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn check_init_status_not_authorized() {
        let (secret, pubkey) = generate_keypair();
        let (_, other_pubkey) = generate_keypair();

        let vault = types::Vault {
            version: "2.0".into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![other_pubkey],
            schema: std::collections::BTreeMap::new(),
            secrets: std::collections::BTreeMap::new(),
            meta: String::new(),
        };

        let status = check_init_status(&vault, &secret).unwrap();
        assert!(!status.authorized);
        assert_eq!(status.pubkey, pubkey);
        assert!(status.display_name.is_none());
    }

    #[test]
    fn create_vault_basic() {
        let (_, pubkey) = generate_keypair();

        let vault = create_vault(".murk", &pubkey, "Bob").unwrap();
        assert_eq!(vault.version, types::VAULT_VERSION);
        assert_eq!(vault.vault_name, ".murk");
        assert_eq!(vault.recipients, vec![pubkey]);
        assert!(vault.schema.is_empty());
        assert!(vault.secrets.is_empty());
        assert!(!vault.meta.is_empty());
    }
}
