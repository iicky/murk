//! Vault initialization logic.

use std::collections::{BTreeMap, HashMap};
use std::process::Command;

use crate::{crypto, decrypt_value, encrypt_value, now_utc, types};

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
    let pubkey = identity.to_public().to_string();
    let authorized = vault.recipients.contains(&pubkey);

    let display_name = if authorized {
        decrypt_value(&vault.meta, &identity)
            .ok()
            .and_then(|plaintext| serde_json::from_slice::<types::Meta>(&plaintext).ok())
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
pub fn create_vault(vault_name: &str, pubkey: &str, name: &str) -> Result<types::Vault, String> {
    // Build meta with the recipient name mapping.
    let mut recipient_names = HashMap::new();
    recipient_names.insert(pubkey.to_string(), name.to_string());

    let recipient = crypto::parse_recipient(pubkey).map_err(|e| e.to_string())?;
    let meta = types::Meta {
        recipients: recipient_names,
        mac: String::new(), // Will be computed by vault write.
    };
    let meta_json = serde_json::to_vec(&meta).map_err(|e| e.to_string())?;
    let meta_enc = encrypt_value(&meta_json, &[recipient])?;

    // Detect git repo URL.
    let repo = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    Ok(types::Vault {
        version: "2.0".into(),
        created: now_utc(),
        vault_name: vault_name.into(),
        repo,
        recipients: vec![pubkey.to_string()],
        schema: BTreeMap::new(),
        secrets: BTreeMap::new(),
        meta: meta_enc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

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
        assert_eq!(vault.version, "2.0");
        assert_eq!(vault.vault_name, ".murk");
        assert_eq!(vault.recipients, vec![pubkey]);
        assert!(vault.schema.is_empty());
        assert!(vault.secrets.is_empty());
        assert!(!vault.meta.is_empty());
    }
}
