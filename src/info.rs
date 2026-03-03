//! Vault info/introspection logic.

use crate::{codename, types};

/// Number of pubkey characters to show when a display name is unavailable.
const PUBKEY_DISPLAY_LEN: usize = 12;

/// A single key entry in the vault info output.
#[derive(Debug)]
pub struct InfoEntry {
    pub key: String,
    pub description: String,
    pub example: Option<String>,
    pub tags: Vec<String>,
    /// Display names (or truncated pubkeys) of recipients with scoped overrides.
    pub scoped_recipients: Vec<String>,
}

/// Aggregated vault information for display.
#[derive(Debug)]
pub struct VaultInfo {
    pub vault_name: String,
    pub codename: String,
    pub repo: String,
    pub created: String,
    pub recipient_count: usize,
    pub entries: Vec<InfoEntry>,
}

/// Compute vault info from raw vault bytes.
///
/// `raw_bytes` is the full file contents (for codename computation).
/// `tags` filters entries by tag (empty = all).
/// `secret_key` enables meta decryption for scoped-recipient display names.
pub fn vault_info(
    raw_bytes: &[u8],
    tags: &[String],
    secret_key: Option<&str>,
) -> Result<VaultInfo, String> {
    let vault: types::Vault = serde_json::from_slice(raw_bytes).map_err(|e| e.to_string())?;

    let codename = codename::from_bytes(raw_bytes);

    // Filter by tag if specified.
    let filtered: Vec<(&String, &types::SchemaEntry)> = if tags.is_empty() {
        vault.schema.iter().collect()
    } else {
        vault
            .schema
            .iter()
            .filter(|(_, e)| e.tags.iter().any(|t| tags.contains(t)))
            .collect()
    };

    // Try to decrypt meta for recipient names.
    let meta_data = secret_key.and_then(|sk| {
        let identity = crate::crypto::parse_identity(sk).ok()?;
        crate::decrypt_meta(&vault, &identity)
    });

    let entries = filtered
        .iter()
        .map(|(key, entry)| {
            let scoped_recipients = if let Some(ref meta) = meta_data {
                vault
                    .secrets
                    .get(key.as_str())
                    .map(|s| {
                        s.scoped
                            .keys()
                            .map(|pk| {
                                meta.recipients.get(pk).cloned().unwrap_or_else(|| {
                                    pk.chars().take(PUBKEY_DISPLAY_LEN).collect::<String>()
                                        + "\u{2026}"
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            };

            InfoEntry {
                key: (*key).clone(),
                description: entry.description.clone(),
                example: entry.example.clone(),
                tags: entry.tags.clone(),
                scoped_recipients,
            }
        })
        .collect();

    Ok(VaultInfo {
        vault_name: vault.vault_name.clone(),
        codename,
        repo: vault.repo.clone(),
        created: vault.created.clone(),
        recipient_count: vault.recipients.len(),
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_vault_bytes(schema: BTreeMap<String, types::SchemaEntry>) -> Vec<u8> {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: "https://github.com/test/repo".into(),
            recipients: vec!["age1test".into()],
            schema,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        serde_json::to_vec(&vault).unwrap()
    }

    #[test]
    fn vault_info_basic() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DB_URL".into(),
            types::SchemaEntry {
                description: "database url".into(),
                example: Some("postgres://...".into()),
                tags: vec!["db".into()],
            },
        );
        let bytes = test_vault_bytes(schema);

        let info = vault_info(&bytes, &[], None).unwrap();
        assert_eq!(info.vault_name, ".murk");
        assert!(!info.codename.is_empty());
        assert_eq!(info.repo, "https://github.com/test/repo");
        assert_eq!(info.recipient_count, 1);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].key, "DB_URL");
        assert_eq!(info.entries[0].description, "database url");
        assert_eq!(info.entries[0].example.as_deref(), Some("postgres://..."));
    }

    #[test]
    fn vault_info_tag_filter() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DB_URL".into(),
            types::SchemaEntry {
                description: "db".into(),
                example: None,
                tags: vec!["db".into()],
            },
        );
        schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "api".into(),
                example: None,
                tags: vec!["api".into()],
            },
        );
        let bytes = test_vault_bytes(schema);

        let info = vault_info(&bytes, &["db".into()], None).unwrap();
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].key, "DB_URL");
    }

    #[test]
    fn vault_info_empty_schema() {
        let bytes = test_vault_bytes(BTreeMap::new());
        let info = vault_info(&bytes, &[], None).unwrap();
        assert!(info.entries.is_empty());
    }

    #[test]
    fn vault_info_invalid_json() {
        let result = vault_info(b"not json", &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn vault_info_valid_json_missing_fields() {
        // Valid JSON but not a vault — should fail deserialization.
        let result = vault_info(b"{\"foo\": \"bar\"}", &[], None);
        assert!(result.is_err());
    }
}
