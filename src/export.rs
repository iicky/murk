//! Export and diff logic for vault secrets.

use std::collections::{BTreeMap, HashMap};

use crate::types;

/// Merge scoped overrides over shared values and filter by tag.
/// Returns raw (unescaped) values suitable for env var injection.
pub fn resolve_secrets(
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
        if allowed_keys
            .as_ref()
            .is_some_and(|a| !a.contains(k.as_str()))
        {
            continue;
        }
        result.insert(k.clone(), v.clone());
    }
    result
}

/// Build shell-escaped export key-value pairs for `eval $(murk export)`.
/// Wraps values in single quotes with embedded quote escaping.
pub fn export_secrets(
    vault: &types::Vault,
    murk: &types::Murk,
    pubkey: &str,
    tags: &[String],
) -> BTreeMap<String, String> {
    resolve_secrets(vault, murk, pubkey, tags)
        .into_iter()
        .map(|(k, v)| (k, v.replace('\'', "'\\''")))
        .collect()
}

/// Decrypt all shared secret values from a vault.
///
/// Silently skips entries that fail to decrypt (the caller may not have been
/// a recipient at the time the vault was written). Returns a map of key → plaintext value.
pub fn decrypt_vault_values(
    vault: &types::Vault,
    identity: &crate::crypto::MurkIdentity,
) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for (key, entry) in &vault.secrets {
        if let Ok(value) = crate::decrypt_value(&entry.shared, identity)
            .and_then(|pt| String::from_utf8(pt).map_err(|e| e.to_string()))
        {
            values.insert(key.clone(), value);
        }
    }
    values
}

/// Parse a vault from its JSON string and decrypt all shared values.
///
/// Combines `vault::parse` with `decrypt_vault_values` for use cases
/// where the vault contents come from a string (e.g., `git show`).
pub fn parse_and_decrypt_values(
    vault_contents: &str,
    identity: &crate::crypto::MurkIdentity,
) -> Result<HashMap<String, String>, String> {
    let vault = crate::vault::parse(vault_contents).map_err(|e| e.to_string())?;
    Ok(decrypt_vault_values(&vault, identity))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::types;

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
        assert_eq!(entries.len(), 3);

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

    // ── resolve_secrets tests ──

    #[test]
    fn resolve_secrets_basic() {
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

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["FOO"], "bar");
    }

    #[test]
    fn resolve_secrets_no_escaping() {
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

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(resolved["KEY"], "it's a test");
    }

    #[test]
    fn resolve_secrets_scoped_override() {
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

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &[]);
        assert_eq!(resolved["KEY"], "override");
    }

    #[test]
    fn resolve_secrets_tag_filter() {
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

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &["db".into()]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["A"], "val_a");
    }

    #[test]
    fn resolve_secrets_tag_in_schema_but_no_secret() {
        let mut vault = empty_vault();
        // Schema says key "ORPHAN" exists with tag "db", but no secret value.
        vault.schema.insert(
            "ORPHAN".into(),
            types::SchemaEntry {
                description: "orphan key".into(),
                example: None,
                tags: vec!["db".into()],
            },
        );
        vault.schema.insert(
            "REAL".into(),
            types::SchemaEntry {
                description: "has a value".into(),
                example: None,
                tags: vec!["db".into()],
            },
        );

        let mut murk = empty_murk();
        // Only REAL has a value, ORPHAN does not.
        murk.values.insert("REAL".into(), "real_val".into());

        let resolved = resolve_secrets(&vault, &murk, "age1pk", &["db".into()]);
        // ORPHAN should not appear since it has no value.
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["REAL"], "real_val");
        assert!(!resolved.contains_key("ORPHAN"));
    }

    #[test]
    fn resolve_secrets_scoped_pubkey_not_in_recipients() {
        let mut vault = empty_vault();
        vault.recipients = vec!["age1alice".into()];
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
        // Scoped override for a pubkey NOT in vault.recipients.
        let mut scoped = HashMap::new();
        scoped.insert("age1outsider".into(), "outsider_val".into());
        murk.scoped.insert("KEY".into(), scoped);

        // The outsider's override should still be applied (resolve doesn't gate on recipient list).
        let resolved = resolve_secrets(&vault, &murk, "age1outsider", &[]);
        assert_eq!(resolved["KEY"], "outsider_val");

        // Alice gets the shared value since she has no scoped override.
        let resolved_alice = resolve_secrets(&vault, &murk, "age1alice", &[]);
        assert_eq!(resolved_alice["KEY"], "shared");
    }

    // ── New edge-case tests ──

    #[test]
    fn export_secrets_empty_vault() {
        let vault = empty_vault();
        let murk = empty_murk();
        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert!(exports.is_empty());
    }

    #[test]
    fn decrypt_vault_values_basic() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", &[recipient.clone()]).unwrap(),
                scoped: std::collections::BTreeMap::new(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val2", &[recipient]).unwrap(),
                scoped: std::collections::BTreeMap::new(),
            },
        );

        let values = crate::export::decrypt_vault_values(&vault, &identity);
        assert_eq!(values.len(), 2);
        assert_eq!(values["KEY1"], "val1");
        assert_eq!(values["KEY2"], "val2");
    }

    #[test]
    fn decrypt_vault_values_wrong_key_skips() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let (wrong_secret, _) = generate_keypair();
        let wrong_identity = make_identity(&wrong_secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", &[recipient]).unwrap(),
                scoped: std::collections::BTreeMap::new(),
            },
        );

        let values = crate::export::decrypt_vault_values(&vault, &wrong_identity);
        assert!(values.is_empty());
    }

    #[test]
    fn decrypt_vault_values_empty_vault() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let vault = empty_vault();

        let values = crate::export::decrypt_vault_values(&vault, &identity);
        assert!(values.is_empty());
    }

    #[test]
    fn diff_secrets_both_empty() {
        let old = HashMap::new();
        let new = HashMap::new();
        assert!(diff_secrets(&old, &new).is_empty());
    }

    // ── parse_and_decrypt_values tests ──

    #[test]
    fn parse_and_decrypt_values_roundtrip() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", &[recipient.clone()]).unwrap(),
                scoped: std::collections::BTreeMap::new(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val2", &[recipient]).unwrap(),
                scoped: std::collections::BTreeMap::new(),
            },
        );

        let json = serde_json::to_string(&vault).unwrap();
        let values = parse_and_decrypt_values(&json, &identity).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values["KEY1"], "val1");
        assert_eq!(values["KEY2"], "val2");
    }

    #[test]
    fn parse_and_decrypt_values_invalid_json() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);

        let result = parse_and_decrypt_values("not valid json", &identity);
        assert!(result.is_err());
    }

    #[test]
    fn parse_and_decrypt_values_wrong_key() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let (wrong_secret, _) = generate_keypair();
        let wrong_identity = make_identity(&wrong_secret);

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey];
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: crate::encrypt_value(b"val1", &[recipient]).unwrap(),
                scoped: std::collections::BTreeMap::new(),
            },
        );

        let json = serde_json::to_string(&vault).unwrap();
        let values = parse_and_decrypt_values(&json, &wrong_identity).unwrap();
        assert!(values.is_empty());
    }
}
