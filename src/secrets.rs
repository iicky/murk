//! Secret CRUD operations on the in-memory `Murk` state.

use crate::{crypto, now_utc, types};

/// Add or update a secret in the working state.
/// If `scoped` is true, stores in scoped (encrypted to self only).
/// Returns true if the key was new (no existing schema entry).
pub fn add_secret(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    key: &str,
    value: &str,
    desc: Option<&str>,
    scoped: bool,
    tags: &[String],
    identity: &crypto::MurkIdentity,
) -> bool {
    if scoped {
        let pubkey = identity.pubkey_string().expect("valid identity has pubkey");
        murk.scoped
            .entry(key.into())
            .or_default()
            .insert(pubkey, value.into());
    } else {
        murk.values.insert(key.into(), value.into());
    }

    let is_new = !vault.schema.contains_key(key);

    let now = now_utc();
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
        entry.updated = Some(now);
    } else {
        vault.schema.insert(
            key.into(),
            types::SchemaEntry {
                description: desc.unwrap_or("").into(),
                example: None,
                tags: tags.to_vec(),
                created: Some(now.clone()),
                updated: Some(now),
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

/// Import multiple secrets at once.
///
/// For each `(key, value)` pair, inserts the value into murk and ensures a
/// schema entry exists. Returns the list of imported key names.
pub fn import_secrets(
    vault: &mut types::Vault,
    murk: &mut types::Murk,
    pairs: &[(String, String)],
) -> Vec<String> {
    let now = now_utc();
    let mut imported = Vec::new();
    for (key, value) in pairs {
        murk.values.insert(key.clone(), value.clone());

        if let Some(entry) = vault.schema.get_mut(key.as_str()) {
            entry.updated = Some(now.clone());
        } else {
            vault.schema.insert(
                key.clone(),
                types::SchemaEntry {
                    description: String::new(),
                    example: None,
                    tags: vec![],
                    created: Some(now.clone()),
                    updated: Some(now.clone()),
                },
            );
        }

        imported.push(key.clone());
    }
    imported
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
        let now = now_utc();
        vault.schema.insert(
            key.into(),
            types::SchemaEntry {
                description: description.into(),
                example: example.map(Into::into),
                tags: tags.to_vec(),
                created: Some(now.clone()),
                updated: Some(now),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::collections::HashMap;

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

        assert!(needs_hint);
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

        assert!(!needs_hint);
        assert_eq!(vault.schema["KEY"].description, "a desc");
    }

    #[test]
    fn add_secret_scoped() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "scoped_val",
            None,
            true,
            &[],
            &identity,
        );

        assert!(!murk.values.contains_key("KEY"));
        assert_eq!(murk.scoped["KEY"][&pubkey], "scoped_val");
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

    #[test]
    fn remove_secret_clears_all() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY".into(),
            types::SchemaEntry {
                description: "desc".into(),
                example: None,
                tags: vec![],
                ..Default::default()
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

    #[test]
    fn list_keys_no_filter() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "A".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
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
                ..Default::default()
            },
        );
        vault.schema.insert(
            "B".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec!["api".into()],
                ..Default::default()
            },
        );
        vault.schema.insert(
            "C".into(),
            types::SchemaEntry {
                description: String::new(),
                example: None,
                tags: vec![],
                ..Default::default()
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
                ..Default::default()
            },
        );

        let keys = list_keys(&vault, &["nonexistent".into()]);
        assert!(keys.is_empty());
    }

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
                ..Default::default()
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
                ..Default::default()
            },
        );

        describe_key(&mut vault, "KEY", "new desc", None, &[]);

        assert_eq!(vault.schema["KEY"].tags, vec!["keep"]);
    }

    // ── New edge-case tests ──

    #[test]
    fn add_secret_overwrite_shared_with_scoped() {
        let (secret, pubkey) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "shared_val",
            None,
            false,
            &[],
            &identity,
        );
        assert_eq!(murk.values["KEY"], "shared_val");

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "scoped_val",
            None,
            true,
            &[],
            &identity,
        );
        // Shared value still exists, scoped override added.
        assert_eq!(murk.values["KEY"], "shared_val");
        assert_eq!(murk.scoped["KEY"][&pubkey], "scoped_val");
    }

    #[test]
    fn add_secret_empty_value() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        add_secret(
            &mut vault,
            &mut murk,
            "KEY",
            "",
            None,
            false,
            &[],
            &identity,
        );
        assert_eq!(murk.values["KEY"], "");
    }

    #[test]
    fn import_secrets_basic() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        let pairs = vec![
            ("KEY1".into(), "val1".into()),
            ("KEY2".into(), "val2".into()),
        ];
        let imported = import_secrets(&mut vault, &mut murk, &pairs);

        assert_eq!(imported, vec!["KEY1", "KEY2"]);
        assert_eq!(murk.values["KEY1"], "val1");
        assert_eq!(murk.values["KEY2"], "val2");
        assert!(vault.schema.contains_key("KEY1"));
        assert!(vault.schema.contains_key("KEY2"));
    }

    #[test]
    fn import_secrets_existing_schema_preserved() {
        let mut vault = empty_vault();
        vault.schema.insert(
            "KEY1".into(),
            types::SchemaEntry {
                description: "existing desc".into(),
                example: Some("ex".into()),
                tags: vec!["tag".into()],
                ..Default::default()
            },
        );
        let mut murk = empty_murk();

        let pairs = vec![("KEY1".into(), "new_val".into())];
        import_secrets(&mut vault, &mut murk, &pairs);

        assert_eq!(murk.values["KEY1"], "new_val");
        assert_eq!(vault.schema["KEY1"].description, "existing desc");
    }

    #[test]
    fn import_secrets_empty() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();
        let imported = import_secrets(&mut vault, &mut murk, &[]);
        assert!(imported.is_empty());
    }

    #[test]
    fn remove_secret_nonexistent() {
        let mut vault = empty_vault();
        let mut murk = empty_murk();

        // Should not panic.
        remove_secret(&mut vault, &mut murk, "NONEXISTENT");
    }
}
