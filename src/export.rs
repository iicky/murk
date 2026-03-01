//! Export and diff logic for vault secrets.

use std::collections::{BTreeMap, HashMap};

use crate::types;

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

    // ── New edge-case tests ──

    #[test]
    fn export_secrets_empty_vault() {
        let vault = empty_vault();
        let murk = empty_murk();
        let exports = export_secrets(&vault, &murk, "age1pk", &[]);
        assert!(exports.is_empty());
    }

    #[test]
    fn diff_secrets_both_empty() {
        let old = HashMap::new();
        let new = HashMap::new();
        assert!(diff_secrets(&old, &new).is_empty());
    }
}
