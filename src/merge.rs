//! Three-way merge driver for `.murk` vault files.
//!
//! Operates at the Vault struct level: recipients as a set, schema and secrets
//! as key-level maps. Ciphertext equality against the base determines whether
//! a side modified a value (murk preserves ciphertext for unchanged values).

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{SecretEntry, Vault};

/// A single conflict discovered during merge.
#[derive(Debug)]
pub struct MergeConflict {
    pub field: String,
    pub reason: String,
}

/// Result of a three-way vault merge.
#[derive(Debug)]
pub struct MergeResult {
    pub vault: Vault,
    pub conflicts: Vec<MergeConflict>,
}

/// Three-way merge of vault files at the struct level.
///
/// `base` is the common ancestor, `ours` is the current branch,
/// `theirs` is the incoming branch. Returns the merged vault and any conflicts.
/// On conflict, the conflicting field keeps the "ours" value.
pub fn merge_vaults(base: &Vault, ours: &Vault, theirs: &Vault) -> MergeResult {
    let mut conflicts = Vec::new();

    // -- Static fields: take ours --
    let version = ours.version.clone();
    let created = ours.created.clone();
    let vault_name = ours.vault_name.clone();
    let repo = ours.repo.clone();

    // -- Recipients: set union/removal --
    let recipients = merge_recipients(base, ours, theirs, &mut conflicts);

    // Detect recipient-change sides (triggers full re-encryption).
    let base_recip: BTreeSet<&str> = base.recipients.iter().map(String::as_str).collect();
    let ours_recip: BTreeSet<&str> = ours.recipients.iter().map(String::as_str).collect();
    let theirs_recip: BTreeSet<&str> = theirs.recipients.iter().map(String::as_str).collect();
    let ours_changed_recipients = ours_recip != base_recip;
    let theirs_changed_recipients = theirs_recip != base_recip;

    // -- Schema: key-level merge --
    let schema = merge_btree(
        &base.schema,
        &ours.schema,
        &theirs.schema,
        "schema",
        &mut conflicts,
    );

    // -- Secrets: key-level merge with ciphertext comparison --
    let secrets = merge_secrets(
        base,
        ours,
        theirs,
        ours_changed_recipients,
        theirs_changed_recipients,
        &mut conflicts,
    );

    // -- Meta: take ours for now; the CLI command handles regeneration --
    let meta = ours.meta.clone();

    let vault = Vault {
        version,
        created,
        vault_name,
        repo,
        recipients,
        schema,
        secrets,
        meta,
    };

    MergeResult { vault, conflicts }
}

/// Merge recipient lists as sets: union additions, honor removals.
fn merge_recipients(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    conflicts: &mut Vec<MergeConflict>,
) -> Vec<String> {
    let base_set: BTreeSet<&str> = base.recipients.iter().map(String::as_str).collect();
    let ours_set: BTreeSet<&str> = ours.recipients.iter().map(String::as_str).collect();
    let theirs_set: BTreeSet<&str> = theirs.recipients.iter().map(String::as_str).collect();

    let ours_added: BTreeSet<&str> = ours_set.difference(&base_set).copied().collect();
    let theirs_added: BTreeSet<&str> = theirs_set.difference(&base_set).copied().collect();
    let ours_removed: BTreeSet<&str> = base_set.difference(&ours_set).copied().collect();
    let theirs_removed: BTreeSet<&str> = base_set.difference(&theirs_set).copied().collect();

    let mut result: BTreeSet<&str> = base_set;

    // Recipient addition requires both sides to agree, or it's a conflict.
    // Blind set-union would let a malicious branch silently grant access.
    for pk in &ours_added {
        if theirs_added.contains(pk) {
            // Both sides added the same recipient — safe.
            result.insert(pk);
        } else {
            // Only ours added — conflict. Include the recipient but flag it.
            result.insert(pk);
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", &pk[..12.min(pk.len())]),
                reason: "added on one side but not the other".into(),
            });
        }
    }
    for pk in &theirs_added {
        if !ours_added.contains(pk) {
            // Only theirs added — conflict.
            result.insert(pk);
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", &pk[..12.min(pk.len())]),
                reason: "added on one side but not the other".into(),
            });
        }
    }

    // Recipient removal requires both sides to agree, or it's a conflict.
    for pk in &ours_removed {
        if theirs_removed.contains(pk) {
            // Both sides removed — safe.
            result.remove(pk);
        } else {
            // Only ours removed — conflict. Keep the recipient (safer default).
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", &pk[..12.min(pk.len())]),
                reason: "removed on one side but not the other".into(),
            });
        }
    }
    for pk in &theirs_removed {
        if !ours_removed.contains(pk) {
            // Only theirs removed — conflict. Keep the recipient.
            conflicts.push(MergeConflict {
                field: format!("recipients.{}", &pk[..12.min(pk.len())]),
                reason: "removed on one side but not the other".into(),
            });
        }
    }

    result.into_iter().map(String::from).collect()
}

/// Generic three-way merge for BTreeMap where values implement PartialEq + Clone.
fn merge_btree<V: PartialEq + Clone>(
    base: &BTreeMap<String, V>,
    ours: &BTreeMap<String, V>,
    theirs: &BTreeMap<String, V>,
    field_name: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, V> {
    let all_keys: BTreeSet<&str> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for key in all_keys {
        let in_base = base.get(key);
        let in_ours = ours.get(key);
        let in_theirs = theirs.get(key);

        match (in_base, in_ours, in_theirs) {
            (None, None, Some(t)) => {
                result.insert(key.to_string(), t.clone());
            }
            (None, Some(o), None) => {
                result.insert(key.to_string(), o.clone());
            }
            (None, Some(o), Some(t)) => {
                if o == t {
                    result.insert(key.to_string(), o.clone());
                } else {
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "added on both sides with different values".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                }
            }

            // Both sides removed — safe to omit.
            (Some(_) | None, None, None) => {}
            // One side removed, other kept unchanged — conflict.
            (Some(b), Some(o), None) => {
                if o == b {
                    // Ours didn't touch it, theirs removed — conflict.
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "removed on one side, unchanged on the other".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                }
                // else: ours modified AND theirs removed — ours wins (modified takes priority)
            }
            (Some(b), None, Some(t)) => {
                if t == b {
                    // Theirs didn't touch it, ours removed — conflict.
                    conflicts.push(MergeConflict {
                        field: format!("{field_name}.{key}"),
                        reason: "removed on one side, unchanged on the other".into(),
                    });
                    result.insert(key.to_string(), t.clone());
                }
                // else: theirs modified AND ours removed — theirs wins
            }

            (Some(b), Some(o), Some(t)) => {
                let ours_changed = o != b;
                let theirs_changed = t != b;

                match (ours_changed, theirs_changed) {
                    (false, true) => {
                        result.insert(key.to_string(), t.clone());
                    }
                    (true, true) if o != t => {
                        conflicts.push(MergeConflict {
                            field: format!("{field_name}.{key}"),
                            reason: "modified on both sides with different values".into(),
                        });
                        result.insert(key.to_string(), o.clone());
                    }
                    _ => {
                        result.insert(key.to_string(), o.clone());
                    }
                }
            }
        }
    }

    result
}

/// Merge secrets with ciphertext-equality-against-base comparison.
///
/// When one side changed recipients (triggering full re-encryption), that side's
/// ciphertext all differs from base. We detect this and use the re-encrypted side
/// as the baseline, applying the other side's additions/removals.
fn merge_secrets(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    ours_changed_recipients: bool,
    theirs_changed_recipients: bool,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    // If one side changed recipients, all its ciphertext differs from base.
    // Use the re-encrypted side as the "new base" and apply the other side's diffs.
    if ours_changed_recipients && !theirs_changed_recipients {
        return merge_secrets_with_reencrypted_side(base, ours, theirs, "theirs", conflicts);
    }
    if theirs_changed_recipients && !ours_changed_recipients {
        return merge_secrets_with_reencrypted_side(base, theirs, ours, "ours", conflicts);
    }
    if ours_changed_recipients && theirs_changed_recipients {
        return merge_secrets_both_reencrypted(base, ours, theirs, conflicts);
    }

    // Normal case: neither side changed recipients. Ciphertext comparison works.
    merge_secrets_normal(base, ours, theirs, conflicts)
}

/// Normal secret merge: compare ciphertext against base to detect changes.
fn merge_secrets_normal(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    let all_keys: BTreeSet<&str> = base
        .secrets
        .keys()
        .chain(ours.secrets.keys())
        .chain(theirs.secrets.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for key in all_keys {
        let in_base = base.secrets.get(key);
        let in_ours = ours.secrets.get(key);
        let in_theirs = theirs.secrets.get(key);

        match (in_base, in_ours, in_theirs) {
            (None, None, Some(t)) => {
                result.insert(key.to_string(), t.clone());
            }
            (None, Some(o), None) => {
                result.insert(key.to_string(), o.clone());
            }
            (None, Some(o), Some(t)) => {
                if o.shared == t.shared {
                    result.insert(key.to_string(), o.clone());
                } else {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{key}"),
                        reason: "added on both sides (values may differ)".into(),
                    });
                    result.insert(key.to_string(), o.clone());
                }
            }

            // Both removed or impossible key.
            (Some(_) | None, None, None) => {}

            (Some(b), Some(o), None) => {
                // Theirs removed, ours kept — always conflict.
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: if o.shared == b.shared {
                        "removed on one side, unchanged on the other".into()
                    } else {
                        "modified on our side but removed on theirs".into()
                    },
                });
                result.insert(key.to_string(), o.clone());
            }
            (Some(b), None, Some(t)) => {
                // Ours removed, theirs kept — always conflict.
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: if t.shared == b.shared {
                        "removed on one side, unchanged on the other".into()
                    } else {
                        "removed on our side but modified on theirs".into()
                    },
                });
                result.insert(key.to_string(), t.clone());
            }

            (Some(b), Some(o), Some(t)) => {
                let ours_changed = o.shared != b.shared;
                let theirs_changed = t.shared != b.shared;

                let shared = match (ours_changed, theirs_changed) {
                    (false, true) => t.shared.clone(),
                    (true, true) => {
                        conflicts.push(MergeConflict {
                            field: format!("secrets.{key}"),
                            reason: "shared value modified on both sides".into(),
                        });
                        o.shared.clone()
                    }
                    _ => o.shared.clone(),
                };

                let scoped = merge_scoped(&b.scoped, &o.scoped, &t.scoped, key, conflicts);
                result.insert(key.to_string(), SecretEntry { shared, scoped });
            }
        }
    }

    result
}

/// Merge scoped (mote) entries within a single secret key.
fn merge_scoped(
    base: &BTreeMap<String, String>,
    ours: &BTreeMap<String, String>,
    theirs: &BTreeMap<String, String>,
    secret_key: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, String> {
    let all_pks: BTreeSet<&str> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for pk in all_pks {
        let in_base = base.get(pk);
        let in_ours = ours.get(pk);
        let in_theirs = theirs.get(pk);

        match (in_base, in_ours, in_theirs) {
            (None, None, Some(t)) => {
                result.insert(pk.to_string(), t.clone());
            }
            (None, Some(o), None) => {
                result.insert(pk.to_string(), o.clone());
            }
            (None, Some(o), Some(t)) => {
                if o == t {
                    result.insert(pk.to_string(), o.clone());
                } else {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{secret_key}.scoped.{pk}"),
                        reason: "scoped override added on both sides".into(),
                    });
                    result.insert(pk.to_string(), o.clone());
                }
            }
            (Some(_) | None, None, None) => {}
            (Some(b), Some(o), None) => {
                if o != b {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{secret_key}.scoped.{pk}"),
                        reason: "scoped override modified on our side but removed on theirs".into(),
                    });
                    result.insert(pk.to_string(), o.clone());
                }
            }
            (Some(b), None, Some(t)) => {
                if t != b {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{secret_key}.scoped.{pk}"),
                        reason: "scoped override removed on our side but modified on theirs".into(),
                    });
                    result.insert(pk.to_string(), t.clone());
                }
            }
            (Some(b), Some(o), Some(t)) => {
                let ours_changed = o != b;
                let theirs_changed = t != b;

                match (ours_changed, theirs_changed) {
                    (false, true) => {
                        result.insert(pk.to_string(), t.clone());
                    }
                    (true, true) if o != t => {
                        conflicts.push(MergeConflict {
                            field: format!("secrets.{secret_key}.scoped.{pk}"),
                            reason: "scoped override modified on both sides".into(),
                        });
                        result.insert(pk.to_string(), o.clone());
                    }
                    _ => {
                        result.insert(pk.to_string(), o.clone());
                    }
                }
            }
        }
    }

    result
}

/// When one side re-encrypted (changed recipients), use it as the new baseline
/// and apply the other side's key-level additions/removals.
///
/// `reencrypted` is the side that changed recipients (all ciphertext differs from base).
/// `other` is the side with stable ciphertext. `other_label` is "ours" or "theirs" for messages.
fn merge_secrets_with_reencrypted_side(
    base: &Vault,
    reencrypted: &Vault,
    other: &Vault,
    other_label: &str,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    // Start with the re-encrypted side's secrets (they have the new recipient set).
    let mut result = reencrypted.secrets.clone();

    // Detect what the other side added/removed/modified relative to base.
    let all_keys: BTreeSet<&str> = base
        .secrets
        .keys()
        .chain(other.secrets.keys())
        .map(String::as_str)
        .collect();

    for key in all_keys {
        let in_base = base.secrets.get(key);
        let in_other = other.secrets.get(key);

        match (in_base, in_other) {
            (None, Some(entry)) => {
                if result.contains_key(key) {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{key}"),
                        reason: format!(
                            "added on {other_label} side and on the side that changed recipients"
                        ),
                    });
                } else {
                    result.insert(key.to_string(), entry.clone());
                }
            }
            (Some(_), None) => {
                // Other side removed this key. Honor the removal.
                result.remove(key);
            }
            (Some(b), Some(entry)) => {
                if entry.shared != b.shared {
                    conflicts.push(MergeConflict {
                        field: format!("secrets.{key}"),
                        reason: format!(
                            "modified on {other_label} side while recipients changed on the other"
                        ),
                    });
                }
                // If other side didn't modify, keep re-encrypted version.
            }
            (None, None) => {}
        }
    }

    result
}

/// Both sides changed recipients — all ciphertext on both sides differs from base.
/// Without decryption we can only merge keys that were added/removed (not modified).
fn merge_secrets_both_reencrypted(
    base: &Vault,
    ours: &Vault,
    theirs: &Vault,
    conflicts: &mut Vec<MergeConflict>,
) -> BTreeMap<String, SecretEntry> {
    let all_keys: BTreeSet<&str> = base
        .secrets
        .keys()
        .chain(ours.secrets.keys())
        .chain(theirs.secrets.keys())
        .map(String::as_str)
        .collect();

    let mut result = BTreeMap::new();

    for key in all_keys {
        let in_base = base.secrets.get(key);
        let in_ours = ours.secrets.get(key);
        let in_theirs = theirs.secrets.get(key);

        match (in_base, in_ours, in_theirs) {
            // Both have it and it was in base — take ours.
            (Some(_), Some(o), Some(_)) | (None, Some(o), None) => {
                result.insert(key.to_string(), o.clone());
            }
            // Removals — honor them.
            (Some(_), Some(_) | None, None) | (Some(_), None, Some(_)) | (None, None, None) => {}
            (None, None, Some(t)) => {
                result.insert(key.to_string(), t.clone());
            }
            (None, Some(o), Some(_)) => {
                conflicts.push(MergeConflict {
                    field: format!("secrets.{key}"),
                    reason: "added on both sides while both changed recipients".into(),
                });
                result.insert(key.to_string(), o.clone());
            }
        }
    }

    result
}

/// Output of the merge driver: the merge result and whether meta was regenerated.
#[derive(Debug)]
pub struct MergeDriverOutput {
    pub result: MergeResult,
    pub meta_regenerated: bool,
}

/// Run the three-way merge driver on vault contents (as strings).
///
/// Parses all three versions, merges, and attempts meta regeneration.
/// Returns the merged vault and conflict list. The caller is responsible for
/// writing the result to disk.
pub fn run_merge_driver(base: &str, ours: &str, theirs: &str) -> Result<MergeDriverOutput, String> {
    use crate::vault;

    let base_vault = vault::parse(base).map_err(|e| format!("parsing base: {e}"))?;
    let ours_vault = vault::parse(ours).map_err(|e| format!("parsing ours: {e}"))?;
    let theirs_vault = vault::parse(theirs).map_err(|e| format!("parsing theirs: {e}"))?;

    let mut result = merge_vaults(&base_vault, &ours_vault, &theirs_vault);
    let meta_regenerated = regenerate_meta(&mut result.vault, &ours_vault, &theirs_vault).is_some();

    Ok(MergeDriverOutput {
        result,
        meta_regenerated,
    })
}

/// Attempt to regenerate the meta blob for a merged vault.
///
/// Decrypts meta from `ours` and `theirs` to merge recipient name maps,
/// recomputes the MAC, and re-encrypts. Falls back to `ours.meta` if
/// MURK_KEY is unavailable.
pub fn regenerate_meta(merged: &mut Vault, ours: &Vault, theirs: &Vault) -> Option<String> {
    use crate::{compute_mac, crypto, decrypt_meta, encrypt_value, parse_recipients, resolve_key};
    use age::secrecy::ExposeSecret;
    use std::collections::HashMap;

    let secret_key = resolve_key().ok()?;
    let identity = crypto::parse_identity(secret_key.expose_secret()).ok()?;

    let default_meta = || crate::types::Meta {
        recipients: HashMap::new(),
        mac: String::new(),
        hmac_key: None,
    };

    let ours_meta = decrypt_meta(ours, &identity).unwrap_or_else(default_meta);
    let theirs_meta = decrypt_meta(theirs, &identity).unwrap_or_else(default_meta);

    // Merge name maps: union, ours wins on conflict.
    let mut names = theirs_meta.recipients;
    for (pk, name) in ours_meta.recipients {
        names.insert(pk, name);
    }

    // Only keep names for recipients still in the merged vault.
    names.retain(|pk, _| merged.recipients.contains(pk));

    let hmac_key_hex = crate::generate_hmac_key();
    let hmac_key = crate::decode_hmac_key(&hmac_key_hex).unwrap();
    let mac = compute_mac(merged, Some(&hmac_key));
    let meta = crate::types::Meta {
        recipients: names,
        mac,
        hmac_key: Some(hmac_key_hex),
    };

    let recipients = parse_recipients(&merged.recipients).ok()?;

    if recipients.is_empty() {
        return None;
    }

    let meta_json = serde_json::to_vec(&meta).ok()?;
    let encrypted = encrypt_value(&meta_json, &recipients).ok()?;
    merged.meta = encrypted;
    Some("meta regenerated".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SchemaEntry, SecretEntry, VAULT_VERSION, Vault};
    use std::collections::BTreeMap;

    fn base_vault() -> Vault {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DB_URL".into(),
            SchemaEntry {
                description: "database url".into(),
                example: None,
                tags: vec![],
            },
        );

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "DB_URL".into(),
            SecretEntry {
                shared: "base-cipher-db".into(),
                scoped: BTreeMap::new(),
            },
        );

        Vault {
            version: VAULT_VERSION.into(),
            created: "2026-01-01T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1alice".into(), "age1bob".into()],
            schema,
            secrets,
            meta: "base-meta".into(),
        }
    }

    // -- No-change merge --

    #[test]
    fn merge_no_changes() {
        let base = base_vault();
        let r = merge_vaults(&base, &base, &base);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.secrets.len(), 1);
        assert_eq!(r.vault.recipients.len(), 2);
    }

    // -- Ours-only changes --

    #[test]
    fn merge_ours_adds_secret() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.insert(
            "API_KEY".into(),
            SecretEntry {
                shared: "ours-cipher-api".into(),
                scoped: BTreeMap::new(),
            },
        );
        ours.schema.insert(
            "API_KEY".into(),
            SchemaEntry {
                description: "api key".into(),
                example: None,
                tags: vec![],
            },
        );

        let r = merge_vaults(&base, &ours, &base);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("API_KEY"));
        assert!(r.vault.schema.contains_key("API_KEY"));
        assert_eq!(r.vault.secrets.len(), 2);
    }

    // -- Theirs-only changes --

    #[test]
    fn merge_theirs_adds_secret() {
        let base = base_vault();
        let mut theirs = base.clone();
        theirs.secrets.insert(
            "STRIPE_KEY".into(),
            SecretEntry {
                shared: "theirs-cipher-stripe".into(),
                scoped: BTreeMap::new(),
            },
        );

        let r = merge_vaults(&base, &base, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("STRIPE_KEY"));
    }

    // -- Both add different keys --

    #[test]
    fn merge_both_add_different_keys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.insert(
            "API_KEY".into(),
            SecretEntry {
                shared: "ours-cipher-api".into(),
                scoped: BTreeMap::new(),
            },
        );

        let mut theirs = base.clone();
        theirs.secrets.insert(
            "STRIPE_KEY".into(),
            SecretEntry {
                shared: "theirs-cipher-stripe".into(),
                scoped: BTreeMap::new(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("API_KEY"));
        assert!(r.vault.secrets.contains_key("STRIPE_KEY"));
        assert!(r.vault.secrets.contains_key("DB_URL"));
        assert_eq!(r.vault.secrets.len(), 3);
    }

    // -- Both remove same key --

    #[test]
    fn merge_both_remove_same_key() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        let mut theirs = base.clone();
        theirs.secrets.remove("DB_URL");

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(!r.vault.secrets.contains_key("DB_URL"));
    }

    // -- Ours modifies, theirs unchanged --

    #[test]
    fn merge_ours_modifies_theirs_unchanged() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-new-cipher-db".into();

        let r = merge_vaults(&base, &ours, &base);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-new-cipher-db");
    }

    // -- Theirs modifies, ours unchanged --

    #[test]
    fn merge_theirs_modifies_ours_unchanged() {
        let base = base_vault();
        let mut theirs = base.clone();
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-new-cipher-db".into();

        let r = merge_vaults(&base, &base, &theirs);
        assert!(r.conflicts.is_empty());
        assert_eq!(r.vault.secrets["DB_URL"].shared, "theirs-new-cipher-db");
    }

    // -- Conflicts --

    #[test]
    fn merge_both_modify_same_secret() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-new".into();
        let mut theirs = base.clone();
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-new".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("DB_URL"));
        // Takes ours on conflict.
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-new");
    }

    #[test]
    fn merge_both_add_same_key() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.insert(
            "NEW_KEY".into(),
            SecretEntry {
                shared: "ours-cipher".into(),
                scoped: BTreeMap::new(),
            },
        );
        let mut theirs = base.clone();
        theirs.secrets.insert(
            "NEW_KEY".into(),
            SecretEntry {
                shared: "theirs-cipher".into(),
                scoped: BTreeMap::new(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("NEW_KEY"));
    }

    #[test]
    fn merge_remove_vs_modify() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-modified".into();
        let mut theirs = base.clone();
        theirs.secrets.remove("DB_URL");

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(
            r.conflicts[0]
                .reason
                .contains("modified on our side but removed on theirs")
        );
    }

    // -- Recipients --

    #[test]
    fn merge_recipient_added_one_side_conflicts() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());

        let r = merge_vaults(&base, &ours, &base);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].reason.contains("added on one side"));
        // Recipient is still included (safer to keep than drop).
        assert!(r.vault.recipients.contains(&"age1charlie".to_string()));
    }

    #[test]
    fn merge_recipient_added_both_same() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());
        let mut theirs = base.clone();
        theirs.recipients.push("age1charlie".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert_eq!(
            r.vault
                .recipients
                .iter()
                .filter(|r| *r == "age1charlie")
                .count(),
            1
        );
    }

    #[test]
    fn merge_recipient_removed_one_side_conflicts() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.retain(|r| r != "age1bob");

        let r = merge_vaults(&base, &ours, &base);
        // One-sided removal should conflict — recipient kept for safety.
        assert!(!r.conflicts.is_empty());
        assert!(r.vault.recipients.contains(&"age1bob".to_string()));
    }

    #[test]
    fn merge_recipient_removed_both_sides_ok() {
        let base = base_vault();
        let mut ours = base.clone();
        let mut theirs = base.clone();
        ours.recipients.retain(|r| r != "age1bob");
        theirs.recipients.retain(|r| r != "age1bob");

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(!r.vault.recipients.contains(&"age1bob".to_string()));
    }

    // -- Schema --

    #[test]
    fn merge_schema_different_keys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.insert(
            "API_KEY".into(),
            SchemaEntry {
                description: "api".into(),
                example: None,
                tags: vec![],
            },
        );
        let mut theirs = base.clone();
        theirs.schema.insert(
            "STRIPE".into(),
            SchemaEntry {
                description: "stripe".into(),
                example: None,
                tags: vec![],
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        assert!(r.vault.schema.contains_key("API_KEY"));
        assert!(r.vault.schema.contains_key("STRIPE"));
    }

    #[test]
    fn merge_schema_same_key_conflict() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.schema.get_mut("DB_URL").unwrap().description = "ours desc".into();
        let mut theirs = base.clone();
        theirs.schema.get_mut("DB_URL").unwrap().description = "theirs desc".into();

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("schema.DB_URL"));
    }

    // -- Scoped --

    #[test]
    fn merge_scoped_different_pubkeys() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1alice".into(), "alice-scope".into());
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1bob".into(), "bob-scope".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert!(r.conflicts.is_empty());
        let entry = &r.vault.secrets["DB_URL"];
        assert_eq!(entry.scoped["age1alice"], "alice-scope");
        assert_eq!(entry.scoped["age1bob"], "bob-scope");
    }

    #[test]
    fn merge_scoped_both_modify_same() {
        let mut base = base_vault();
        base.secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1alice".into(), "base-scope".into());

        let mut ours = base.clone();
        ours.secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1alice".into(), "ours-scope".into());
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1alice".into(), "theirs-scope".into());

        let r = merge_vaults(&base, &ours, &theirs);
        assert_eq!(r.conflicts.len(), 1);
        assert!(r.conflicts[0].field.contains("scoped"));
    }

    #[test]
    fn merge_scoped_add_vs_base_key_removal() {
        let base = base_vault();

        // Ours: remove the base key entirely.
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        ours.schema.remove("DB_URL");

        // Theirs: add a scoped entry on the same key (shared unchanged).
        let mut theirs = base.clone();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1alice".into(), "alice-scoped".into());

        let r = merge_vaults(&base, &ours, &theirs);
        // Ours removed the key, theirs kept it — conflict.
        // Schema removal conflicts, secret kept because theirs modified (added scoped).
        assert!(!r.conflicts.is_empty());
        assert!(r.vault.secrets.contains_key("DB_URL"));
    }

    #[test]
    fn merge_scoped_add_vs_base_key_modification() {
        let base = base_vault();

        // Ours: remove the base key entirely.
        let mut ours = base.clone();
        ours.secrets.remove("DB_URL");
        ours.schema.remove("DB_URL");

        // Theirs: modify the shared value AND add scoped.
        let mut theirs = base.clone();
        theirs.secrets.get_mut("DB_URL").unwrap().shared = "theirs-modified".into();
        theirs
            .secrets
            .get_mut("DB_URL")
            .unwrap()
            .scoped
            .insert("age1alice".into(), "alice-scoped".into());

        let r = merge_vaults(&base, &ours, &theirs);
        // Theirs modified shared, ours removed — conflicts for both secrets and schema.
        assert!(r.conflicts.len() >= 1);
        assert!(r.conflicts.iter().any(|c| c.reason.contains("removed")));
    }

    // -- Recipient change + secret addition --

    #[test]
    fn merge_ours_changes_recipients_theirs_adds_key() {
        let base = base_vault();
        let mut ours = base.clone();
        ours.recipients.push("age1charlie".into());
        ours.secrets.get_mut("DB_URL").unwrap().shared = "ours-reencrypted-db".into();

        let mut theirs = base.clone();
        theirs.secrets.insert(
            "NEW_KEY".into(),
            SecretEntry {
                shared: "theirs-new".into(),
                scoped: BTreeMap::new(),
            },
        );

        let r = merge_vaults(&base, &ours, &theirs);
        // One-sided recipient addition now conflicts.
        assert!(
            r.conflicts
                .iter()
                .any(|c| c.reason.contains("added on one side"))
        );
        assert_eq!(r.vault.secrets["DB_URL"].shared, "ours-reencrypted-db");
        assert!(r.vault.secrets.contains_key("NEW_KEY"));
        assert!(r.vault.recipients.contains(&"age1charlie".to_string()));
    }
}
