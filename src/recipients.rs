//! Recipient management: authorize, revoke, and list vault recipients.

use crate::{crypto, decrypt_value, types};

/// A single recipient entry with resolved display info.
#[derive(Debug)]
pub struct RecipientEntry {
    pub pubkey: String,
    pub display_name: Option<String>,
    pub is_self: bool,
}

/// List all recipients in the vault with optional name resolution.
///
/// If `secret_key` is provided, decrypts meta to resolve display names
/// and marks which recipient corresponds to the caller's key.
pub fn list_recipients(vault: &types::Vault, secret_key: Option<&str>) -> Vec<RecipientEntry> {
    let meta_data = secret_key.filter(|k| !k.is_empty()).and_then(|sk| {
        let identity = crypto::parse_identity(sk).ok()?;
        let my_pubkey = identity.to_public().to_string();
        let plaintext = decrypt_value(&vault.meta, &identity).ok()?;
        let meta: types::Meta = serde_json::from_slice(&plaintext).ok()?;
        Some((meta, my_pubkey))
    });

    vault
        .recipients
        .iter()
        .map(|pk| {
            let (display_name, is_self) = match &meta_data {
                Some((meta, my_pubkey)) => {
                    let name = meta.recipients.get(pk).filter(|n| !n.is_empty()).cloned();
                    (name, pk == my_pubkey)
                }
                None => (None, false),
            };
            RecipientEntry {
                pubkey: pk.clone(),
                display_name,
                is_self,
            }
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::types;
    use std::collections::{BTreeMap, HashMap};

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

        assert!(vault.secrets["KEY"].scoped.is_empty());
        assert!(murk.scoped["KEY"].is_empty());
    }

    // ── New edge-case tests ──

    // ── list_recipients tests ──

    #[test]
    fn list_recipients_with_meta() {
        let (secret, pubkey) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let mut names = std::collections::HashMap::new();
        names.insert(pubkey.clone(), "Alice".to_string());
        names.insert(pk2.clone(), "Bob".to_string());
        let meta = types::Meta {
            recipients: names,
            mac: String::new(),
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        let r2 = make_recipient(&pk2);
        let meta_enc = crate::encrypt_value(&meta_json, &[recipient, r2]).unwrap();

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey.clone(), pk2.clone()];
        vault.meta = meta_enc;

        let entries = list_recipients(&vault, Some(&secret));
        assert_eq!(entries.len(), 2);
        let me = entries.iter().find(|e| e.pubkey == pubkey).unwrap();
        assert!(me.is_self);
        assert_eq!(me.display_name.as_deref(), Some("Alice"));
        let other = entries.iter().find(|e| e.pubkey == pk2).unwrap();
        assert!(!other.is_self);
        assert_eq!(other.display_name.as_deref(), Some("Bob"));
    }

    #[test]
    fn list_recipients_without_key() {
        let (_, pubkey) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pubkey.clone()];

        let entries = list_recipients(&vault, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pubkey, pubkey);
        assert!(entries[0].display_name.is_none());
        assert!(!entries[0].is_self);
    }

    #[test]
    fn list_recipients_wrong_key() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let (wrong_secret, _) = generate_keypair();

        let meta = types::Meta {
            recipients: std::collections::HashMap::from([(pubkey.clone(), "Alice".into())]),
            mac: String::new(),
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        let meta_enc = crate::encrypt_value(&meta_json, &[recipient]).unwrap();

        let mut vault = empty_vault();
        vault.recipients = vec![pubkey.clone()];
        vault.meta = meta_enc;

        let entries = list_recipients(&vault, Some(&wrong_secret));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].display_name.is_none());
        assert!(!entries[0].is_self);
    }

    #[test]
    fn list_recipients_empty_vault() {
        let vault = empty_vault();
        let entries = list_recipients(&vault, None);
        assert!(entries.is_empty());
    }

    #[test]
    fn revoke_recipient_no_scoped() {
        let (_, pk1) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let mut vault = empty_vault();
        vault.recipients = vec![pk1.clone(), pk2.clone()];
        let mut murk = empty_murk();
        murk.recipients.insert(pk2.clone(), "bob".into());

        let result = revoke_recipient(&mut vault, &mut murk, &pk2).unwrap();
        assert_eq!(result.display_name.as_deref(), Some("bob"));
        assert!(!vault.recipients.contains(&pk2));
    }
}
