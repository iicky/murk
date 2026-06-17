//! Agent access policy: machine-enforceable guardrails embedded in the vault
//! header. Policy is NOT access control — every recipient can read every shared
//! secret by design. Its value is constraining what the murk binary will expose
//! to *agents* (CI, AI coding agents), enforced at the agent entry points
//! (`agent exec`, `agent grant`). It lives in the plaintext header and is
//! MAC-covered (see [`crate::compute_mac`]) so it can't be silently weakened.
//!
//! The only policy today is a tag allow-list: in agent mode a secret may be
//! injected or granted only if it carries at least one allowed tag. Once a
//! policy is set it is default-deny — untagged or wrong-tagged keys are refused.

use crate::error::MurkError;
use crate::types::{Policy, Vault};

/// Check that every key in `keys` is permitted to agents by the vault's policy.
///
/// No policy → all keys allowed (backward compatible). With a policy, a key is
/// allowed only if its schema carries at least one of the policy's
/// `agent_allow_tags`. Fails closed: an unknown key (no schema entry) or a key
/// with no matching tag is refused. Returns an error naming every forbidden key
/// and the allowed tags, so the caller's message is actionable.
pub fn check_agent_keys(vault: &Vault, keys: &[String]) -> Result<(), MurkError> {
    let Some(policy) = &vault.policy else {
        return Ok(());
    };

    let forbidden: Vec<&String> = keys
        .iter()
        .filter(|key| !key_allowed(vault, policy, key))
        .collect();

    if forbidden.is_empty() {
        return Ok(());
    }

    let names: Vec<&str> = forbidden.iter().map(|s| s.as_str()).collect();
    let allowed = if policy.agent_allow_tags.is_empty() {
        "none — this vault's policy locks agents out entirely".to_string()
    } else {
        policy.agent_allow_tags.join(", ")
    };
    Err(MurkError::Policy(format!(
        "policy forbids {} in agent mode (allowed tags: {allowed}) — tag the key with `murk describe` or update the policy with `murk policy`",
        names.join(", "),
    )))
}

/// True if `key` carries at least one of the policy's allowed tags.
fn key_allowed(vault: &Vault, policy: &Policy, key: &str) -> bool {
    vault.schema.get(key).is_some_and(|entry| {
        entry
            .tags
            .iter()
            .any(|t| policy.agent_allow_tags.contains(t))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Policy, SchemaEntry, Vault};
    use std::collections::BTreeMap;

    fn vault_with(tags: &[(&str, &[&str])], policy: Option<Policy>) -> Vault {
        let mut schema = BTreeMap::new();
        for (key, key_tags) in tags {
            schema.insert(
                (*key).to_string(),
                SchemaEntry {
                    tags: key_tags.iter().map(|t| (*t).to_string()).collect(),
                    ..Default::default()
                },
            );
        }
        Vault {
            version: "2.0".into(),
            created: "2026-06-16T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![],
            schema,
            policy,
            secrets: BTreeMap::new(),
            meta: String::new(),
        }
    }

    fn policy(tags: &[&str]) -> Policy {
        Policy {
            agent_allow_tags: tags.iter().map(|t| (*t).to_string()).collect(),
        }
    }

    #[test]
    fn no_policy_allows_everything() {
        let v = vault_with(&[("PROD_DB", &["production"])], None);
        assert!(check_agent_keys(&v, &["PROD_DB".into()]).is_ok());
    }

    #[test]
    fn allow_tag_permits_matching_key() {
        let v = vault_with(&[("TEST_KEY", &["agents"])], Some(policy(&["agents"])));
        assert!(check_agent_keys(&v, &["TEST_KEY".into()]).is_ok());
    }

    #[test]
    fn missing_tag_is_refused() {
        let v = vault_with(
            &[("PROD_DB", &["production"]), ("TEST_KEY", &["agents"])],
            Some(policy(&["agents"])),
        );
        let err = check_agent_keys(&v, &["PROD_DB".into()]).unwrap_err();
        assert!(err.to_string().contains("PROD_DB"));
        assert!(err.to_string().contains("agents"));
        // A mix reports only the forbidden one.
        let err = check_agent_keys(&v, &["TEST_KEY".into(), "PROD_DB".into()]).unwrap_err();
        assert!(err.to_string().contains("PROD_DB"));
        assert!(!err.to_string().contains("TEST_KEY,"));
    }

    #[test]
    fn unknown_key_is_refused_under_policy() {
        let v = vault_with(&[], Some(policy(&["agents"])));
        assert!(check_agent_keys(&v, &["NOPE".into()]).is_err());
    }

    #[test]
    fn empty_allow_list_locks_agents_out() {
        let v = vault_with(&[("TEST_KEY", &["agents"])], Some(policy(&[])));
        let err = check_agent_keys(&v, &["TEST_KEY".into()]).unwrap_err();
        assert!(err.to_string().contains("locks agents out"));
    }
}
