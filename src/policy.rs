//! Agent access policy: machine-enforceable guardrails embedded in the vault
//! header. Policy is NOT access control — every recipient can read every shared
//! secret by design. Its value is constraining what the murk binary will expose
//! to *agents* (CI, AI coding agents), enforced at the agent entry points
//! (`agent exec`, `agent grant`) and on operator reads under self-scope
//! (`MURK_SELF_SCOPE`/`MURK_AGENT`). It lives in the plaintext header and is
//! MAC-covered (see [`crate::compute_mac`]) so it can't be silently weakened.
//!
//! The only policy today is a tag allow-list: in agent mode a secret may be
//! injected or granted only if it carries at least one allowed tag. Once a
//! policy is set it is default-deny — untagged or wrong-tagged keys are refused.

use crate::error::MurkError;
use crate::types::{Murk, Policy, Vault};

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

/// True when `pubkey` identifies a granted agent for this decrypted vault state.
///
/// Agent grants live in the encrypted meta and are carried into [`Murk::grants`]
/// after decryption, so this is the same "am I an agent" test the CLI makes when
/// it decrypts as an agent (`lib::decrypt_vault`). An operator (or any plain
/// recipient) is not in `grants`, so this returns `false` for them.
pub fn is_agent_identity(murk: &Murk, pubkey: &str) -> bool {
    murk.grants.values().any(|g| g.pubkey == pubkey)
}

/// Apply [`check_agent_keys`] when the caller is a granted agent, or when the
/// operator has opted into self-scope ([`crate::hardening::self_scope`]).
///
/// The library bindings (Python/Node) load a vault and read secrets directly,
/// without the CLI's `agent exec` policy gate. This is that gate for them: when
/// the loaded identity is an agent grant — or the caller is self-scoping — the
/// same policy the CLI enforces at `agent exec` applies here too, so a policy
/// vault is enforced from every entry point. For a plain operator identity with
/// no self-scope it is a no-op, matching the CLI's ungated `get`/`export`.
///
/// The real boundary is cryptographic: an agent's ephemeral key is not a
/// recipient of out-of-scope secrets, so it cannot decrypt them regardless. This
/// check is defense-in-depth, and it makes a later policy or tag change apply to
/// agents retroactively at read time (the agent's old scoped ciphertext lingers,
/// but the binding refuses to hand it over).
pub fn enforce_agent_policy(
    vault: &Vault,
    murk: &Murk,
    pubkey: &str,
    keys: &[String],
) -> Result<(), MurkError> {
    if is_agent_identity(murk, pubkey) || crate::hardening::self_scope() {
        check_agent_keys(vault, keys)?;
    }
    Ok(())
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

/// Whether `key` may be read under the agent allow-tag policy: always true when
/// the vault has no policy, otherwise true only if the key carries an allowed
/// tag. The public, per-key form of [`check_agent_keys`], used by self-scope
/// filtering (e.g. `murk export`).
pub fn is_agent_key_allowed(vault: &Vault, key: &str) -> bool {
    match &vault.policy {
        None => true,
        Some(policy) => key_allowed(vault, policy, key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GrantEntry, Murk, Policy, SchemaEntry, Vault};
    use std::collections::BTreeMap;

    fn agent_murk(pubkey: &str) -> Murk {
        let mut grants = BTreeMap::new();
        grants.insert(
            "codex".to_string(),
            GrantEntry {
                pubkey: pubkey.to_string(),
                ..Default::default()
            },
        );
        Murk {
            grants,
            ..Default::default()
        }
    }

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

    #[test]
    fn is_agent_identity_matches_granted_pubkey() {
        let murk = agent_murk("age1agent");
        assert!(is_agent_identity(&murk, "age1agent"));
        assert!(!is_agent_identity(&murk, "age1operator"));
        assert!(!is_agent_identity(&Murk::default(), "age1agent"));
    }

    #[test]
    fn enforce_agent_policy_is_noop_for_operator() {
        // A policy that would forbid PROD_DB, but the caller is not an agent.
        let v = vault_with(&[("PROD_DB", &["production"])], Some(policy(&["agents"])));
        let operator = Murk::default();
        assert!(enforce_agent_policy(&v, &operator, "age1operator", &["PROD_DB".into()]).is_ok());
    }

    #[test]
    fn enforce_agent_policy_applies_to_agents() {
        let v = vault_with(
            &[("PROD_DB", &["production"]), ("TEST_KEY", &["agents"])],
            Some(policy(&["agents"])),
        );
        let agent = agent_murk("age1agent");
        // Allowed key passes.
        assert!(enforce_agent_policy(&v, &agent, "age1agent", &["TEST_KEY".into()]).is_ok());
        // Forbidden key is refused for the agent.
        let err = enforce_agent_policy(&v, &agent, "age1agent", &["PROD_DB".into()]).unwrap_err();
        assert!(err.to_string().contains("PROD_DB"));
    }

    #[test]
    fn enforce_agent_policy_noop_without_policy() {
        // No policy set: even an agent reads anything (backward compatible).
        let v = vault_with(&[("PROD_DB", &["production"])], None);
        let agent = agent_murk("age1agent");
        assert!(enforce_agent_policy(&v, &agent, "age1agent", &["PROD_DB".into()]).is_ok());
    }

    #[test]
    fn is_agent_key_allowed_no_policy_allows_any_key() {
        let v = vault_with(&[("PROD_DB", &["production"])], None);
        assert!(is_agent_key_allowed(&v, "PROD_DB"));
        // Even a key with no schema entry at all is allowed absent a policy.
        assert!(is_agent_key_allowed(&v, "UNKNOWN"));
    }

    #[test]
    fn is_agent_key_allowed_checks_tags_under_policy() {
        let v = vault_with(
            &[
                ("TEST_KEY", &["agents"]),
                ("UNTAGGED", &[]),
                ("OTHER_KEY", &["other"]),
            ],
            Some(policy(&["agents"])),
        );
        assert!(is_agent_key_allowed(&v, "TEST_KEY"));
        assert!(!is_agent_key_allowed(&v, "UNTAGGED"));
        assert!(!is_agent_key_allowed(&v, "OTHER_KEY"));
    }
}
