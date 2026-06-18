//! Encrypted secrets manager for developers — one file, age encryption, git-friendly.
//!
//! This library provides the core functionality for murk: vault I/O, age encryption,
//! BIP39 key recovery, and secret management. The CLI binary wraps this library.

#![warn(clippy::pedantic)]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::too_many_arguments,
    clippy::implicit_hasher
)]

// Domain modules — pub(crate) unless main.rs needs direct path access.
pub(crate) mod agent;
pub(crate) mod codename;
pub mod crypto;
pub mod edit;
pub(crate) mod env;
pub mod error;
pub(crate) mod export;
pub(crate) mod git;
pub mod github;
pub(crate) mod grants;
pub(crate) mod groups;
pub mod hardening;
pub(crate) mod info;
pub(crate) mod init;
pub(crate) mod merge;
pub(crate) mod policy;
pub(crate) mod recipients;
pub mod recovery;
pub mod scan;
pub(crate) mod secrets;
pub mod types;
pub mod vault;

#[cfg(feature = "python")]
mod python;

// Shared test utilities
#[cfg(test)]
pub mod testutil;

// Re-exports: keep the flat murk_cli::foo() API for main.rs
pub use agent::{AgentPlan, AgentPlanKey, agent_plan, format_agent_plan_text};
pub use env::{
    EnvrcStatus, KeySource, agent_key_file_path, agent_keys_dir, dotenv_has_murk_key,
    key_file_path, parse_env, resolve_key, resolve_key_for_vault, resolve_key_with_source,
    warn_env_permissions, write_envrc, write_key_ref_to_dotenv, write_key_to_dotenv,
    write_key_to_file,
};
pub use error::MurkError;
pub use export::{
    DiffEntry, DiffKind, decrypt_vault_values, diff_secrets, export_secrets, format_diff_lines,
    parse_and_decrypt_values, resolve_secrets,
};
pub use git::{MergeDriverSetupStep, setup_merge_driver};
pub use github::{GitHubError, fetch_keys};
pub use grants::{create_grant, parse_ttl, remove_grant, validate_grant_name};
pub use groups::{
    add_member, create_group, delete_group, remove_member, resolve_member, validate_group_name,
};
pub use info::{InfoEntry, VaultInfo, format_info_lines, lifecycle_segment, vault_info};
pub use init::{DiscoveredKey, InitStatus, check_init_status, create_vault, discover_existing_key};
pub use merge::{MergeDriverOutput, run_merge_driver};
pub use policy::{check_agent_keys, enforce_agent_policy, is_agent_identity};
pub use recipients::{
    RecipientEntry, RevokeResult, authorize_recipient, format_recipient_lines, key_type_label,
    list_recipients, revoke_recipient, truncate_pubkey,
};
pub use secrets::{
    EXPIRY_WARN_DAYS, RotationIssue, add_grouped_secret, add_secret, describe_key, get_secret,
    import_secrets, list_keys, mark_revoked, remove_secret, rotation_health,
};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// Check whether a key name is a valid shell identifier (safe for `export KEY=...`).
/// Must start with a letter or underscore, and contain only `[A-Za-z0-9_]`.
pub fn is_valid_key_name(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

use age::secrecy::ExposeSecret;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;

// Re-export polymorphic types for consumers.
pub use crypto::{MurkIdentity, MurkRecipient};

/// Decrypt the meta blob from a vault, returning the deserialized Meta if possible.
pub fn decrypt_meta(vault: &types::Vault, identity: &crypto::MurkIdentity) -> Option<types::Meta> {
    if vault.meta.is_empty() {
        return None;
    }
    let plaintext = decrypt_value(&vault.meta, identity).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Parse a list of pubkey strings into recipients (age or SSH).
pub(crate) fn parse_recipients(
    pubkeys: &[String],
) -> Result<Vec<crypto::MurkRecipient>, MurkError> {
    pubkeys
        .iter()
        .map(|pk| crypto::parse_recipient(pk).map_err(MurkError::from))
        .collect()
}

/// Encrypt a value and return base64-encoded ciphertext.
pub fn encrypt_value(
    plaintext: &[u8],
    recipients: &[crypto::MurkRecipient],
) -> Result<String, MurkError> {
    let ciphertext = crypto::encrypt(plaintext, recipients)?;
    Ok(BASE64.encode(&ciphertext))
}

/// Decrypt a base64-encoded ciphertext and return plaintext bytes.
///
/// The returned buffer is zeroized on drop.
pub fn decrypt_value(
    encoded: &str,
    identity: &crypto::MurkIdentity,
) -> Result<Zeroizing<Vec<u8>>, MurkError> {
    let ciphertext = BASE64.decode(encoded).map_err(|e| {
        MurkError::Crypto(crypto::CryptoError::Decrypt(format!("invalid base64: {e}")))
    })?;
    Ok(crypto::decrypt(&ciphertext, identity)?)
}

/// Validate decrypted bytes as UTF-8 and return a zeroizing `String`.
///
/// The returned `String` and the input `&[u8]` are both zeroized when dropped
/// (assuming the caller holds the bytes inside a `Zeroizing`), so plaintext
/// never escapes to a non-zeroed buffer.
pub(crate) fn plaintext_bytes_to_zeroizing_string(
    bytes: &[u8],
) -> Result<Zeroizing<String>, std::str::Utf8Error> {
    let s = std::str::from_utf8(bytes)?;
    Ok(Zeroizing::new(s.to_owned()))
}

/// Read a vault file from disk.
///
/// This is a thin wrapper around `vault::read` for a convenient string-path API.
pub fn read_vault(vault_path: &str) -> Result<types::Vault, MurkError> {
    Ok(vault::read(Path::new(vault_path))?)
}

/// Resolve a vault path argument, walking up parent directories to discover the vault.
///
/// Mirrors how git finds `.git` and cargo finds `Cargo.toml`: if the user passed a bare
/// filename (no path separator, not absolute) and it does not exist in the current
/// directory, walk up from CWD looking for a file of that name. Stops at:
///
/// - a directory containing `.git` (the git root — don't escape the repo)
/// - `$HOME` (don't traverse into parents of the user's home)
/// - the filesystem root
///
/// If a match is found, returns the absolute path. Otherwise returns the input unchanged,
/// so downstream error messages still reference what the user asked for.
///
/// Explicit paths (absolute, or containing `/` or `\`) are returned unchanged — the user
/// told us exactly where to look, so don't second-guess them.
pub fn resolve_vault_path(arg: &str) -> String {
    use std::path::PathBuf;

    // Explicit path: no traversal.
    if arg.is_empty() || arg.contains('/') || arg.contains('\\') || Path::new(arg).is_absolute() {
        return arg.to_string();
    }

    let Ok(cwd) = std::env::current_dir() else {
        return arg.to_string();
    };

    // Found in CWD — nothing to discover.
    if cwd.join(arg).exists() {
        return arg.to_string();
    }

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut dir = cwd.as_path();
    loop {
        let candidate = dir.join(arg);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
        // Stop at git root after checking this directory.
        if dir.join(".git").exists() {
            break;
        }
        // Stop at $HOME boundary (don't traverse above the user's home).
        if let Some(ref h) = home
            && dir == h.as_path()
        {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    arg.to_string()
}

/// The non-secret state carried out of the encrypted meta blob after integrity
/// verification: recipient names, group membership, agent grants, the
/// legacy-MAC flag, and pinned GitHub fingerprints.
struct MetaState {
    recipients: HashMap<String, String>,
    groups: BTreeMap<String, Vec<String>>,
    grants: BTreeMap<String, types::GrantEntry>,
    legacy_mac: bool,
    github_pins: HashMap<String, Vec<String>>,
}

/// Decrypt the meta blob and verify the vault's integrity MAC, returning the
/// recipient/group/grant state. Errors if the vault has secrets but a missing or
/// invalid MAC — a tampered or inconsistent vault should fail loudly here rather
/// than surface a misleading decryption error later.
fn resolve_meta_state(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<MetaState, MurkError> {
    match decrypt_meta(vault, identity) {
        Some(meta) if !meta.mac.is_empty() => {
            let mac_key = meta.mac_key.as_deref().and_then(decode_mac_key);
            if !verify_mac(
                vault,
                &meta.groups,
                &meta.grants,
                &meta.mac,
                mac_key.as_ref(),
            ) {
                let expected = compute_mac(vault, &meta.groups, &meta.grants, mac_key.as_ref());
                return Err(MurkError::Integrity(format!(
                    "vault may have been tampered with (expected {expected}, got {})",
                    meta.mac
                )));
            }
            let legacy_mac = meta.mac.starts_with("sha256:") || meta.mac.starts_with("sha256v2:");
            Ok(MetaState {
                recipients: meta.recipients,
                groups: meta.groups,
                grants: meta.grants,
                legacy_mac,
                github_pins: meta.github_pins,
            })
        }
        Some(meta) if vault.secrets.is_empty() => Ok(MetaState {
            recipients: meta.recipients,
            groups: meta.groups,
            grants: meta.grants,
            legacy_mac: false,
            github_pins: meta.github_pins,
        }),
        Some(_) => Err(MurkError::Integrity(
            "vault has secrets but MAC is empty — vault may have been tampered with".into(),
        )),
        None if vault.secrets.is_empty() && vault.meta.is_empty() => Ok(MetaState {
            recipients: HashMap::new(),
            groups: BTreeMap::new(),
            grants: BTreeMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
        }),
        None => Err(MurkError::Integrity(
            "vault has secrets but no meta — vault may have been tampered with".into(),
        )),
    }
}

/// Decrypt a vault using the given identity. Verifies integrity, decrypts all
/// shared and scoped values, and returns the working state.
///
/// Use this when you already have a key (e.g. from a Python SDK or test harness).
/// For the common CLI case where the key comes from the environment, use `load_vault`.
pub fn decrypt_vault(
    vault: &types::Vault,
    identity: &crypto::MurkIdentity,
) -> Result<types::Murk, MurkError> {
    let pubkey = identity.pubkey_string()?;

    // Verify integrity BEFORE decrypting secrets — a tampered vault should fail
    // with an integrity error, not a misleading "you are not a recipient" message.
    let MetaState {
        recipients,
        groups,
        grants,
        legacy_mac,
        github_pins,
    } = resolve_meta_state(vault, identity)?;

    // An agent grant is a recipient of the meta blob (so it can verify integrity
    // and read its grant) but is deliberately excluded from the shared "everyone"
    // layer. Such an identity legitimately cannot decrypt shared ciphertexts, so
    // it skips them rather than erroring. A normal recipient that fails to decrypt
    // shared is a genuine problem (a true outsider already failed at meta
    // decryption above), so it still gets the clear "not a recipient" error.
    let is_agent = grants.values().any(|g| g.pubkey == pubkey);

    // Decrypt shared values (skip scoped-only entries with empty shared ciphertext).
    let mut values: HashMap<String, Zeroizing<String>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        if entry.shared.is_empty() {
            continue;
        }
        let plaintext = match decrypt_value(&entry.shared, identity) {
            Ok(plaintext) => plaintext,
            Err(_) if is_agent => continue,
            Err(_) => {
                return Err(MurkError::Crypto(crypto::CryptoError::Decrypt(
                    "you are not a recipient of this vault. Run `murk circle` to check, or ask a recipient to authorize you".into(),
                )));
            }
        };
        let value = plaintext_bytes_to_zeroizing_string(&plaintext)
            .map_err(|e| MurkError::Secret(format!("invalid UTF-8 in secret {key}: {e}")))?;
        values.insert(key.clone(), value);
    }

    // Decrypt our private (per-recipient) overrides — the `me` tier.
    let mut private: HashMap<String, HashMap<String, Zeroizing<String>>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        if let Some(encoded) = entry.private.get(&pubkey)
            && let Ok(value) = decrypt_value(encoded, identity).and_then(|pt| {
                plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| MurkError::Secret(e.to_string()))
            })
        {
            private
                .entry(key.clone())
                .or_default()
                .insert(pubkey.clone(), value);
        }
    }

    // Decrypt named-group values we're a member of. age tells us whether our
    // identity is a recipient, so we just try each group ciphertext and keep the
    // ones that decrypt — non-members silently fall through.
    let mut grouped: HashMap<String, HashMap<String, Zeroizing<String>>> = HashMap::new();
    for (key, entry) in &vault.secrets {
        for (group, encoded) in &entry.grouped {
            if let Ok(value) = decrypt_value(encoded, identity).and_then(|pt| {
                plaintext_bytes_to_zeroizing_string(&pt)
                    .map_err(|e| MurkError::Secret(e.to_string()))
            }) {
                grouped
                    .entry(key.clone())
                    .or_default()
                    .insert(group.clone(), value);
            }
        }
    }

    Ok(types::Murk {
        values,
        recipients,
        private,
        grouped,
        groups,
        grants,
        legacy_mac,
        github_pins,
    })
}

/// Resolve the key from the environment, read the vault, and decrypt it.
///
/// Convenience wrapper combining `resolve_key` + `read_vault` + `decrypt_vault`.
pub fn load_vault(
    vault_path: &str,
) -> Result<(types::Vault, types::Murk, crypto::MurkIdentity), MurkError> {
    let secret_key = env::resolve_key_for_vault(vault_path).map_err(MurkError::Key)?;

    let identity = crypto::parse_identity(secret_key.expose_secret()).map_err(|e| {
        MurkError::Key(format!(
            "{e}. For age keys, set MURK_KEY. For SSH keys, set MURK_KEY_FILE=~/.ssh/id_ed25519"
        ))
    })?;

    let vault = read_vault(vault_path)?;
    let murk = decrypt_vault(&vault, &identity)?;

    Ok((vault, murk, identity))
}

/// Re-encrypt a key's shared (everyone) ciphertext, reusing the existing one
/// when the value and recipient set are unchanged (for minimal git diffs).
fn rebuild_shared(
    key: &str,
    vault: &types::Vault,
    recipients: &[crypto::MurkRecipient],
    recipients_changed: bool,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<String, MurkError> {
    let Some(value) = current.values.get(key) else {
        // Scoped/group-only key — no shared ciphertext.
        return Ok(String::new());
    };
    // Reuse the stored ciphertext when the value and recipient set are unchanged.
    if !recipients_changed
        && original.values.get(key) == Some(value)
        && let Some(existing) = vault.secrets.get(key)
    {
        return Ok(existing.shared.clone());
    }
    encrypt_value(value.as_bytes(), recipients)
}

/// Re-encrypt a key's scoped (per-recipient) ciphertexts, keeping unchanged
/// entries and dropping ones removed since load.
fn rebuild_private(
    key: &str,
    vault: &types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<BTreeMap<String, String>, MurkError> {
    let mut scoped = vault
        .secrets
        .get(key)
        .map(|e| e.private.clone())
        .unwrap_or_default();

    if let Some(key_scoped) = current.private.get(key) {
        for (pk, val) in key_scoped {
            let original_val = original.private.get(key).and_then(|m| m.get(pk));
            if original_val != Some(val) {
                let recipient = crypto::parse_recipient(pk)?;
                scoped.insert(pk.clone(), encrypt_value(val.as_bytes(), &[recipient])?);
            }
        }
    }

    if let Some(orig_key_scoped) = original.private.get(key) {
        for pk in orig_key_scoped.keys() {
            let still_present = current.private.get(key).is_some_and(|m| m.contains_key(pk));
            if !still_present {
                scoped.remove(pk);
            }
        }
    }

    Ok(scoped)
}

/// Re-encrypt a key's named-group ciphertexts to each group's current members.
/// Re-encrypts when the value changed or the group's membership changed; drops
/// groups removed since load.
fn rebuild_grouped(
    key: &str,
    vault: &types::Vault,
    changed_groups: &BTreeSet<&str>,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<BTreeMap<String, String>, MurkError> {
    let mut grouped = vault
        .secrets
        .get(key)
        .map(|e| e.grouped.clone())
        .unwrap_or_default();

    if let Some(key_grouped) = current.grouped.get(key) {
        for (group, val) in key_grouped {
            let members = current.groups.get(group).ok_or_else(|| {
                MurkError::Secret(format!("secret {key} references unknown group {group}"))
            })?;
            let original_val = original.grouped.get(key).and_then(|m| m.get(group));
            if original_val != Some(val) || changed_groups.contains(group.as_str()) {
                let group_recipients = parse_recipients(members)?;
                grouped.insert(
                    group.clone(),
                    encrypt_value(val.as_bytes(), &group_recipients)?,
                );
            }
        }
    }

    if let Some(orig_key_grouped) = original.grouped.get(key) {
        for group in orig_key_grouped.keys() {
            let still_present = current
                .grouped
                .get(key)
                .is_some_and(|m| m.contains_key(group));
            if !still_present {
                grouped.remove(group);
            }
        }
    }

    Ok(grouped)
}

/// Keep each active grant's private copy of `key` in sync with the key's current
/// shared value. A grant stages a per-agent private copy at grant time; without
/// this, rotating a granted key would leave the agent reading the stale value
/// (the operator can't see the agent's ciphertext to re-encrypt it, and
/// `rebuild_private` preserves it as-is). When the value changed since load and
/// the operator can read it, re-encrypt the agent's copy; unchanged values keep
/// their preserved ciphertext (no churn), and keys the operator can't read are
/// left untouched.
fn resync_grant_private(
    key: &str,
    private: &mut BTreeMap<String, String>,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    let Some(value) = current.values.get(key) else {
        return Ok(());
    };
    if original.values.get(key) == Some(value) {
        return Ok(());
    }
    for grant in current.grants.values() {
        if grant.scope.iter().any(|k| k == key) {
            let recipient = crypto::parse_recipient(&grant.pubkey)?;
            private.insert(
                grant.pubkey.clone(),
                encrypt_value(value.as_bytes(), &[recipient])?,
            );
        }
    }
    Ok(())
}

/// Save the vault: compare against original state and only re-encrypt changed values.
/// Unchanged values keep their original ciphertext for minimal git diffs.
pub fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) -> Result<(), MurkError> {
    // The full recipient set encrypts the meta blob, so every recipient —
    // including agent grants — can verify integrity and read group/grant state.
    let recipients = parse_recipients(&vault.recipients)?;

    // Agent grant pubkeys are deliberately excluded from the shared "everyone"
    // layer: a granted agent must read only the scoped values granted to it, not
    // every shared secret. They remain meta recipients (above) but never receive
    // the shared ciphertext.
    let grant_pubkeys: BTreeSet<&str> =
        current.grants.values().map(|g| g.pubkey.as_str()).collect();
    let shared_recipients: Vec<crypto::MurkRecipient> = vault
        .recipients
        .iter()
        .filter(|pk| !grant_pubkeys.contains(pk.as_str()))
        .map(|pk| crypto::parse_recipient(pk))
        .collect::<Result<_, _>>()?;

    // Check if the *shared* recipient set (recipients minus agent grants) changed
    // — that forces full re-encryption of shared values. Adding or removing an
    // agent doesn't change this set, so it doesn't needlessly churn shared
    // ciphertext (and never pulls an agent into the shared layer).
    let shared_recipients_changed = {
        let orig_grant_pubkeys: BTreeSet<&str> = original
            .grants
            .values()
            .map(|g| g.pubkey.as_str())
            .collect();
        let mut current_pks: Vec<&str> = vault
            .recipients
            .iter()
            .map(String::as_str)
            .filter(|pk| !grant_pubkeys.contains(pk))
            .collect();
        let mut original_pks: Vec<&str> = original
            .recipients
            .keys()
            .map(String::as_str)
            .filter(|pk| !orig_grant_pubkeys.contains(pk))
            .collect();
        current_pks.sort_unstable();
        original_pks.sort_unstable();
        current_pks != original_pks
    };

    // Groups whose membership changed since load — their secrets must be
    // re-encrypted even when the plaintext is unchanged, so a removed member
    // loses access (and a new one gains it).
    let changed_groups: BTreeSet<&str> = current
        .groups
        .keys()
        .chain(original.groups.keys())
        .filter(|g| current.groups.get(*g) != original.groups.get(*g))
        .map(String::as_str)
        .collect();

    let mut new_secrets = BTreeMap::new();

    // Collect all keys with a shared, scoped, or grouped value in the operator's
    // working state.
    let mut all_keys: BTreeSet<&String> = current.values.keys().collect();
    all_keys.extend(current.private.keys());
    all_keys.extend(current.grouped.keys());

    // Preserve on-disk secrets the operator can't see (other groups' values, or
    // other recipients' scoped entries). These never enter the decrypted `Murk`,
    // so without this they'd be silently dropped when a non-member saves. A key
    // the operator *deleted* was visible at load (in `original`) and is excluded,
    // so deletions still take effect.
    let original_visible: BTreeSet<&String> = original
        .values
        .keys()
        .chain(original.private.keys())
        .chain(original.grouped.keys())
        .collect();
    for key in vault.secrets.keys() {
        if !original_visible.contains(key) {
            all_keys.insert(key);
        }
    }

    for key in all_keys {
        let shared = rebuild_shared(
            key,
            vault,
            &shared_recipients,
            shared_recipients_changed,
            original,
            current,
        )?;
        let mut private = rebuild_private(key, vault, original, current)?;
        resync_grant_private(key, &mut private, original, current)?;
        let grouped = rebuild_grouped(key, vault, &changed_groups, original, current)?;
        new_secrets.insert(
            key.clone(),
            types::SecretEntry {
                shared,
                private,
                grouped,
            },
        );
    }

    vault.secrets = new_secrets;

    // Update meta — always generate a fresh BLAKE3 key on save.
    let mac_key_hex = generate_mac_key();
    let mac_key = decode_mac_key(&mac_key_hex).unwrap();
    let mac = compute_mac(vault, &current.groups, &current.grants, Some(&mac_key));
    let meta = types::Meta {
        recipients: current.recipients.clone(),
        mac,
        mac_key: Some(mac_key_hex),
        github_pins: current.github_pins.clone(),
        groups: current.groups.clone(),
        grants: current.grants.clone(),
    };
    let meta_json =
        serde_json::to_vec(&meta).map_err(|e| MurkError::Secret(format!("meta serialize: {e}")))?;
    vault.meta = encrypt_value(&meta_json, &recipients)?;

    Ok(vault::write(Path::new(vault_path), vault)?)
}

/// Compute an integrity MAC over the vault's secrets, scoped entries, grouped
/// entries, recipients, schema, and group membership.
///
/// With a key and at least one group, uses BLAKE3 keyed hash v6 (`blake3v4:`),
/// which additionally covers the grouped ciphertexts and group definitions. With
/// a key and no groups, uses v5 (`blake3v3:`) so group-free vaults stay
/// byte-identical to before groups existed. Without a key, falls back to unkeyed
/// SHA-256 v2 for legacy compatibility.
pub(crate) fn compute_mac(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    mac_key: Option<&[u8; 32]>,
) -> String {
    match mac_key {
        Some(key) if vault.schema.values().any(|e| e.revoked_at.is_some()) => {
            compute_mac_v9(vault, groups, grants, key)
        }
        Some(key) if vault.policy.is_some() => compute_mac_v8(vault, groups, grants, key),
        Some(key) if !grants.is_empty() => compute_mac_v7(vault, groups, grants, key),
        Some(key) if !groups.is_empty() => compute_mac_v6(vault, groups, key),
        Some(key) => compute_mac_v5(vault, key),
        None => compute_mac_v2(vault),
    }
}

/// Legacy MAC: covers key names, shared ciphertext, and recipients (no scoped).
fn compute_mac_v1(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    for key in vault.secrets.keys() {
        hasher.update(key.as_bytes());
        hasher.update(b"\x00");
    }

    for entry in vault.secrets.values() {
        hasher.update(entry.shared.as_bytes());
        hasher.update(b"\x00");
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        hasher.update(pk.as_bytes());
        hasher.update(b"\x00");
    }

    let digest = hasher.finalize();
    format!(
        "sha256:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    )
}

/// V2 MAC: covers key names, shared ciphertext, scoped entries, and recipients.
fn compute_mac_v2(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Hash sorted key names.
    for key in vault.secrets.keys() {
        hasher.update(key.as_bytes());
        hasher.update(b"\x00");
    }

    // Hash encrypted shared values (as stored).
    for entry in vault.secrets.values() {
        hasher.update(entry.shared.as_bytes());
        hasher.update(b"\x00");

        // Hash scoped entries (sorted by pubkey for determinism).
        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            hasher.update(pk.as_bytes());
            hasher.update(b"\x01");
            hasher.update(entry.private[pk].as_bytes());
            hasher.update(b"\x00");
        }
    }

    // Hash sorted recipient pubkeys.
    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        hasher.update(pk.as_bytes());
        hasher.update(b"\x00");
    }

    let digest = hasher.finalize();
    format!(
        "sha256v2:{}",
        digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    )
}

/// V3 MAC: BLAKE3 keyed hash over the same inputs as v2.
fn compute_mac_v3(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3:{hash}")
}

/// V4 MAC: BLAKE3 keyed hash over secrets, recipients, AND schema.
/// Prefix `blake3v2:` distinguishes from v3 which omitted schema.
fn compute_mac_v4(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    // Schema: include descriptions, examples, and tags for each key.
    // Uses 0x02 separator to distinguish from secrets/recipients data.
    for (key_name, entry) in &vault.schema {
        data.push(0x02);
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(entry.description.as_bytes());
        data.push(0x00);
        if let Some(example) = &entry.example {
            data.extend_from_slice(example.as_bytes());
        }
        data.push(0x00);
        for tag in &entry.tags {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v2:{hash}")
}

/// V5 MAC: extends v4 to also cover each schema entry's lifecycle metadata —
/// `created`, `updated`, `rotation_interval_days`, and `expires_at`. This makes
/// rotation policy tamper-evident, so strict mode can treat it as a trustworthy
/// machine-checkable signal rather than freely-editable plaintext. Prefix
/// `blake3v3:` distinguishes it from v4 which stopped at description/example/tags.
fn compute_mac_v5(vault: &types::Vault, key: &[u8; 32]) -> String {
    let mut data = Vec::new();

    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    // Schema: description, example, tags (as in v4) plus lifecycle metadata.
    // Optional fields are emitted as their bytes (empty when absent) followed by
    // a 0x00 terminator, so present/absent stays deterministic. `0x02` separates
    // each schema entry from the secrets/recipients stream above.
    for (key_name, entry) in &vault.schema {
        data.push(0x02);
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(entry.description.as_bytes());
        data.push(0x00);
        if let Some(example) = &entry.example {
            data.extend_from_slice(example.as_bytes());
        }
        data.push(0x00);
        for tag in &entry.tags {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }
        // Lifecycle metadata (new in v5). Strings go in as UTF-8; the interval
        // goes in as its decimal text for consistency with the rest of the stream.
        if let Some(created) = &entry.created {
            data.extend_from_slice(created.as_bytes());
        }
        data.push(0x00);
        if let Some(updated) = &entry.updated {
            data.extend_from_slice(updated.as_bytes());
        }
        data.push(0x00);
        if let Some(days) = entry.rotation_interval_days {
            data.extend_from_slice(days.to_string().as_bytes());
        }
        data.push(0x00);
        if let Some(expires) = &entry.expires_at {
            data.extend_from_slice(expires.as_bytes());
        }
        data.push(0x00);
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v3:{hash}")
}

/// Append the v5/v6 schema byte stream to `data`. Kept identical to the inline
/// loop in `compute_mac_v5` so v6 reuses the exact schema encoding without
/// risking a change to v5's bytes.
fn schema_mac_bytes(vault: &types::Vault, data: &mut Vec<u8>) {
    for (key_name, entry) in &vault.schema {
        data.push(0x02);
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(entry.description.as_bytes());
        data.push(0x00);
        if let Some(example) = &entry.example {
            data.extend_from_slice(example.as_bytes());
        }
        data.push(0x00);
        for tag in &entry.tags {
            data.extend_from_slice(tag.as_bytes());
            data.push(0x00);
        }
        if let Some(created) = &entry.created {
            data.extend_from_slice(created.as_bytes());
        }
        data.push(0x00);
        if let Some(updated) = &entry.updated {
            data.extend_from_slice(updated.as_bytes());
        }
        data.push(0x00);
        if let Some(days) = entry.rotation_interval_days {
            data.extend_from_slice(days.to_string().as_bytes());
        }
        data.push(0x00);
        if let Some(expires) = &entry.expires_at {
            data.extend_from_slice(expires.as_bytes());
        }
        data.push(0x00);
    }
}

/// Append the v6 byte stream (secrets, scoped, grouped ciphertexts, recipients,
/// schema, and group definitions) to `data`. Factored out so v7 can extend the
/// exact same bytes without risking a change to v6's encoding.
fn v6_mac_bytes(vault: &types::Vault, groups: &BTreeMap<String, Vec<String>>, data: &mut Vec<u8>) {
    for key_name in vault.secrets.keys() {
        data.extend_from_slice(key_name.as_bytes());
        data.push(0x00);
    }

    for entry in vault.secrets.values() {
        data.extend_from_slice(entry.shared.as_bytes());
        data.push(0x00);

        let mut scoped_pks: Vec<&String> = entry.private.keys().collect();
        scoped_pks.sort();
        for pk in scoped_pks {
            data.extend_from_slice(pk.as_bytes());
            data.push(0x01);
            data.extend_from_slice(entry.private[pk].as_bytes());
            data.push(0x00);
        }

        // Grouped ciphertexts, sorted by group name. `0x03` marks each entry so
        // the group stream can't be confused with the scoped (`0x01`) stream.
        let mut group_names: Vec<&String> = entry.grouped.keys().collect();
        group_names.sort();
        for g in group_names {
            data.push(0x03);
            data.extend_from_slice(g.as_bytes());
            data.push(0x00);
            data.extend_from_slice(entry.grouped[g].as_bytes());
            data.push(0x00);
        }
    }

    let mut pks = vault.recipients.clone();
    pks.sort();
    for pk in &pks {
        data.extend_from_slice(pk.as_bytes());
        data.push(0x00);
    }

    schema_mac_bytes(vault, data);

    // Group definitions (sorted by name; members sorted). `0x04` separates each
    // group, `0x05` each member, so membership can't be tampered with undetected.
    for (name, members) in groups {
        data.push(0x04);
        data.extend_from_slice(name.as_bytes());
        data.push(0x00);
        let mut sorted = members.clone();
        sorted.sort();
        for member in &sorted {
            data.push(0x05);
            data.extend_from_slice(member.as_bytes());
        }
    }
}

/// v6 MAC (`blake3v4:`). Extends v5 with the per-secret grouped ciphertexts and
/// the group membership map, so a named group's members and the values encrypted
/// to them cannot be tampered with undetected. Only emitted once a vault has at
/// least one group; group-free vaults keep writing v5 and stay byte-identical.
fn compute_mac_v6(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v6_mac_bytes(vault, groups, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v4:{hash}")
}

/// v7 MAC (`blake3v5:`). Extends v6 with agent grant metadata — each grant's
/// name, ephemeral pubkey, sorted scope, issued_at, expires_at, and issuer — so
/// a grant's TTL and scope cannot be tampered with undetected. Only emitted once
/// a vault has at least one grant; grant-free vaults keep writing v5/v6 and stay
/// byte-identical.
/// Append the v7 byte stream (v6 bytes plus agent grant metadata) to `data`.
/// Factored out so v8 can extend the exact same bytes without risking a change
/// to v7's encoding.
fn v7_mac_bytes(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    data: &mut Vec<u8>,
) {
    v6_mac_bytes(vault, groups, data);

    // Grants (BTreeMap → sorted by name). `0x06` separates each grant; fixed
    // fields are 0x00-terminated; each scope key is prefixed `0x07` (sorted), so
    // the grant stream can't be confused with the group (`0x04`/`0x05`) stream.
    for (name, grant) in grants {
        data.push(0x06);
        data.extend_from_slice(name.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.pubkey.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.issued_at.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.expires_at.as_bytes());
        data.push(0x00);
        data.extend_from_slice(grant.issuer.as_bytes());
        data.push(0x00);
        let mut scope = grant.scope.clone();
        scope.sort();
        for k in &scope {
            data.push(0x07);
            data.extend_from_slice(k.as_bytes());
        }
    }
}

fn compute_mac_v7(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v7_mac_bytes(vault, groups, grants, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v5:{hash}")
}

/// Append the v8 byte stream (v7 bytes plus the header policy block) to `data`.
/// Factored out so v9 can extend the exact same bytes without risking a change
/// to v8's encoding.
fn v8_mac_bytes(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    data: &mut Vec<u8>,
) {
    v7_mac_bytes(vault, groups, grants, data);

    // Policy (header). `0x08` opens the policy block (present only when a policy
    // exists, so Some-but-empty is distinct from None). Each agent allow-tag is
    // length-prefixed (4-byte big-endian) and sorted, so the byte stream is
    // unambiguous regardless of tag contents — a crafted tag can't forge a
    // boundary (e.g. `["a\tb"]` and `["a", "b"]` hash differently). New policy
    // fields extend this block.
    if let Some(policy) = &vault.policy {
        data.push(0x08);
        let mut tags = policy.agent_allow_tags.clone();
        tags.sort();
        for tag in &tags {
            let bytes = tag.as_bytes();
            // usize→u64 is lossless on supported targets; fixed-width length
            // prefix keeps the encoding unambiguous.
            data.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            data.extend_from_slice(bytes);
        }
    }
}

/// v8 MAC (`blake3v6:`). Extends v7 with the plaintext header policy object, so a
/// vault's agent access policy cannot be weakened or stripped undetected. Only
/// emitted once a vault has a policy; policy-free vaults keep writing v5/v6/v7
/// and stay byte-identical.
fn compute_mac_v8(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v8_mac_bytes(vault, groups, grants, &mut data);
    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v6:{hash}")
}

/// v9 MAC (`blake3v7:`). Extends v8 with each schema entry's `revoked_at` marker,
/// so the "still owed a rotation since a revoke" flag is tamper-evident — an
/// attacker editing `.murk` can't silently clear it. Only emitted once a vault
/// has at least one `revoked_at` set; vaults without one keep writing v5–v8 and
/// stay byte-identical.
fn compute_mac_v9(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    key: &[u8; 32],
) -> String {
    let mut data = Vec::new();
    v8_mac_bytes(vault, groups, grants, &mut data);

    // Revoked-at markers, in schema order (BTreeMap → sorted by key name). `0x09`
    // opens each marker so the stream can't be confused with the schema (`0x02`)
    // or policy (`0x08`) blocks; absent markers emit nothing, so a vault that
    // sets one then clears it hashes identically to one that never set it.
    for (key_name, entry) in &vault.schema {
        if let Some(revoked_at) = &entry.revoked_at {
            data.push(0x09);
            data.extend_from_slice(key_name.as_bytes());
            data.push(0x00);
            data.extend_from_slice(revoked_at.as_bytes());
            data.push(0x00);
        }
    }

    let hash = blake3::keyed_hash(key, &data);
    format!("blake3v7:{hash}")
}

/// Verify a stored MAC against the vault, accepting v1, v2, blake3, blake3v2,
/// blake3v3, blake3v4, blake3v5, blake3v6, and blake3v7 schemes.
pub(crate) fn verify_mac(
    vault: &types::Vault,
    groups: &BTreeMap<String, Vec<String>>,
    grants: &BTreeMap<String, types::GrantEntry>,
    stored_mac: &str,
    mac_key: Option<&[u8; 32]>,
) -> bool {
    use constant_time_eq::constant_time_eq;

    // `revoked_at` is only covered by v9 (`blake3v7:`). A vault carrying one but
    // stamped with an older MAC is tampered or inconsistent — reject it so an
    // attacker can't clear a pending-rotation flag by downgrading the MAC.
    if vault.schema.values().any(|e| e.revoked_at.is_some()) && !stored_mac.starts_with("blake3v7:")
    {
        return false;
    }

    // Policy is covered by v8 (`blake3v6:`) and v9 (`blake3v7:`). A vault carrying
    // a policy but stamped with an older MAC is tampered or inconsistent — reject
    // it so an attacker can't strip or weaken the policy by downgrading the MAC.
    if vault.policy.is_some()
        && !stored_mac.starts_with("blake3v6:")
        && !stored_mac.starts_with("blake3v7:")
    {
        return false;
    }

    // Grant metadata is covered by v7 (`blake3v5:`) and up. A vault carrying
    // grants but stamped with an older MAC is tampered or inconsistent.
    if !grants.is_empty()
        && !stored_mac.starts_with("blake3v5:")
        && !stored_mac.starts_with("blake3v6:")
        && !stored_mac.starts_with("blake3v7:")
    {
        return false;
    }

    // Group data is covered by v6 and up. A vault carrying any grouped ciphertext
    // or group membership but stamped with an older MAC is either tampered (an
    // attacker injected a `grouped` entry that the old MAC ignores, then relies on
    // group-before-shared resolution) or inconsistent. Reject it rather than
    // verify against a scheme that doesn't cover groups.
    let touches_groups =
        !groups.is_empty() || vault.secrets.values().any(|e| !e.grouped.is_empty());
    if touches_groups
        && !stored_mac.starts_with("blake3v4:")
        && !stored_mac.starts_with("blake3v5:")
        && !stored_mac.starts_with("blake3v6:")
        && !stored_mac.starts_with("blake3v7:")
    {
        return false;
    }

    let expected = if stored_mac.starts_with("blake3v7:") {
        match mac_key {
            Some(key) => compute_mac_v9(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v6:") {
        match mac_key {
            Some(key) => compute_mac_v8(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v5:") {
        match mac_key {
            Some(key) => compute_mac_v7(vault, groups, grants, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v4:") {
        match mac_key {
            Some(key) => compute_mac_v6(vault, groups, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v3:") {
        match mac_key {
            Some(key) => compute_mac_v5(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3v2:") {
        match mac_key {
            Some(key) => compute_mac_v4(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("blake3:") {
        match mac_key {
            Some(key) => compute_mac_v3(vault, key),
            None => return false,
        }
    } else if stored_mac.starts_with("sha256v2:") {
        compute_mac_v2(vault)
    } else if stored_mac.starts_with("sha256:") {
        compute_mac_v1(vault)
    } else {
        return false;
    };
    constant_time_eq(stored_mac.as_bytes(), expected.as_bytes())
}

/// Generate a random 32-byte BLAKE3 MAC key, returned as hex.
pub(crate) fn generate_mac_key() -> String {
    let key: [u8; 32] = rand::random();
    key.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Decode a hex-encoded 32-byte key.
pub(crate) fn decode_mac_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(key)
}

/// Generate an ISO-8601 UTC timestamp.
pub(crate) fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::collections::BTreeMap;
    use std::fs;

    use crate::testutil::ENV_LOCK;

    #[test]
    fn resolve_vault_path_finds_in_parent_dir() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        // Create a fake git repo with a vault at the root and a nested subdir.
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".murk"), "{}").unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested).unwrap();
        let got = resolve_vault_path(".murk");
        std::env::set_current_dir(prev).unwrap();

        assert_eq!(
            std::fs::canonicalize(&got).unwrap(),
            std::fs::canonicalize(dir.path().join(".murk")).unwrap()
        );
    }

    #[test]
    fn resolve_vault_path_returns_as_is_when_found_in_cwd() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".murk"), "{}").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let got = resolve_vault_path(".murk");
        std::env::set_current_dir(prev).unwrap();
        assert_eq!(got, ".murk");
    }

    #[test]
    fn resolve_vault_path_passes_through_explicit_paths() {
        assert_eq!(resolve_vault_path("/abs/path.murk"), "/abs/path.murk");
        assert_eq!(resolve_vault_path("./foo.murk"), "./foo.murk");
        assert_eq!(resolve_vault_path("sub/dir.murk"), "sub/dir.murk");
    }

    #[test]
    fn resolve_vault_path_stops_at_git_root() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        // Vault lives OUTSIDE the git repo; traversal should not find it.
        fs::write(dir.path().join(".murk"), "{}").unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        let nested = repo.join("sub");
        fs::create_dir(&nested).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested).unwrap();
        let got = resolve_vault_path(".murk");
        std::env::set_current_dir(prev).unwrap();

        // Unchanged — we stopped at the git root and never saw the outer vault.
        assert_eq!(got, ".murk");
    }

    #[test]
    fn encrypt_decrypt_value_roundtrip() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let encoded = encrypt_value(b"hello world", &[recipient]).unwrap();
        let decrypted = decrypt_value(&encoded, &identity).unwrap();
        assert_eq!(&decrypted[..], b"hello world");
    }

    #[test]
    fn decrypt_value_invalid_base64() {
        let (secret, _) = generate_keypair();
        let identity = make_identity(&secret);

        let result = decrypt_value("not!valid!base64!!!", &identity);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid base64"));
    }

    #[test]
    fn encrypt_value_multiple_recipients() {
        let (secret_a, pubkey_a) = generate_keypair();
        let (secret_b, pubkey_b) = generate_keypair();

        let recipients = vec![make_recipient(&pubkey_a), make_recipient(&pubkey_b)];
        let encoded = encrypt_value(b"shared secret", &recipients).unwrap();

        // Both can decrypt.
        let id_a = make_identity(&secret_a);
        let id_b = make_identity(&secret_b);
        assert_eq!(
            &decrypt_value(&encoded, &id_a).unwrap()[..],
            b"shared secret"
        );
        assert_eq!(
            &decrypt_value(&encoded, &id_b).unwrap()[..],
            b"shared secret"
        );
    }

    #[test]
    fn decrypt_value_wrong_key_fails() {
        let (_, pubkey) = generate_keypair();
        let (wrong_secret, _) = generate_keypair();

        let recipient = make_recipient(&pubkey);
        let wrong_identity = make_identity(&wrong_secret);

        let encoded = encrypt_value(b"secret", &[recipient]).unwrap();
        assert!(decrypt_value(&encoded, &wrong_identity).is_err());
    }

    #[test]
    fn compute_mac_deterministic() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac1 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        let mac2 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_eq!(mac1, mac2);
        assert!(mac1.starts_with("blake3v3:"));

        // Without key, falls back to sha256v2
        let mac_legacy = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            None,
        );
        assert!(mac_legacy.starts_with("sha256v2:"));
    }

    #[test]
    fn compute_mac_changes_with_different_secrets() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac_empty = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mac_with_secret = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_empty, mac_with_secret);
    }

    #[test]
    fn compute_mac_changes_with_different_recipients() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac1 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        vault.recipients.push("age1xyz".into());
        let mac2 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn save_vault_preserves_unchanged_ciphertext() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_save_unchanged");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"original", std::slice::from_ref(&recipient)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: shared.clone(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("original"))]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let current = original.clone();
        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert_eq!(vault.secrets["KEY1"].shared, shared);

        let mut changed = current.clone();
        changed
            .values
            .insert("KEY1".into(), crate::testutil::secret("modified"));
        save_vault(path.to_str().unwrap(), &mut vault, &original, &changed).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        let decrypted = decrypt_value(&vault.secrets["KEY1"].shared, &identity).unwrap();
        assert_eq!(&decrypted[..], b"modified");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_adds_new_secret() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_add");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared,
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let mut current = original.clone();
        current
            .values
            .insert("KEY2".into(), crate::testutil::secret("val2"));

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets.contains_key("KEY1"));
        assert!(vault.secrets.contains_key("KEY2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_removes_deleted_secret() {
        let (_, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_save_remove");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );
        vault.secrets.insert(
            "KEY2".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val2", std::slice::from_ref(&recipient)).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([
                ("KEY1".into(), crate::testutil::secret("val1")),
                ("KEY2".into(), crate::testutil::secret("val2")),
            ]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let mut current = original.clone();
        current.values.remove("KEY2");

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets.contains_key("KEY1"));
        assert!(!vault.secrets.contains_key("KEY2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_reencrypts_all_on_recipient_change() {
        let (secret1, pubkey1) = generate_keypair();
        let (_, pubkey2) = generate_keypair();
        let recipient1 = make_recipient(&pubkey1);

        let dir = std::env::temp_dir().join("murk_test_save_reencrypt");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"val1", std::slice::from_ref(&recipient1)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey1.clone(), pubkey2.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: shared.clone(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey1.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        let mut current_recipients = HashMap::new();
        current_recipients.insert(pubkey1.clone(), "alice".into());
        current_recipients.insert(pubkey2.clone(), "bob".into());
        let current = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: current_recipients,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert_ne!(vault.secrets["KEY1"].shared, shared);

        let identity1 = make_identity(&secret1);
        let decrypted = decrypt_value(&vault.secrets["KEY1"].shared, &identity1).unwrap();
        assert_eq!(&decrypted[..], b"val1");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_vault_scoped_entry_lifecycle() {
        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_save_scoped");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let shared = encrypt_value(b"shared_val", std::slice::from_ref(&recipient)).unwrap();
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared,
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("shared_val"))]),
            recipients: recipients_map.clone(),
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        // Add a scoped override.
        let mut current = original.clone();
        let mut key_scoped = HashMap::new();
        key_scoped.insert(pubkey.clone(), crate::testutil::secret("my_override"));
        current.private.insert("KEY1".into(), key_scoped);

        save_vault(path.to_str().unwrap(), &mut vault, &original, &current).unwrap();

        assert!(vault.secrets["KEY1"].private.contains_key(&pubkey));
        let scoped_val = decrypt_value(&vault.secrets["KEY1"].private[&pubkey], &identity).unwrap();
        assert_eq!(&scoped_val[..], b"my_override");

        // Now remove the scoped override.
        let original_with_scoped = current.clone();
        let mut current_no_scoped = original_with_scoped.clone();
        current_no_scoped.private.remove("KEY1");

        save_vault(
            path.to_str().unwrap(),
            &mut vault,
            &original_with_scoped,
            &current_no_scoped,
        )
        .unwrap();

        assert!(vault.secrets["KEY1"].private.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_validates_mac() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);
        let _identity = make_identity(&secret);

        let dir = std::env::temp_dir().join("murk_test_load_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret, save it (computes valid MAC).
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        // save_vault needs MURK_KEY set to encrypt meta.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Now tamper: change the ciphertext in the saved vault file.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.secrets.get_mut("KEY1").unwrap().shared =
            encrypt_value(b"tampered", &[recipient]).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Load should fail MAC validation.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_succeeds_with_valid_mac() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_valid_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient]).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Load should succeed.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(result.is_ok());
        let (_, murk, _) = result.unwrap();
        assert_eq!(murk.values["KEY1"].as_str(), "val1");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_not_a_recipient() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, _pubkey) = generate_keypair();
        let (other_secret, other_pubkey) = generate_keypair();
        let other_recipient = make_recipient(&other_pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_not_recipient");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault encrypted to `other`, not to `secret`.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![other_pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[other_recipient]).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        // Save via save_vault (needs the other key for re-encryption).
        let mut recipients_map = HashMap::new();
        recipients_map.insert(other_pubkey.clone(), "other".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &other_secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Now try to load with a key that is NOT a recipient.
        unsafe { std::env::set_var("MURK_KEY", secret) };
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let Err(err) = result else {
            panic!("expected load_vault to fail for non-recipient");
        };
        // Non-recipient can't decrypt meta, so integrity check fails first.
        let msg = err.to_string();
        assert!(
            msg.contains("decryption failed")
                || msg.contains("no meta")
                || msg.contains("tampered"),
            "expected decryption or integrity failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_zero_secrets() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();

        let dir = std::env::temp_dir().join("murk_test_load_zero_secrets");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with no secrets at all.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::new(),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        assert!(result.is_ok());
        let (_, murk, _) = result.unwrap();
        assert!(murk.values.is_empty());
        assert!(murk.private.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_stripped_meta_with_secrets_fails() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_stripped_meta");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret and a valid MAC via save_vault.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", &[recipient]).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let original = types::Murk {
            values: HashMap::from([("KEY1".into(), crate::testutil::secret("val1"))]),
            recipients: recipients_map,
            private: HashMap::new(),
            legacy_mac: false,
            github_pins: HashMap::new(),
            ..Default::default()
        };

        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        save_vault(path.to_str().unwrap(), &mut vault, &original, &original).unwrap();

        // Tamper: strip meta field entirely.
        let mut tampered: types::Vault =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.meta = String::new();
        fs::write(&path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();

        // Load should fail: secrets present but no meta.
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_vault_empty_mac_with_secrets_fails() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (secret, pubkey) = generate_keypair();
        let recipient = make_recipient(&pubkey);

        let dir = std::env::temp_dir().join("murk_test_load_empty_mac");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        // Build a vault with one secret.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec![pubkey.clone()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.secrets.insert(
            "KEY1".into(),
            types::SecretEntry {
                shared: encrypt_value(b"val1", std::slice::from_ref(&recipient)).unwrap(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        // Manually create meta with empty MAC and encrypt it.
        let mut recipients_map = HashMap::new();
        recipients_map.insert(pubkey.clone(), "alice".into());
        let meta = types::Meta {
            recipients: recipients_map,
            mac: String::new(),
            mac_key: None,
            github_pins: HashMap::new(),
            ..Default::default()
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        vault.meta = encrypt_value(&meta_json, &[recipient]).unwrap();

        // Write the vault to disk.
        crate::vault::write(Path::new(path.to_str().unwrap()), &vault).unwrap();

        // Load should fail: secrets present but MAC is empty.
        unsafe { std::env::set_var("MURK_KEY", &secret) };
        unsafe { std::env::remove_var("MURK_KEY_FILE") };
        let result = load_vault(path.to_str().unwrap());
        unsafe { std::env::remove_var("MURK_KEY") };

        let err = result.expect_err("expected MAC validation to fail");
        assert!(
            err.to_string().contains("integrity check failed"),
            "expected integrity check failure, got: {err}"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compute_mac_changes_with_scoped_entries() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        vault.secrets.insert(
            "KEY".into(),
            types::SecretEntry {
                shared: "ciphertext".into(),
                private: BTreeMap::new(),
                grouped: std::collections::BTreeMap::default(),
            },
        );

        let key = [0u8; 32];
        let mac_no_scoped = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        vault
            .secrets
            .get_mut("KEY")
            .unwrap()
            .private
            .insert("age1bob".into(), "scoped-ct".into());

        let mac_with_scoped = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_no_scoped, mac_with_scoped);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustively enumerates every MAC scheme
    fn verify_mac_accepts_v1_prefix() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let v1_mac = compute_mac_v1(&vault);
        let v2_mac = compute_mac_v2(&vault);
        let v3_mac = compute_mac_v3(&vault, &key);
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v1_mac,
            None
        ));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v2_mac,
            None
        ));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v3_mac,
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "sha256:bogus",
            None
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "blake3:bogus",
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "blake3v2:bogus",
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "blake3v3:bogus",
            Some(&key)
        ));
        assert!(!verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            "unknown:prefix",
            None
        ));

        // v4 (blake3v2) — includes schema; still accepted as legacy
        let v4_mac = compute_mac_v4(&vault, &key);
        assert!(v4_mac.starts_with("blake3v2:"));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v4_mac,
            Some(&key)
        ));

        // v5 (blake3v3) — current scheme, includes lifecycle metadata
        let v5_mac = compute_mac_v5(&vault, &key);
        assert!(v5_mac.starts_with("blake3v3:"));
        assert!(verify_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &v5_mac,
            Some(&key)
        ));
        // compute_mac emits v5 when there are no groups
        assert!(
            compute_mac(
                &vault,
                &std::collections::BTreeMap::new(),
                &std::collections::BTreeMap::new(),
                Some(&key)
            )
            .starts_with("blake3v3:")
        );

        // v6 (blake3v4) — emitted once a group exists; verifies and round-trips
        let groups = BTreeMap::from([("prod".to_string(), vec!["age1abc".to_string()])]);
        let v6_mac = compute_mac(
            &vault,
            &groups,
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert!(v6_mac.starts_with("blake3v4:"));
        assert!(verify_mac(
            &vault,
            &groups,
            &std::collections::BTreeMap::new(),
            &v6_mac,
            Some(&key)
        ));
        // Tampering with membership changes the MAC.
        let tampered = BTreeMap::from([(
            "prod".to_string(),
            vec!["age1abc".to_string(), "age1evil".to_string()],
        )]);
        assert!(!verify_mac(
            &vault,
            &tampered,
            &std::collections::BTreeMap::new(),
            &v6_mac,
            Some(&key)
        ));
    }

    #[test]
    fn verify_mac_rejects_grouped_under_legacy_prefix() {
        // A v5 (blake3v3) MAC doesn't cover grouped ciphertext. Injecting a
        // grouped entry must not verify against the old scheme — otherwise an
        // attacker without a key could add a group value that wins on read.
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [7u8; 32];
        let no_groups = BTreeMap::new();
        let v5_mac = compute_mac(
            &vault,
            &no_groups,
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert!(v5_mac.starts_with("blake3v3:"));
        assert!(verify_mac(
            &vault,
            &no_groups,
            &std::collections::BTreeMap::new(),
            &v5_mac,
            Some(&key)
        ));

        // Attacker injects a grouped entry; the v5 MAC is now invalid for it.
        vault.secrets.insert(
            "STOLEN".into(),
            types::SecretEntry {
                grouped: BTreeMap::from([("prod".to_string(), "injected-ct".to_string())]),
                ..Default::default()
            },
        );
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &std::collections::BTreeMap::new(),
            &v5_mac,
            Some(&key)
        ));
    }

    #[test]
    fn mac_v7_covers_grant_metadata() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into(), "age1agent".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [9u8; 32];
        let no_groups = BTreeMap::new();

        // compute_mac emits v7 (blake3v5) once a grant exists.
        let grants = BTreeMap::from([(
            "codex".to_string(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                scope: vec!["STRIPE_KEY".into()],
                issued_at: "2026-02-28T00:00:00Z".into(),
                expires_at: "2026-02-28T02:00:00Z".into(),
                issuer: "age1abc".into(),
            },
        )]);
        let v7_mac = compute_mac(&vault, &no_groups, &grants, Some(&key));
        assert!(v7_mac.starts_with("blake3v5:"));
        assert!(verify_mac(&vault, &no_groups, &grants, &v7_mac, Some(&key)));

        // Widening the scope (or extending the TTL) changes the MAC.
        let tampered = BTreeMap::from([(
            "codex".to_string(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                scope: vec!["STRIPE_KEY".into(), "PROD_DB".into()],
                issued_at: "2026-02-28T00:00:00Z".into(),
                expires_at: "2026-02-28T02:00:00Z".into(),
                issuer: "age1abc".into(),
            },
        )]);
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &tampered,
            &v7_mac,
            Some(&key)
        ));
    }

    #[test]
    fn verify_mac_rejects_grants_under_legacy_prefix() {
        // Grant metadata is only covered by v7. A vault carrying grants but
        // stamped with an older (group-era) MAC must not verify — otherwise an
        // attacker could fabricate or extend a grant the MAC ignores.
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [3u8; 32];
        let no_groups = BTreeMap::new();
        let grants = BTreeMap::from([(
            "codex".to_string(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                scope: vec!["STRIPE_KEY".into()],
                issued_at: "2026-02-28T00:00:00Z".into(),
                expires_at: "2026-02-28T02:00:00Z".into(),
                issuer: "age1abc".into(),
            },
        )]);
        // A v6 MAC (no grants in the digest) must be rejected once grants exist.
        let v6_mac = compute_mac_v6(&vault, &no_groups, &key);
        assert!(v6_mac.starts_with("blake3v4:"));
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &grants,
            &v6_mac,
            Some(&key)
        ));
    }

    #[test]
    fn mac_v8_covers_policy() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: Some(types::Policy {
                agent_allow_tags: vec!["agents".into()],
            }),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [11u8; 32];
        let no_groups = BTreeMap::new();
        let no_grants = BTreeMap::new();

        // compute_mac emits v8 (blake3v6) once a policy exists.
        let v8_mac = compute_mac(&vault, &no_groups, &no_grants, Some(&key));
        assert!(v8_mac.starts_with("blake3v6:"));
        assert!(verify_mac(
            &vault,
            &no_groups,
            &no_grants,
            &v8_mac,
            Some(&key)
        ));

        // Weakening the policy (adding an allowed tag) changes the MAC.
        vault.policy = Some(types::Policy {
            agent_allow_tags: vec!["agents".into(), "production".into()],
        });
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &no_grants,
            &v8_mac,
            Some(&key)
        ));
    }

    #[test]
    fn mac_v8_policy_tags_are_unambiguous() {
        // A crafted tag must not collide with a different tag list: ["a\tb"] and
        // ["a", "b"] previously hashed identically under a separator-only scheme.
        let base = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [7u8; 32];
        let groups = BTreeMap::new();
        let grants = BTreeMap::new();

        let mut a = base.clone();
        a.policy = Some(types::Policy {
            agent_allow_tags: vec!["a\tb".into()],
        });
        let mut b = base.clone();
        b.policy = Some(types::Policy {
            agent_allow_tags: vec!["a".into(), "b".into()],
        });

        let mac_a = compute_mac(&a, &groups, &grants, Some(&key));
        let mac_b = compute_mac(&b, &groups, &grants, Some(&key));
        assert_ne!(mac_a, mac_b, "distinct tag lists must not share a MAC");
    }

    #[test]
    fn verify_mac_rejects_policy_under_legacy_prefix() {
        // Policy is only covered by v8. A vault carrying a policy but stamped
        // with an older MAC must not verify — otherwise an attacker could strip
        // or weaken the policy by downgrading the MAC.
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: Some(types::Policy {
                agent_allow_tags: vec!["agents".into()],
            }),
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        let key = [5u8; 32];
        let no_groups = BTreeMap::new();
        let no_grants = BTreeMap::new();
        // A v5 MAC (no policy in the digest) must be rejected once a policy exists.
        let v5_mac = compute_mac_v5(&vault, &key);
        assert!(v5_mac.starts_with("blake3v3:"));
        assert!(!verify_mac(
            &vault,
            &no_groups,
            &no_grants,
            &v5_mac,
            Some(&key)
        ));
    }

    #[test]
    fn compute_mac_v5_covers_rotation_metadata() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "Main API key".into(),
                updated: Some("2026-02-28T00:00:00Z".into()),
                ..Default::default()
            },
        );

        let key = [0u8; 32];
        let baseline = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        // Setting a rotation interval changes the MAC — tamper-evident.
        vault
            .schema
            .get_mut("API_KEY")
            .unwrap()
            .rotation_interval_days = Some(90);
        let with_interval = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(baseline, with_interval);

        // So does an expiry.
        vault.schema.get_mut("API_KEY").unwrap().expires_at = Some("2026-09-01T23:59:59Z".into());
        let with_expiry = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(with_interval, with_expiry);

        // v4 (which ignores these fields) is blind to the change — the reason
        // v5 exists. Confirms the new fields really are what moved the MAC.
        let mut cleared = vault.clone();
        cleared
            .schema
            .get_mut("API_KEY")
            .unwrap()
            .rotation_interval_days = None;
        cleared.schema.get_mut("API_KEY").unwrap().expires_at = None;
        assert_eq!(compute_mac_v4(&vault, &key), compute_mac_v4(&cleared, &key));
    }

    #[test]
    fn compute_mac_v9_covers_revoked_at() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };
        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "Main API key".into(),
                updated: Some("2026-02-28T00:00:00Z".into()),
                ..Default::default()
            },
        );
        let key = [0u8; 32];
        let groups = BTreeMap::new();
        let grants = BTreeMap::new();

        // No marker → v8 falls through to v5 (no policy/grants/groups here).
        let baseline = compute_mac(&vault, &groups, &grants, Some(&key));
        assert!(baseline.starts_with("blake3v3:"));

        // Setting `revoked_at` switches the written scheme to v9 and changes the MAC.
        vault.schema.get_mut("API_KEY").unwrap().revoked_at = Some("2026-06-18T00:00:00Z".into());
        let with_marker = compute_mac(&vault, &groups, &grants, Some(&key));
        assert!(with_marker.starts_with("blake3v7:"));
        assert_ne!(baseline, with_marker);

        // The v9 MAC round-trips, and a downgraded (v8) MAC is rejected while the
        // marker is present — an attacker can't clear it by stamping an older scheme.
        assert!(verify_mac(
            &vault,
            &groups,
            &grants,
            &with_marker,
            Some(&key)
        ));
        let v8_mac = compute_mac_v8(&vault, &groups, &grants, &key);
        assert!(!verify_mac(&vault, &groups, &grants, &v8_mac, Some(&key)));

        // v8 (which ignores the marker) is blind to it — confirms `revoked_at` is
        // what moved the v9 digest, mirroring the v5 rotation-metadata test.
        let mut cleared = vault.clone();
        cleared.schema.get_mut("API_KEY").unwrap().revoked_at = None;
        assert_eq!(
            compute_mac_v8(&vault, &groups, &grants, &key),
            compute_mac_v8(&cleared, &groups, &grants, &key)
        );
    }

    #[test]
    fn compute_mac_changes_with_schema() {
        let mut vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key = [0u8; 32];
        let mac_no_schema = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );

        vault.schema.insert(
            "API_KEY".into(),
            types::SchemaEntry {
                description: "Main API key".into(),
                tags: vec!["deploy".into()],
                ..Default::default()
            },
        );

        let mac_with_schema = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_no_schema, mac_with_schema);

        // Changing a tag changes the MAC
        let mac_before_retag = mac_with_schema;
        vault.schema.get_mut("API_KEY").unwrap().tags = vec!["ops".into()];
        let mac_after_retag = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key),
        );
        assert_ne!(mac_before_retag, mac_after_retag);
    }

    #[test]
    fn mac_key_roundtrip() {
        let hex = generate_mac_key();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let key = decode_mac_key(&hex).expect("valid hex should decode");
        // Re-encode and compare.
        let rehex = key.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, rehex);
    }

    #[test]
    fn decode_mac_key_rejects_bad_input() {
        assert!(decode_mac_key("").is_none());
        assert!(decode_mac_key("tooshort").is_none());
        assert!(decode_mac_key(&"zz".repeat(32)).is_none()); // invalid hex
        assert!(decode_mac_key(&"aa".repeat(31)).is_none()); // 31 bytes
        assert!(decode_mac_key(&"aa".repeat(33)).is_none()); // 33 bytes
    }

    #[test]
    fn blake3_mac_different_key_different_mac() {
        let vault = types::Vault {
            version: types::VAULT_VERSION.into(),
            created: "2026-02-28T00:00:00Z".into(),
            vault_name: ".murk".into(),
            repo: String::new(),
            recipients: vec!["age1abc".into()],
            schema: BTreeMap::new(),
            policy: None,
            secrets: BTreeMap::new(),
            meta: String::new(),
        };

        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let mac1 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key1),
        );
        let mac2 = compute_mac(
            &vault,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            Some(&key2),
        );
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn valid_key_names() {
        assert!(is_valid_key_name("DATABASE_URL"));
        assert!(is_valid_key_name("_PRIVATE"));
        assert!(is_valid_key_name("A"));
        assert!(is_valid_key_name("key123"));
    }

    #[test]
    fn invalid_key_names() {
        assert!(!is_valid_key_name(""));
        assert!(!is_valid_key_name("123_START"));
        assert!(!is_valid_key_name("KEY-NAME"));
        assert!(!is_valid_key_name("KEY NAME"));
        assert!(!is_valid_key_name("FOO$(bar)"));
        assert!(!is_valid_key_name("KEY=VAL"));
    }

    #[test]
    fn now_utc_format() {
        let ts = now_utc();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}
