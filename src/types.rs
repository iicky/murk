use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Current vault format version.
pub const VAULT_VERSION: &str = "2.0";

/// Default vault filename.
pub const DEFAULT_VAULT_NAME: &str = ".murk";

// -- Vault (on-disk format, v2) --
// The entire .murk file is a single JSON document with per-value encryption.
// Key names and schema are plaintext. Values are individually age-encrypted.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub version: String,
    pub created: String,
    pub vault_name: String,
    /// Repository URL, auto-detected from git remote during init.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo: String,
    /// Public keys only — no names. Name mappings live in the encrypted meta blob.
    pub recipients: Vec<String>,
    /// Key metadata — public, readable without decryption.
    pub schema: BTreeMap<String, SchemaEntry>,
    /// Per-value encrypted secrets. Each value is a separate age ciphertext.
    pub secrets: BTreeMap<String, SecretEntry>,
    /// Encrypted metadata blob: recipient names and integrity MAC.
    pub meta: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// When the key was first added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// When the value was last updated. Doubles as "last rotated": any value
    /// change (`add`/`edit`/`rotate`) bumps it, so it anchors the rotation clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// Soft rotation policy: rotate at least every N days. `doctor` flags the
    /// key as overdue when `updated + rotation_interval_days` is in the past.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval_days: Option<u32>,
    /// Hard expiry (ISO-8601 UTC) for credentials with a known end-of-life,
    /// e.g. a token. `doctor` flags it as expired or expiring soon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Shared value encrypted to all recipients (the implicit `everyone` group).
    /// Empty when the secret's base group is a named group instead.
    pub shared: String,
    /// Scoped overrides: pubkey → encrypted value (encrypted to that pubkey only).
    /// This is the `me` tier — a singleton group of one recipient.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scoped: BTreeMap<String, String>,
    /// Named-group values: group name → encrypted value (encrypted to that
    /// group's current members). A secret has at most one base group, so this
    /// map holds at most one entry, but it is keyed by name so the integrity MAC
    /// and merge driver can treat it uniformly with `scoped`. Group *names* are
    /// plaintext (like key names); group *membership* lives in the encrypted meta.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub grouped: BTreeMap<String, String>,
}

// -- Meta (encrypted, stored in vault.meta) --
// Contains metadata only visible to recipients.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Maps pubkey → display name. The only place names are stored.
    pub recipients: HashMap<String, String>,
    /// Integrity MAC over secrets + schema.
    pub mac: String,
    /// BLAKE3 keyed MAC key (hex-encoded, 32 bytes). Generated at init, stored encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "hmac_key")]
    pub mac_key: Option<String>,
    /// Pinned GitHub key fingerprints: username → [SHA256:...].
    /// Used for TOFU (Trust On First Use) verification on `authorize github:user`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub github_pins: HashMap<String, Vec<String>>,
    /// Named recipient groups: group name → member pubkeys. Stored here (not in
    /// the plaintext header) so org structure — who is in which group — does not
    /// leak. Members are a subset of `Vault::recipients`. Covered by the keyed
    /// MAC (`blake3v4:`) so membership cannot be tampered with undetected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, Vec<String>>,
}

// -- Murk (decrypted in-memory state) --
// The working representation after decryption. Commands read/modify this,
// then save_vault compares against the original to minimize re-encryption.

#[derive(Debug, Clone, Default)]
pub struct Murk {
    /// Decrypted shared values. Wrapped in `Zeroizing` so plaintext is cleared
    /// from memory when the `Murk` is dropped.
    pub values: HashMap<String, Zeroizing<String>>,
    /// Pubkey → display name (from meta).
    pub recipients: HashMap<String, String>,
    /// Scoped overrides: key → { pubkey → decrypted value }.
    /// Only contains entries decryptable by the current identity.
    pub scoped: HashMap<String, HashMap<String, Zeroizing<String>>>,
    /// Named-group values: key → { group name → decrypted value }.
    /// Only contains groups the current identity is a member of (and can decrypt).
    pub grouped: HashMap<String, HashMap<String, Zeroizing<String>>>,
    /// Group membership: group name → member pubkeys (carried from meta).
    pub groups: BTreeMap<String, Vec<String>>,
    /// True if the vault uses a legacy unkeyed MAC (sha256/sha256v2).
    pub legacy_mac: bool,
    /// Pinned GitHub key fingerprints (carried from meta).
    pub github_pins: HashMap<String, Vec<String>>,
}
