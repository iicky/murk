use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Shared value encrypted to all recipients.
    pub shared: String,
    /// Scoped overrides: pubkey → encrypted value (encrypted to that pubkey only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scoped: BTreeMap<String, String>,
}

// -- Meta (encrypted, stored in vault.meta) --
// Contains private metadata only visible to recipients.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// Maps pubkey → display name. The only place names are stored.
    pub recipients: HashMap<String, String>,
    /// Integrity MAC over secrets + schema.
    pub mac: String,
}

// -- Murk (decrypted in-memory state) --
// The working representation after decryption. Commands read/modify this,
// then save_vault compares against the original to minimize re-encryption.

#[derive(Debug, Clone)]
pub struct Murk {
    /// Decrypted shared values.
    pub values: HashMap<String, String>,
    /// Pubkey → display name (from meta).
    pub recipients: HashMap<String, String>,
    /// Scoped overrides: key → { pubkey → decrypted value }.
    /// Only contains entries decryptable by the current identity.
    pub scoped: HashMap<String, HashMap<String, String>>,
}
