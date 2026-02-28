use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// -- Plaintext Header --
// Public. Anyone with repo access can read this.
// Contains NO secret values or identity information — just pubkeys and schema.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub version: String,
    pub created: String,
    pub vault_name: String,
    pub murk_hash: String,
    /// Public keys only — no names or emails. Name mappings live in the encrypted Murk.
    pub recipients: Vec<String>,
    pub schema: Vec<SchemaEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub key: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

// -- Murk --
// Encrypted to ALL recipients. Contains shared secret values,
// recipient name mappings, and nested motes. Each mote is itself
// age-encrypted to only its owner's key.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Murk {
    pub values: HashMap<String, String>,
    /// Maps pubkey → display name. The only place names are stored.
    pub recipients: HashMap<String, String>,
    pub per_key_access: HashMap<String, Vec<String>>,
    /// Maps pubkey → encrypted personal blob.
    pub motes: HashMap<String, String>,
}

// -- Mote --
// Encrypted to a SINGLE recipient. Stored as an age-encrypted
// payload inside Murk.motes, keyed by recipient name.
// Values here override shared values during `murk export`.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mote {
    pub values: HashMap<String, String>,
}
