//! Shared test helpers for vault construction and key generation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// Process-global lock for tests that mutate env vars (MURK_KEY, MURK_KEY_FILE).
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Process-global lock for tests that change the working directory.
pub static CWD_LOCK: Mutex<()> = Mutex::new(());

use age::secrecy::ExposeSecret;

use crate::{crypto, types};

pub fn generate_keypair() -> (String, String) {
    let identity = age::x25519::Identity::generate();
    let secret = identity.to_string();
    let pubkey = identity.to_public().to_string();
    (secret.expose_secret().to_string(), pubkey)
}

pub fn make_recipient(pubkey: &str) -> crypto::MurkRecipient {
    crypto::parse_recipient(pubkey).unwrap()
}

pub fn make_identity(secret: &str) -> crypto::MurkIdentity {
    crypto::parse_identity(secret).unwrap()
}

pub fn empty_vault() -> types::Vault {
    types::Vault {
        version: types::VAULT_VERSION.into(),
        created: "2026-02-28T00:00:00Z".into(),
        vault_name: ".murk".into(),
        repo: String::new(),
        recipients: vec![],
        schema: BTreeMap::new(),
        secrets: BTreeMap::new(),
        meta: String::new(),
    }
}

pub fn empty_murk() -> types::Murk {
    types::Murk {
        values: HashMap::new(),
        recipients: HashMap::new(),
        scoped: HashMap::new(),
        legacy_mac: false,
    }
}
