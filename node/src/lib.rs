//! Node.js/TypeScript bindings for murk via napi-rs.
//!
//! ```typescript
//! import { load, get, exportAll, hasKey } from '@iicky/murk-secrets'
//!
//! const vault = load()              // reads MURK_KEY from env, .murk from cwd
//! vault.get('DATABASE_URL')         // decrypt a single value
//! vault.export()                    // Record<string, string> of all secrets
//! get('DATABASE_URL')               // one-liner convenience
//! ```

use std::collections::HashMap;

use napi_derive::napi;

/// A loaded and decrypted murk vault.
#[napi]
pub struct Vault {
    vault: murk_cli::types::Vault,
    murk: murk_cli::types::Murk,
    pubkey: String,
}

#[napi]
impl Vault {
    /// Get a single decrypted secret value.
    /// Returns the scoped override if one exists, otherwise the shared value.
    #[napi]
    pub fn get(&self, key: String) -> Option<String> {
        if let Some(value) = self.murk.scoped.get(&key).and_then(|m| m.get(&self.pubkey)) {
            return Some(value.clone());
        }
        self.murk.values.get(&key).cloned()
    }

    /// Export all secrets as an object. Scoped values override shared values.
    #[napi]
    pub fn export(&self) -> HashMap<String, String> {
        murk_cli::resolve_secrets(&self.vault, &self.murk, &self.pubkey, &[])
            .into_iter()
            .collect()
    }

    /// List all key names.
    #[napi]
    pub fn keys(&self) -> Vec<String> {
        self.vault.schema.keys().cloned().collect()
    }

    /// Number of secrets in the vault.
    #[napi(getter)]
    pub fn length(&self) -> u32 {
        self.vault.schema.len() as u32
    }

    /// Check if a key exists.
    #[napi]
    pub fn has(&self, key: String) -> bool {
        self.vault.schema.contains_key(&key)
    }
}

/// Load a murk vault. Reads MURK_KEY from the environment.
#[napi]
pub fn load(vault_path: Option<String>) -> napi::Result<Vault> {
    let path = vault_path.as_deref().unwrap_or(".murk");
    let (vault, murk, identity) =
        murk_cli::load_vault(path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let pubkey = identity
        .pubkey_string()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(Vault {
        vault,
        murk,
        pubkey,
    })
}

/// One-liner: load the vault and get a single key.
#[napi]
pub fn get(key: String, vault_path: Option<String>) -> napi::Result<Option<String>> {
    Ok(load(vault_path)?.get(key))
}

/// One-liner: load the vault and export all secrets as an object.
#[napi]
pub fn export_all(vault_path: Option<String>) -> napi::Result<HashMap<String, String>> {
    Ok(load(vault_path)?.export())
}

/// Check if a MURK_KEY is available in the environment.
#[napi]
pub fn has_key() -> bool {
    murk_cli::resolve_key().is_ok()
}
