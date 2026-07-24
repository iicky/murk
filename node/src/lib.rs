//! Node.js/TypeScript bindings for murk via napi-rs.
//!
//! ```typescript
//! import { load, get, exportAll, hasIdentity } from '@iicky/murk-secrets'
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
    /// Get a single decrypted secret value. Resolution order: a personal scoped
    /// override, then a named-group value we can read, then the shared value.
    ///
    /// Internally, vault state stores values in `Zeroizing<String>` so plaintext
    /// is wiped from memory when dropped. Crossing the napi boundary into a
    /// JavaScript `String` requires copying the plaintext into a regular Rust
    /// `String`; the V8 garbage collector owns it from there and zeroize cannot
    /// follow. This is a known leak in the JS bindings — see THREAT_MODEL.md.
    ///
    /// When the loaded identity is a granted agent, the vault's agent policy is
    /// enforced before the value is returned — the same gate the CLI applies at
    /// `agent exec`. Throws if policy forbids the key. For an operator identity
    /// this is a no-op.
    #[napi]
    pub fn get(&self, key: String) -> napi::Result<Option<String>> {
        let value = murk_cli::get_secret(&self.murk, &key, &self.pubkey).map(str::to_string);
        // Only enforce when there is a value to hand back: a key the agent
        // cannot decrypt is already inaccessible, so policy is moot.
        if value.is_some() {
            murk_cli::enforce_agent_policy(&self.vault, &self.murk, &self.pubkey, &[key])
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        }
        Ok(value)
    }

    /// Export all secrets as an object. Scoped values override shared values.
    ///
    /// See `get` for the zeroize caveat — the returned `HashMap` holds plain
    /// `String` plaintext, not `Zeroizing<String>`.
    ///
    /// For a granted agent, the vault's agent policy is enforced over the full
    /// key set first (mirroring `murk agent exec`): if any resolvable key is
    /// outside the policy, the whole export throws rather than returning a
    /// partial object. For an operator identity this is a no-op.
    #[napi]
    pub fn export(&self) -> napi::Result<HashMap<String, String>> {
        let resolved = murk_cli::resolve_secrets(&self.vault, &self.murk, &self.pubkey, &[]);
        let keys: Vec<String> = resolved.keys().cloned().collect();
        murk_cli::enforce_agent_policy(&self.vault, &self.murk, &self.pubkey, &keys)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(resolved
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect())
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
    load(vault_path)?.get(key)
}

/// One-liner: load the vault and export all secrets as an object.
#[napi]
pub fn export_all(vault_path: Option<String>) -> napi::Result<HashMap<String, String>> {
    load(vault_path)?.export()
}

/// Whether a decryption identity (`MURK_KEY` / `MURK_KEY_FILE`) is available in
/// the environment — i.e. whether `load` can decrypt. This does not check
/// whether a secret exists; use `Vault.has` / `Vault.keys` for that.
#[napi]
pub fn has_identity() -> bool {
    murk_cli::resolve_key().is_ok()
}
