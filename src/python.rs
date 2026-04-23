//! Python bindings for murk via PyO3.
//!
//! ```python
//! import murk
//!
//! vault = murk.load()              # reads MURK_KEY from env, .murk from cwd
//! vault.get("DATABASE_URL")        # decrypt a single value
//! vault.export()                   # dict of all key/values
//! murk.get("DATABASE_URL")         # one-liner convenience
//! ```

use std::collections::HashMap;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::{env, export, types};

/// A loaded and decrypted murk vault.
#[pyclass]
struct Vault {
    inner: types::Vault,
    decrypted: types::Murk,
    pubkey: String,
}

#[pymethods]
impl Vault {
    /// Get a single decrypted secret value.
    /// Returns the scoped override if one exists, otherwise the shared value.
    ///
    /// The returned `String` is a plain Python-owned copy — once it crosses
    /// the FFI boundary the plaintext is outside murk's zeroization.
    fn get(&self, key: &str) -> Option<String> {
        if let Some(value) = self
            .decrypted
            .scoped
            .get(key)
            .and_then(|m| m.get(&self.pubkey))
        {
            return Some(value.to_string());
        }
        self.decrypted.values.get(key).map(|v| v.to_string())
    }

    /// Export all secrets as a dict. Scoped values override shared values.
    fn export(&self) -> HashMap<String, String> {
        // Python dicts own plain Strings — zeroization ends at the FFI boundary.
        export::resolve_secrets(&self.inner, &self.decrypted, &self.pubkey, &[])
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    }

    /// List all key names.
    fn keys(&self) -> Vec<String> {
        self.inner.schema.keys().cloned().collect()
    }

    /// Number of secrets in the vault.
    fn __len__(&self) -> usize {
        self.inner.schema.len()
    }

    /// Get a value by key (dict-style access).
    fn __getitem__(&self, key: &str) -> PyResult<String> {
        self.get(key)
            .ok_or_else(|| PyRuntimeError::new_err(format!("key not found: {key}")))
    }

    /// Check if a key exists.
    fn __contains__(&self, key: &str) -> bool {
        self.inner.schema.contains_key(key)
    }

    fn __repr__(&self) -> String {
        format!(
            "Vault({} secrets, {} recipients)",
            self.inner.schema.len(),
            self.inner.recipients.len()
        )
    }
}

/// Load a murk vault. Reads MURK_KEY from the environment.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn load(vault_path: &str) -> PyResult<Vault> {
    let (vault, murk, identity) =
        crate::load_vault(vault_path).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let pubkey = identity
        .pubkey_string()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(Vault {
        inner: vault,
        decrypted: murk,
        pubkey,
    })
}

/// One-liner: load the vault and get a single key.
#[pyfunction]
#[pyo3(signature = (key, vault_path=".murk"))]
fn get(key: &str, vault_path: &str) -> PyResult<Option<String>> {
    let v = load(vault_path)?;
    Ok(v.get(key))
}

/// One-liner: load the vault and export all secrets as a dict.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn export_all(vault_path: &str) -> PyResult<HashMap<String, String>> {
    let v = load(vault_path)?;
    Ok(v.export())
}

/// Resolve the MURK_KEY from the environment without loading a vault.
/// Returns true if a key is available.
#[pyfunction]
fn has_key() -> bool {
    env::resolve_key().is_ok()
}

/// Python module definition.
#[pymodule]
fn murk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Vault>()?;
    m.add_function(wrap_pyfunction!(load, m)?)?;
    m.add_function(wrap_pyfunction!(get, m)?)?;
    m.add_function(wrap_pyfunction!(export_all, m)?)?;
    m.add_function(wrap_pyfunction!(has_key, m)?)?;
    Ok(())
}
