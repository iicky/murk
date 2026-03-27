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
    vault: types::Vault,
    murk: types::Murk,
    pubkey: String,
}

#[pymethods]
impl Vault {
    /// Get a single decrypted secret value.
    /// Returns the scoped override if one exists, otherwise the shared value.
    fn get(&self, key: &str) -> PyResult<Option<String>> {
        // Check scoped first.
        if let Some(scoped_map) = self.murk.scoped.get(key) {
            if let Some(value) = scoped_map.get(&self.pubkey) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(self.murk.values.get(key).cloned())
    }

    /// Export all secrets as a dict. Scoped values override shared values.
    fn export(&self) -> PyResult<HashMap<String, String>> {
        Ok(
            export::resolve_secrets(&self.vault, &self.murk, &self.pubkey, &[])
                .into_iter()
                .collect(),
        )
    }

    /// List all key names.
    fn keys(&self) -> PyResult<Vec<String>> {
        Ok(self.vault.schema.keys().cloned().collect())
    }

    /// Number of secrets in the vault.
    fn __len__(&self) -> usize {
        self.vault.schema.len()
    }

    /// Get a value by key (dict-style access).
    fn __getitem__(&self, key: &str) -> PyResult<String> {
        self.get(key)?
            .ok_or_else(|| PyRuntimeError::new_err(format!("key not found: {key}")))
    }

    /// Check if a key exists.
    fn __contains__(&self, key: &str) -> bool {
        self.vault.schema.contains_key(key)
    }

    fn __repr__(&self) -> String {
        format!(
            "Vault({} secrets, {} recipients)",
            self.vault.schema.len(),
            self.vault.recipients.len()
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
        vault,
        murk,
        pubkey,
    })
}

/// One-liner: load the vault and get a single key.
#[pyfunction]
#[pyo3(signature = (key, vault_path=".murk"))]
fn get(key: &str, vault_path: &str) -> PyResult<Option<String>> {
    load(vault_path)?.get(key)
}

/// One-liner: load the vault and export all secrets as a dict.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn export_all(vault_path: &str) -> PyResult<HashMap<String, String>> {
    load(vault_path)?.export()
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
