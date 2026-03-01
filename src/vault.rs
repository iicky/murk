use std::fs;
use std::path::Path;

use crate::types::Vault;

/// Errors that can occur during vault file operations.
#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Parse(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                write!(f, "vault file not found. Run `murk init` to create one")
            }
            VaultError::Io(e) => write!(f, "vault I/O error: {e}"),
            VaultError::Parse(msg) => write!(f, "vault parse error: {msg}"),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

/// Parse vault from a JSON string.
pub fn parse(contents: &str) -> Result<Vault, VaultError> {
    serde_json::from_str(contents).map_err(|e| {
        VaultError::Parse(format!(
            "invalid vault JSON: {e}. Vault may be corrupted — restore from git"
        ))
    })
}

/// Read a .murk vault file.
pub fn read(path: &Path) -> Result<Vault, VaultError> {
    let contents = fs::read_to_string(path)?;
    parse(&contents)
}

/// Write a vault to a .murk file as pretty-printed JSON.
pub fn write(path: &Path, vault: &Vault) -> Result<(), VaultError> {
    let json = serde_json::to_string_pretty(vault)
        .map_err(|e| VaultError::Parse(format!("failed to serialize vault: {e}")))?;
    fs::write(path, json + "\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SchemaEntry, SecretEntry};
    use std::collections::BTreeMap;

    fn test_vault() -> Vault {
        let mut schema = BTreeMap::new();
        schema.insert(
            "DATABASE_URL".into(),
            SchemaEntry {
                description: "postgres connection string".into(),
                example: Some("postgres://user:pass@host/db".into()),
                tags: vec![],
            },
        );

        Vault {
            version: "2.0".into(),
            created: "2026-02-27T00:00:00Z".into(),
            vault_name: ".murk".into(),
            recipients: vec!["age1test".into()],
            schema,
            secrets: BTreeMap::new(),
            meta: "encrypted-meta".into(),
        }
    }

    #[test]
    fn roundtrip_read_write() {
        let dir = std::env::temp_dir().join("murk_test_vault_v2");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        vault.secrets.insert(
            "DATABASE_URL".into(),
            SecretEntry {
                shared: "encrypted-value".into(),
                scoped: BTreeMap::new(),
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();

        assert_eq!(read_vault.version, "2.0");
        assert_eq!(read_vault.recipients[0], "age1test");
        assert!(read_vault.schema.contains_key("DATABASE_URL"));
        assert!(read_vault.secrets.contains_key("DATABASE_URL"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn schema_is_sorted() {
        let dir = std::env::temp_dir().join("murk_test_sorted_v2");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        vault.schema.insert(
            "ZZZ_KEY".into(),
            SchemaEntry {
                description: "last".into(),
                example: None,
                tags: vec![],
            },
        );
        vault.schema.insert(
            "AAA_KEY".into(),
            SchemaEntry {
                description: "first".into(),
                example: None,
                tags: vec![],
            },
        );

        write(&path, &vault).unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        // BTreeMap ensures sorted output — AAA before DATABASE before ZZZ.
        let aaa_pos = contents.find("AAA_KEY").unwrap();
        let db_pos = contents.find("DATABASE_URL").unwrap();
        let zzz_pos = contents.find("ZZZ_KEY").unwrap();
        assert!(aaa_pos < db_pos);
        assert!(db_pos < zzz_pos);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_errors() {
        let result = read(Path::new("/tmp/null.murk"));
        assert!(result.is_err());
    }
}
