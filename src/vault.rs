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
            repo: String::new(),
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

    #[test]
    fn parse_invalid_json() {
        let result = parse("not json at all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("vault parse error"));
        assert!(msg.contains("Vault may be corrupted"));
    }

    #[test]
    fn parse_empty_string() {
        let result = parse("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_valid_json() {
        let json = serde_json::to_string(&test_vault()).unwrap();
        let result = parse(&json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, "2.0");
    }

    #[test]
    fn error_display_not_found() {
        let err = VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file",
        ));
        let msg = err.to_string();
        assert!(msg.contains("vault file not found"));
        assert!(msg.contains("murk init"));
    }

    #[test]
    fn error_display_io() {
        let err = VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        let msg = err.to_string();
        assert!(msg.contains("vault I/O error"));
    }

    #[test]
    fn error_display_parse() {
        let err = VaultError::Parse("bad data".into());
        assert!(err.to_string().contains("vault parse error: bad data"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let vault_err: VaultError = io_err.into();
        assert!(matches!(vault_err, VaultError::Io(_)));
    }

    #[test]
    fn scoped_entries_roundtrip() {
        let dir = std::env::temp_dir().join("murk_test_scoped_rt");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let mut vault = test_vault();
        let mut scoped = BTreeMap::new();
        scoped.insert("age1bob".into(), "encrypted-for-bob".into());

        vault.secrets.insert(
            "DATABASE_URL".into(),
            SecretEntry {
                shared: "encrypted-value".into(),
                scoped,
            },
        );

        write(&path, &vault).unwrap();
        let read_vault = read(&path).unwrap();

        let entry = &read_vault.secrets["DATABASE_URL"];
        assert_eq!(entry.scoped["age1bob"], "encrypted-for-bob");

        fs::remove_dir_all(&dir).unwrap();
    }
}
