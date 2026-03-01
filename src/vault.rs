use std::fs;
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::types::Header;

/// Separator between header and encrypted murk in the .murk file.
const SECTION_SEP: &str = "\n\n";

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

/// Parse vault contents from a string, returning the header and raw encrypted bytes.
pub fn parse(contents: &str) -> Result<(Header, Vec<u8>), VaultError> {
    let (header_str, murk_b64) = contents.split_once(SECTION_SEP).ok_or_else(|| {
        VaultError::Parse(
            "missing section separator. Vault may be corrupted — restore from git".into(),
        )
    })?;

    let header: Header = serde_json::from_str(header_str).map_err(|e| {
        VaultError::Parse(format!(
            "invalid header JSON: {e}. Vault may be corrupted — restore from git"
        ))
    })?;

    let murk_bytes = BASE64.decode(murk_b64.trim()).map_err(|e| {
        VaultError::Parse(format!(
            "invalid base64 in vault: {e}. Vault may be corrupted — restore from git"
        ))
    })?;

    Ok((header, murk_bytes))
}

/// Read a .murk vault file, returning the parsed header and raw encrypted bytes.
pub fn read(path: &Path) -> Result<(Header, Vec<u8>), VaultError> {
    let contents = fs::read_to_string(path)?;
    parse(&contents)
}

/// Write a header and raw encrypted bytes to a .murk vault file.
/// The encrypted bytes are base64-encoded so the file remains valid text.
pub fn write(path: &Path, header: &Header, murk_bytes: &[u8]) -> Result<(), VaultError> {
    let header_json = serde_json::to_string_pretty(header)
        .map_err(|e| VaultError::Parse(format!("failed to serialize header: {e}")))?;

    let murk_b64 = BASE64.encode(murk_bytes);

    let contents = format!("{header_json}{SECTION_SEP}{murk_b64}");
    fs::write(path, contents)?;

    Ok(())
}

/// Read only the header from a .murk vault file (no decryption needed).
pub fn read_header(path: &Path) -> Result<Header, VaultError> {
    let contents = fs::read_to_string(path)?;

    let header_str = contents
        .split_once(SECTION_SEP)
        .map_or(contents.as_str(), |(h, _)| h);

    let header: Header = serde_json::from_str(header_str)
        .map_err(|e| VaultError::Parse(format!("invalid header JSON: {e}")))?;

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SchemaEntry;

    fn test_header() -> Header {
        Header {
            version: "1.0".into(),
            created: "2026-02-27T00:00:00Z".into(),
            vault_name: ".murk".into(),
            murk_hash: "sha256:abc123".into(),
            recipients: vec!["age1test".into()],
            schema: vec![SchemaEntry {
                key: "DATABASE_URL".into(),
                description: "postgres connection string".into(),
                example: Some("postgres://user:pass@host/db".into()),
                tags: vec![],
            }],
        }
    }

    #[test]
    fn roundtrip_read_write() {
        let dir = std::env::temp_dir().join("murk_test_vault");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let header = test_header();
        let murk_bytes = b"all my secrets here";

        write(&path, &header, murk_bytes).unwrap();
        let (read_header, read_bytes) = read(&path).unwrap();

        assert_eq!(read_header.version, header.version);
        assert_eq!(read_header.recipients[0], "age1test");
        assert_eq!(read_bytes, murk_bytes);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_header_only() {
        let dir = std::env::temp_dir().join("murk_test_header");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.murk");

        let header = test_header();
        write(&path, &header, b"do-not-tell").unwrap();

        let read_h = read_header(&path).unwrap();
        assert_eq!(read_h.schema[0].key, "DATABASE_URL");
        assert_eq!(
            read_h.schema[0].example.as_deref(),
            Some("postgres://user:pass@host/db")
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_errors() {
        let result = read(Path::new("/tmp/null.murk"));
        assert!(result.is_err());
    }
}
