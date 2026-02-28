use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of the given bytes and return it in the
/// `sha256:hex` format used throughout the .murk file.
pub fn hash(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("sha256:{}", hex::encode(digest))
}

/// Verify that `data` matches an expected hash string (e.g. "sha256:abc123...").
/// Returns Ok(()) if valid, Err with a message if not.
pub fn verify(data: &[u8], expected: &str) -> Result<(), IntegrityError> {
    let actual = hash(data);
    if actual == expected {
        Ok(())
    } else {
        Err(IntegrityError::Mismatch {
            expected: expected.to_string(),
            actual,
        })
    }
}

/// Errors that can occur during integrity verification.
#[derive(Debug)]
pub enum IntegrityError {
    Mismatch { expected: String, actual: String },
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityError::Mismatch { expected, actual } => {
                write!(
                    f,
                    "integrity check failed: expected {expected}, got {actual}"
                )
            }
        }
    }
}

/// Simple hex encoding (no extra dependency needed).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_format() {
        let h = hash(b"hello world");
        assert!(h.starts_with("sha256:"));
        // SHA-256 produces 64 hex chars
        assert_eq!(h.len(), "sha256:".len() + 64);
    }

    #[test]
    fn hash_deterministic() {
        assert_eq!(hash(b"test data"), hash(b"test data"));
    }

    #[test]
    fn hash_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = hash(b"");
        assert_eq!(
            h,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn verify_matching() {
        let data = b"some data";
        let h = hash(data);
        assert!(verify(data, &h).is_ok());
    }

    #[test]
    fn verify_mismatch() {
        let result = verify(
            b"actual data",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
    }

    #[test]
    fn different_data_different_hash() {
        assert_ne!(hash(b"foo"), hash(b"bar"));
    }
}
