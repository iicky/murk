//! Unified error type for the murk library.

use crate::crypto::CryptoError;
use crate::github::GitHubError;
use crate::vault::VaultError;

/// Top-level error type for murk operations.
#[derive(Debug)]
pub enum MurkError {
    /// Vault file I/O or parsing.
    Vault(VaultError),
    /// Cryptographic operation (encrypt/decrypt/key parse).
    Crypto(CryptoError),
    /// Integrity check failed (MAC mismatch, tampering).
    Integrity(String),
    /// Key resolution or environment configuration.
    Key(String),
    /// Recipient management (authorize, revoke).
    Recipient(String),
    /// Secret management (add, remove, describe).
    Secret(String),
    /// GitHub key fetch.
    GitHub(GitHubError),
    /// General I/O.
    Io(std::io::Error),
}

impl std::fmt::Display for MurkError {
    #[allow(clippy::match_same_arms)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MurkError::Vault(e) => write!(f, "{e}"),
            MurkError::Crypto(e) => write!(f, "{e}"),
            MurkError::Integrity(msg) => write!(f, "integrity check failed: {msg}"),
            MurkError::Key(msg) => write!(f, "{msg}"),
            MurkError::Recipient(msg) => write!(f, "{msg}"),
            MurkError::Secret(msg) => write!(f, "{msg}"),
            MurkError::GitHub(e) => write!(f, "{e}"),
            MurkError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for MurkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MurkError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<VaultError> for MurkError {
    fn from(e: VaultError) -> Self {
        MurkError::Vault(e)
    }
}

impl From<CryptoError> for MurkError {
    fn from(e: CryptoError) -> Self {
        MurkError::Crypto(e)
    }
}

impl From<GitHubError> for MurkError {
    fn from(e: GitHubError) -> Self {
        MurkError::GitHub(e)
    }
}

impl From<std::io::Error> for MurkError {
    fn from(e: std::io::Error) -> Self {
        MurkError::Io(e)
    }
}
