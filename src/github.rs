//! GitHub SSH key fetching for `murk authorize github:username`.

use crate::crypto::{self, MurkRecipient};

/// Errors that can occur when fetching GitHub SSH keys.
#[derive(Debug)]
pub enum GitHubError {
    /// HTTP request failed.
    Fetch(String),
    /// No supported SSH keys found for this user.
    NoKeys(String),
}

impl std::fmt::Display for GitHubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitHubError::Fetch(msg) => write!(f, "GitHub key fetch failed: {msg}"),
            GitHubError::NoKeys(user) => write!(
                f,
                "no supported SSH keys found for GitHub user {user} (need ed25519 or rsa)"
            ),
        }
    }
}

/// Fetch all SSH public keys for a GitHub user.
///
/// Hits `https://github.com/{username}.keys` (no auth needed) and parses
/// each line as an SSH public key. Returns all valid keys as recipients
/// paired with the key type string (e.g., "ssh-ed25519").
///
/// Filters to supported types only (ed25519 and rsa). Unsupported key
/// types (ecdsa, sk-ssh-*) are silently skipped.
pub fn fetch_keys(username: &str) -> Result<Vec<(MurkRecipient, String)>, GitHubError> {
    // GitHub usernames: alphanumeric + hyphens, no path traversal.
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
        || username.is_empty()
    {
        return Err(GitHubError::Fetch(format!(
            "invalid GitHub username: {username}"
        )));
    }

    let url = format!("https://github.com/{username}.keys");

    let body = ureq::get(&url)
        .call()
        .map_err(|e| GitHubError::Fetch(format!("{url}: {e}")))?
        .into_body()
        .read_to_string()
        .map_err(|e| GitHubError::Fetch(format!("reading response: {e}")))?;

    if body.trim().is_empty() {
        return Err(GitHubError::NoKeys(username.into()));
    }

    let mut keys = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Extract key type (first space-delimited token).
        let key_type = line.split_whitespace().next().unwrap_or("");

        // Only accept ed25519 and rsa — skip ecdsa, sk-ssh-*, etc.
        if key_type != "ssh-ed25519" && key_type != "ssh-rsa" {
            continue;
        }

        // Normalize: parse and re-serialize (strips any trailing comment).
        if let Ok(recipient) = crypto::parse_recipient(line) {
            // Use the normalized (comment-stripped) key string.
            let normalized = match &recipient {
                MurkRecipient::Ssh(r) => r.to_string(),
                MurkRecipient::Age(_) => unreachable!("SSH key parsed as age key"),
            };
            keys.push((recipient, normalized));
        }
    }

    if keys.is_empty() {
        return Err(GitHubError::NoKeys(username.into()));
    }

    Ok(keys)
}

/// Classify an SSH key type for human-readable display.
///
/// Returns a short label like "ssh-ed25519" or "ssh-rsa" from
/// the full key string.
pub fn key_type_label(key_string: &str) -> &str {
    key_string.split_whitespace().next().unwrap_or("ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_label_ed25519() {
        assert_eq!(
            key_type_label("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."),
            "ssh-ed25519"
        );
    }

    #[test]
    fn key_type_label_rsa() {
        assert_eq!(key_type_label("ssh-rsa AAAAB3NzaC1yc2EAAAA..."), "ssh-rsa");
    }

    #[test]
    fn key_type_label_empty() {
        assert_eq!(key_type_label(""), "ssh");
    }
}
