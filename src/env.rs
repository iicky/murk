//! Environment and `.env` file handling.

use std::env;
use std::fs;
use std::path::Path;

use age::secrecy::SecretString;

/// Keys to skip when importing from a .env file.
const IMPORT_SKIP: &[&str] = &["MURK_KEY", "MURK_KEY_FILE", "MURK_VAULT"];

/// Resolve the secret key from `MURK_KEY` or `MURK_KEY_FILE`.
/// `MURK_KEY` takes priority; `MURK_KEY_FILE` reads the key from a file.
/// Returns the key wrapped in `SecretString` so it is zeroized on drop.
pub fn resolve_key() -> Result<SecretString, String> {
    if let Ok(k) = env::var("MURK_KEY") {
        return Ok(SecretString::from(k));
    }
    if let Ok(path) = env::var("MURK_KEY_FILE") {
        return fs::read_to_string(&path)
            .map(|contents| SecretString::from(contents.trim().to_string()))
            .map_err(|e| format!("cannot read MURK_KEY_FILE ({path}): {e}"));
    }
    Err("MURK_KEY not set. Add it to .env and load with direnv or `eval $(cat .env)`. Alternatively, set MURK_KEY_FILE to a path containing the key".into())
}

/// Parse a .env file into key-value pairs.
/// Skips comments, blank lines, `MURK_*` keys, and strips quotes and `export` prefixes.
pub fn parse_env(contents: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();

    for line in contents.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        // Strip surrounding quotes.
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);

        if key.is_empty() || IMPORT_SKIP.contains(&key) {
            continue;
        }

        pairs.push((key.into(), value.into()));
    }

    pairs
}

/// Warn if `.env` has loose permissions (Unix only).
pub fn warn_env_permissions() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let env_path = Path::new(".env");
        if env_path.exists()
            && let Ok(meta) = fs::metadata(env_path)
        {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "\x1b[1;33mwarning:\x1b[0m .env is readable by others (mode {:o}). Run: \x1b[1mchmod 600 .env\x1b[0m",
                    mode & 0o777
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_env_empty() {
        assert!(parse_env("").is_empty());
    }

    #[test]
    fn parse_env_comments_and_blanks() {
        let input = "# comment\n\n  # another\n";
        assert!(parse_env(input).is_empty());
    }

    #[test]
    fn parse_env_basic() {
        let input = "FOO=bar\nBAZ=qux\n";
        let pairs = parse_env(input);
        assert_eq!(
            pairs,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into())]
        );
    }

    #[test]
    fn parse_env_double_quotes() {
        let pairs = parse_env("KEY=\"hello world\"\n");
        assert_eq!(pairs, vec![("KEY".into(), "hello world".into())]);
    }

    #[test]
    fn parse_env_single_quotes() {
        let pairs = parse_env("KEY='hello world'\n");
        assert_eq!(pairs, vec![("KEY".into(), "hello world".into())]);
    }

    #[test]
    fn parse_env_export_prefix() {
        let pairs = parse_env("export FOO=bar\n");
        assert_eq!(pairs, vec![("FOO".into(), "bar".into())]);
    }

    #[test]
    fn parse_env_skips_murk_keys() {
        let input = "MURK_KEY=secret\nMURK_KEY_FILE=/path\nMURK_VAULT=.murk\nKEEP=yes\n";
        let pairs = parse_env(input);
        assert_eq!(pairs, vec![("KEEP".into(), "yes".into())]);
    }

    #[test]
    fn parse_env_equals_in_value() {
        let pairs = parse_env("URL=postgres://host?opt=1\n");
        assert_eq!(pairs, vec![("URL".into(), "postgres://host?opt=1".into())]);
    }

    #[test]
    fn parse_env_no_equals_skipped() {
        let pairs = parse_env("not-a-valid-line\nKEY=val\n");
        assert_eq!(pairs, vec![("KEY".into(), "val".into())]);
    }

    // ── New edge-case tests ──

    #[test]
    fn parse_env_empty_value() {
        let pairs = parse_env("KEY=\n");
        assert_eq!(pairs, vec![("KEY".into(), String::new())]);
    }

    #[test]
    fn parse_env_trailing_whitespace() {
        let pairs = parse_env("KEY=value   \n");
        assert_eq!(pairs, vec![("KEY".into(), "value".into())]);
    }

    #[test]
    fn parse_env_unicode_value() {
        let pairs = parse_env("KEY=hello🔐world\n");
        assert_eq!(pairs, vec![("KEY".into(), "hello🔐world".into())]);
    }
}
