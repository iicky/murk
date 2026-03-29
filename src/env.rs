//! Environment and `.env` file handling.

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use age::secrecy::SecretString;

/// Reject symlinks at the given path to prevent symlink-clobber attacks.
/// Returns Ok(()) if the path does not exist or is not a symlink.
pub(crate) fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    if path.is_symlink() {
        return Err(format!(
            "{label} is a symlink — refusing to follow for security"
        ));
    }
    Ok(())
}

/// Read a file, rejecting symlinks and (on Unix) group/world-readable permissions.
/// Returns the file contents as a string.
fn read_secret_file(path: &Path, label: &str) -> Result<String, String> {
    reject_symlink(path, label)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.mode();
            if mode & WORLD_READABLE_MASK != 0 {
                return Err(format!(
                    "{label} is readable by others (mode {:o}). Run: chmod 600 {}",
                    mode & 0o777,
                    path.display()
                ));
            }
        }
    }

    fs::read_to_string(path).map_err(|e| format!("cannot read {label}: {e}"))
}

/// Environment variable for the secret key.
pub const ENV_MURK_KEY: &str = "MURK_KEY";
/// Environment variable for the secret key file path.
pub const ENV_MURK_KEY_FILE: &str = "MURK_KEY_FILE";
/// Environment variable for the vault filename.
pub const ENV_MURK_VAULT: &str = "MURK_VAULT";

/// Keys to skip when importing from a .env file.
const IMPORT_SKIP: &[&str] = &[ENV_MURK_KEY, ENV_MURK_KEY_FILE, ENV_MURK_VAULT];

/// File mode for `.env`: owner read/write only.
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

/// Bitmask for group/other permission bits.
#[cfg(unix)]
const WORLD_READABLE_MASK: u32 = 0o077;

/// Resolve the secret key, checking in order:
/// 1. `MURK_KEY` env var (explicit key)
/// 2. `MURK_KEY_FILE` env var (path to key file)
/// 3. `~/.config/murk/keys/<vault-hash>` (automatic lookup for default vault)
/// 4. `.env` file in cwd (backward compat)
///
/// Returns the key wrapped in `SecretString` so it is zeroized on drop.
pub fn resolve_key() -> Result<SecretString, String> {
    resolve_key_for_vault(".murk")
}

/// Resolve the secret key for a specific vault, checking in order:
/// 1. `MURK_KEY` env var (explicit key)
/// 2. `MURK_KEY_FILE` env var (path to key file)
/// 3. `~/.config/murk/keys/<vault-hash>` (automatic lookup keyed to the given vault path)
/// 4. `.env` file in cwd (backward compat)
pub fn resolve_key_for_vault(vault_path: &str) -> Result<SecretString, String> {
    // 1. Direct env var.
    if let Some(k) = env::var(ENV_MURK_KEY).ok().filter(|k| !k.is_empty()) {
        return Ok(SecretString::from(k));
    }
    // 2. Key file env var.
    if let Ok(path) = env::var(ENV_MURK_KEY_FILE) {
        let p = std::path::Path::new(&path);
        let contents = read_secret_file(p, "MURK_KEY_FILE")?;
        return Ok(SecretString::from(contents.trim().to_string()));
    }
    // 3. Key file for the specified vault.
    if let Some(path) = key_file_path(vault_path).ok().filter(|p| p.exists()) {
        let contents = read_secret_file(&path, "key file")?;
        return Ok(SecretString::from(contents.trim().to_string()));
    }
    // 4. Backward compat: read from .env file (deprecated).
    if let Some(key) = read_key_from_dotenv() {
        eprintln!(
            "\x1b[1;33mwarn\x1b[0m reading key from .env is deprecated — use MURK_KEY_FILE or `murk init` instead"
        );
        return Ok(SecretString::from(key));
    }
    Err(
        "MURK_KEY not set — run `murk init` to generate a key, or ask a recipient to authorize you"
            .into(),
    )
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
            if mode & WORLD_READABLE_MASK != 0 {
                eprintln!(
                    "\x1b[1;33mwarning:\x1b[0m .env is readable by others (mode {:o}). Run: \x1b[1mchmod 600 .env\x1b[0m",
                    mode & 0o777
                );
            }
        }
    }
}

/// Read MURK_KEY from `.env` file if present.
///
/// Supports `MURK_KEY_FILE=path` references (preferred) and legacy inline
/// `MURK_KEY=value` (deprecated — logs a warning).
pub fn read_key_from_dotenv() -> Option<String> {
    let env_path = Path::new(".env");
    let contents = fs::read_to_string(env_path).ok()?;
    for line in contents.lines() {
        let trimmed = line.trim();
        // Key file reference (preferred path).
        if let Some(path_str) = trimmed
            .strip_prefix("export MURK_KEY_FILE=")
            .or_else(|| trimmed.strip_prefix("MURK_KEY_FILE="))
        {
            let p = Path::new(path_str.trim());
            if let Ok(contents) = read_secret_file(p, "MURK_KEY_FILE from .env") {
                return Some(contents.trim().to_string());
            }
        }
        // Inline key (deprecated — still accepted for backward compat).
        if let Some(key) = trimmed.strip_prefix("export MURK_KEY=") {
            eprintln!(
                "\x1b[1;33mwarn\x1b[0m inline MURK_KEY in .env is deprecated — use MURK_KEY_FILE instead"
            );
            return Some(key.to_string());
        }
        if let Some(key) = trimmed.strip_prefix("MURK_KEY=") {
            eprintln!(
                "\x1b[1;33mwarn\x1b[0m inline MURK_KEY in .env is deprecated — use MURK_KEY_FILE instead"
            );
            return Some(key.to_string());
        }
    }
    None
}

/// Check whether `.env` already contains a `MURK_KEY` line.
pub fn dotenv_has_murk_key() -> bool {
    let env_path = Path::new(".env");
    if !env_path.exists() {
        return false;
    }
    let contents = fs::read_to_string(env_path).unwrap_or_default();
    contents.lines().any(|l| {
        l.starts_with("MURK_KEY=")
            || l.starts_with("export MURK_KEY=")
            || l.starts_with("MURK_KEY_FILE=")
            || l.starts_with("export MURK_KEY_FILE=")
    })
}

/// Write a MURK_KEY to `.env`, removing any existing MURK_KEY lines.
/// On Unix, sets file permissions to 600 atomically at creation time to
/// prevent a TOCTOU window where the secret key is world-readable.
/// On non-Unix platforms, permissions are not hardened.
pub fn write_key_to_dotenv(secret_key: &str) -> Result<(), String> {
    let env_path = Path::new(".env");
    reject_symlink(env_path, ".env")?;

    // Read existing content (minus any MURK_KEY lines).
    let existing = if env_path.exists() {
        let contents = fs::read_to_string(env_path).map_err(|e| format!("reading .env: {e}"))?;
        let filtered: Vec<&str> = contents
            .lines()
            .filter(|l| !l.starts_with("MURK_KEY=") && !l.starts_with("export MURK_KEY="))
            .collect();
        filtered.join("\n") + "\n"
    } else {
        String::new()
    };

    let full_content = format!("{existing}export MURK_KEY={secret_key}\n");

    // Write the file with restricted permissions from the start (Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .open(env_path)
            .map_err(|e| format!("opening .env: {e}"))?;
        file.write_all(full_content.as_bytes())
            .map_err(|e| format!("writing .env: {e}"))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(env_path, &full_content).map_err(|e| format!("writing .env: {e}"))?;
    }

    Ok(())
}

/// Compute the key file path for a vault: `~/.config/murk/keys/<hash>`.
/// The hash is a truncated SHA-256 of the absolute vault path.
pub fn key_file_path(vault_path: &str) -> Result<std::path::PathBuf, String> {
    use sha2::{Digest, Sha256};

    let abs_path = std::path::Path::new(vault_path)
        .canonicalize()
        .or_else(|_| {
            // Vault may not exist yet (init). Use cwd + vault_path.
            std::env::current_dir().map(|cwd| cwd.join(vault_path))
        })
        .map_err(|e| format!("cannot resolve vault path: {e}"))?;

    let hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
    let short_hash: String = hash.iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });

    let config_dir = dirs_path()?;
    Ok(config_dir.join(&short_hash))
}

/// Return `~/.config/murk/keys/`, creating it if needed.
fn dirs_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine home directory")?;
    let dir = std::path::Path::new(&home)
        .join(".config")
        .join("murk")
        .join("keys");
    fs::create_dir_all(&dir).map_err(|e| format!("creating key directory: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent = dir.parent().unwrap(); // ~/.config/murk
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
    }

    Ok(dir)
}

/// Write a secret key to a file with restricted permissions.
pub fn write_key_to_file(path: &std::path::Path, secret_key: &str) -> Result<(), String> {
    reject_symlink(path, &path.display().to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .open(path)
            .map_err(|e| format!("writing key file: {e}"))?;
        file.write_all(secret_key.as_bytes())
            .map_err(|e| format!("writing key file: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, secret_key).map_err(|e| format!("writing key file: {e}"))?;
    }
    Ok(())
}

/// Write a MURK_KEY_FILE reference to `.env`, removing any existing MURK_KEY/MURK_KEY_FILE lines.
pub fn write_key_ref_to_dotenv(key_file_path: &std::path::Path) -> Result<(), String> {
    let env_path = Path::new(".env");
    reject_symlink(env_path, ".env")?;

    let existing = if env_path.exists() {
        let contents = fs::read_to_string(env_path).map_err(|e| format!("reading .env: {e}"))?;
        let filtered: Vec<&str> = contents
            .lines()
            .filter(|l| {
                !l.starts_with("MURK_KEY=")
                    && !l.starts_with("export MURK_KEY=")
                    && !l.starts_with("MURK_KEY_FILE=")
                    && !l.starts_with("export MURK_KEY_FILE=")
            })
            .collect();
        filtered.join("\n") + "\n"
    } else {
        String::new()
    };

    let full_content = format!(
        "{existing}export MURK_KEY_FILE={}\n",
        key_file_path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .open(env_path)
            .map_err(|e| format!("opening .env: {e}"))?;
        file.write_all(full_content.as_bytes())
            .map_err(|e| format!("writing .env: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(env_path, &full_content).map_err(|e| format!("writing .env: {e}"))?;
    }

    Ok(())
}

/// Status of `.envrc` after writing.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvrcStatus {
    /// `.envrc` already contained `murk export`.
    AlreadyPresent,
    /// Appended murk export line to existing `.envrc`.
    Appended,
    /// Created a new `.envrc` file.
    Created,
}

/// Write a `.envrc` file for direnv integration.
///
/// If `.envrc` exists and already contains `murk export`, returns `AlreadyPresent`.
/// If it exists but doesn't, appends the line. Otherwise creates the file.
pub fn write_envrc(vault_name: &str) -> Result<EnvrcStatus, String> {
    let envrc = Path::new(".envrc");
    reject_symlink(envrc, ".envrc")?;
    let murk_line = format!("eval \"$(murk export --vault {vault_name})\"");

    if envrc.exists() {
        let contents = fs::read_to_string(envrc).map_err(|e| format!("reading .envrc: {e}"))?;
        if contents.contains("murk export") {
            return Ok(EnvrcStatus::AlreadyPresent);
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(envrc)
            .map_err(|e| format!("writing .envrc: {e}"))?;
        writeln!(file, "\n{murk_line}").map_err(|e| format!("writing .envrc: {e}"))?;
        Ok(EnvrcStatus::Appended)
    } else {
        fs::write(envrc, format!("{murk_line}\n")).map_err(|e| format!("writing .envrc: {e}"))?;
        Ok(EnvrcStatus::Created)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::{CWD_LOCK, ENV_LOCK};

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

    #[test]
    fn parse_env_empty_key_skipped() {
        let pairs = parse_env("=value\n");
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_env_mixed_quotes_unmatched() {
        // Mismatched quotes are not stripped.
        let pairs = parse_env("KEY=\"hello'\n");
        assert_eq!(pairs, vec![("KEY".into(), "\"hello'".into())]);
    }

    #[test]
    fn parse_env_multiple_murk_vars() {
        // All three MURK_ vars are skipped, other vars kept.
        let input = "MURK_KEY=x\nMURK_KEY_FILE=y\nMURK_VAULT=z\nA=1\nB=2\n";
        let pairs = parse_env(input);
        assert_eq!(
            pairs,
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
    }

    /// Helper: acquire both locks and cd to a clean temp dir.
    /// Returns guards and the previous cwd. The cwd is restored on drop
    /// via the returned `prev` path — callers must restore manually before
    /// asserting so panics don't leave cwd changed.
    fn resolve_key_sandbox(
        name: &str,
    ) -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("murk_test_{name}"));
        let _ = std::fs::create_dir_all(&tmp);
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        (env, cwd, tmp, prev)
    }

    fn resolve_key_sandbox_teardown(tmp: &std::path::Path, prev: &std::path::Path) {
        std::env::set_current_dir(prev).unwrap();
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn resolve_key_from_env() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("from_env");
        let key = "AGE-SECRET-KEY-1TEST";
        unsafe { env::set_var("MURK_KEY", key) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };
        resolve_key_sandbox_teardown(&tmp, &prev);

        let secret = result.unwrap();
        use age::secrecy::ExposeSecret;
        assert_eq!(secret.expose_secret(), key);
    }

    #[test]
    fn resolve_key_from_file() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("from_file");
        unsafe { env::remove_var("MURK_KEY") };

        let path = std::env::temp_dir().join("murk_test_key_file");
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                std::io::Write::write_all(&mut f, b"AGE-SECRET-KEY-1FROMFILE\n").unwrap();
            }
            #[cfg(not(unix))]
            std::fs::write(&path, "AGE-SECRET-KEY-1FROMFILE\n").unwrap();
        }

        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_file(&path).ok();
        resolve_key_sandbox_teardown(&tmp, &prev);

        let secret = result.unwrap();
        use age::secrecy::ExposeSecret;
        assert_eq!(secret.expose_secret(), "AGE-SECRET-KEY-1FROMFILE");
    }

    #[test]
    fn resolve_key_file_not_found() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("file_not_found");
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::set_var("MURK_KEY_FILE", "/nonexistent/path/murk_key") };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };
        resolve_key_sandbox_teardown(&tmp, &prev);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn resolve_key_neither_set() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("neither_set");
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        let result = resolve_key();
        resolve_key_sandbox_teardown(&tmp, &prev);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MURK_KEY not set"));
    }

    #[test]
    fn resolve_key_empty_string_treated_as_unset() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("empty_string");
        unsafe { env::set_var("MURK_KEY", "") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };
        resolve_key_sandbox_teardown(&tmp, &prev);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MURK_KEY not set"));
    }

    #[test]
    fn resolve_key_murk_key_takes_priority_over_file() {
        let (_env, _cwd, tmp, prev) = resolve_key_sandbox("priority");
        let direct_key = "AGE-SECRET-KEY-1DIRECT";
        let file_key = "AGE-SECRET-KEY-1FILE";

        let path = std::env::temp_dir().join("murk_test_key_priority");
        std::fs::write(&path, format!("{file_key}\n")).unwrap();

        unsafe { env::set_var("MURK_KEY", direct_key) };
        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_file(&path).ok();
        resolve_key_sandbox_teardown(&tmp, &prev);

        let secret = result.unwrap();
        use age::secrecy::ExposeSecret;
        assert_eq!(secret.expose_secret(), direct_key);
    }

    #[cfg(unix)]
    #[test]
    fn warn_env_permissions_no_warning_on_secure_file() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("murk_test_perms");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "KEY=val\n").unwrap();
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Just verify it doesn't panic — output goes to stderr.
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        warn_env_permissions();
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_key_from_dotenv_export_form() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_read_dotenv_export");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "export MURK_KEY=AGE-SECRET-KEY-1ABC\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = read_key_from_dotenv();
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(result, Some("AGE-SECRET-KEY-1ABC".into()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_key_from_dotenv_bare_form() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_read_dotenv_bare");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        std::fs::write(&env_path, "MURK_KEY=AGE-SECRET-KEY-1XYZ\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = read_key_from_dotenv();
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(result, Some("AGE-SECRET-KEY-1XYZ".into()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_key_from_dotenv_missing_file() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_read_dotenv_missing");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = read_key_from_dotenv();
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(result, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dotenv_has_murk_key_true() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_has_key_true");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "MURK_KEY=test\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert!(dotenv_has_murk_key());
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dotenv_has_murk_key_false() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_has_key_false");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "OTHER=val\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert!(!dotenv_has_murk_key());
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dotenv_has_murk_key_no_file() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_has_key_nofile");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert!(!dotenv_has_murk_key());
        std::env::set_current_dir(original_dir).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_key_to_dotenv_creates_new() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_write_key_new");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_to_dotenv("AGE-SECRET-KEY-1NEW").unwrap();

        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(contents.contains("export MURK_KEY=AGE-SECRET-KEY-1NEW"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_key_to_dotenv_replaces_existing() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_write_key_replace");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".env"),
            "OTHER=keep\nMURK_KEY=old\nexport MURK_KEY=also_old\n",
        )
        .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        write_key_to_dotenv("AGE-SECRET-KEY-1REPLACED").unwrap();

        let contents = std::fs::read_to_string(dir.join(".env")).unwrap();
        assert!(contents.contains("OTHER=keep"));
        assert!(contents.contains("export MURK_KEY=AGE-SECRET-KEY-1REPLACED"));
        assert!(!contents.contains("MURK_KEY=old"));
        assert!(!contents.contains("also_old"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_key_to_dotenv_permissions_are_600() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("murk_test_write_key_perms");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        // Create new .env — should be 0o600 from the start.
        write_key_to_dotenv("AGE-SECRET-KEY-1PERMTEST").unwrap();
        let meta = std::fs::metadata(dir.join(".env")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            SECRET_FILE_MODE,
            "new .env should be created with mode 600"
        );

        // Replace existing — should still be 0o600.
        write_key_to_dotenv("AGE-SECRET-KEY-1PERMTEST2").unwrap();
        let meta = std::fs::metadata(dir.join(".env")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            SECRET_FILE_MODE,
            "rewritten .env should maintain mode 600"
        );

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_envrc_creates_new() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_envrc_new");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc(".murk").unwrap();
        assert_eq!(status, EnvrcStatus::Created);

        let contents = std::fs::read_to_string(dir.join(".envrc")).unwrap();
        assert!(contents.contains("murk export --vault .murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_envrc_appends() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_envrc_append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".envrc"), "existing content\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc(".murk").unwrap();
        assert_eq!(status, EnvrcStatus::Appended);

        let contents = std::fs::read_to_string(dir.join(".envrc")).unwrap();
        assert!(contents.contains("existing content"));
        assert!(contents.contains("murk export"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_envrc_already_present() {
        let _cwd = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("murk_test_envrc_present");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".envrc"),
            "eval \"$(murk export --vault .murk)\"\n",
        )
        .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let status = write_envrc(".murk").unwrap();
        assert_eq!(status, EnvrcStatus::AlreadyPresent);

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
