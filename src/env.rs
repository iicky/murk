//! Environment and `.env` file handling.

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use age::secrecy::SecretString;

/// Keys to skip when importing from a .env file.
const IMPORT_SKIP: &[&str] = &["MURK_KEY", "MURK_KEY_FILE", "MURK_VAULT"];

/// File mode for `.env`: owner read/write only.
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

/// Bitmask for group/other permission bits.
#[cfg(unix)]
const WORLD_READABLE_MASK: u32 = 0o077;

/// Resolve the secret key from `MURK_KEY` or `MURK_KEY_FILE`.
/// `MURK_KEY` takes priority; `MURK_KEY_FILE` reads the key from a file.
/// Returns the key wrapped in `SecretString` so it is zeroized on drop.
pub fn resolve_key() -> Result<SecretString, String> {
    if let Ok(k) = env::var("MURK_KEY") {
        if !k.is_empty() {
            return Ok(SecretString::from(k));
        }
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
/// Checks for both `export MURK_KEY=...` and `MURK_KEY=...` forms.
/// Returns the key value or `None` if not found.
pub fn read_key_from_dotenv() -> Option<String> {
    let contents = fs::read_to_string(".env").ok()?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(key) = trimmed.strip_prefix("export MURK_KEY=") {
            return Some(key.to_string());
        }
        if let Some(key) = trimmed.strip_prefix("MURK_KEY=") {
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
    contents
        .lines()
        .any(|l| l.starts_with("MURK_KEY=") || l.starts_with("export MURK_KEY="))
}

/// Write a MURK_KEY to `.env`, removing any existing MURK_KEY lines.
/// Sets file permissions to 600 on Unix.
pub fn write_key_to_dotenv(secret_key: &str) -> Result<(), String> {
    let env_path = Path::new(".env");

    // Remove existing MURK_KEY line(s) if file exists.
    if env_path.exists() {
        let contents = fs::read_to_string(env_path).map_err(|e| format!("reading .env: {e}"))?;
        let filtered: Vec<&str> = contents
            .lines()
            .filter(|l| !l.starts_with("MURK_KEY=") && !l.starts_with("export MURK_KEY="))
            .collect();
        fs::write(env_path, filtered.join("\n") + "\n")
            .map_err(|e| format!("writing .env: {e}"))?;
    }

    // Append MURK_KEY.
    let mut env_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(env_path)
        .map_err(|e| format!("opening .env: {e}"))?;
    writeln!(env_file, "export MURK_KEY={secret_key}").map_err(|e| format!("writing .env: {e}"))?;
    drop(env_file);

    // Restrict to owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(env_path, fs::Permissions::from_mode(SECRET_FILE_MODE))
            .map_err(|e| format!("chmod .env: {e}"))?;
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
    use std::sync::Mutex;

    /// Tests that mutate MURK_KEY / MURK_KEY_FILE env vars must hold this lock
    /// to avoid racing with each other (cargo test runs tests in parallel).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Tests that call `std::env::set_current_dir` must hold this lock to
    /// prevent CWD races (the working directory is process-global state).
    static CWD_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn resolve_key_from_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let key = "AGE-SECRET-KEY-1TEST";
        unsafe { env::set_var("MURK_KEY", key) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };

        let secret = result.unwrap();
        use age::secrecy::ExposeSecret;
        assert_eq!(secret.expose_secret(), key);
    }

    #[test]
    fn resolve_key_from_file() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("MURK_KEY") };

        let path = std::env::temp_dir().join("murk_test_key_file");
        std::fs::write(&path, "AGE-SECRET-KEY-1FROMFILE\n").unwrap();

        unsafe { env::set_var("MURK_KEY_FILE", path.to_str().unwrap()) };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };
        std::fs::remove_file(&path).ok();

        let secret = result.unwrap();
        use age::secrecy::ExposeSecret;
        assert_eq!(secret.expose_secret(), "AGE-SECRET-KEY-1FROMFILE");
    }

    #[test]
    fn resolve_key_file_not_found() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::set_var("MURK_KEY_FILE", "/nonexistent/path/murk_key") };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY_FILE") };

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read MURK_KEY_FILE"));
    }

    #[test]
    fn resolve_key_neither_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("MURK_KEY") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        let result = resolve_key();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MURK_KEY not set"));
    }

    #[test]
    fn resolve_key_empty_string_treated_as_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe { env::set_var("MURK_KEY", "") };
        unsafe { env::remove_var("MURK_KEY_FILE") };
        let result = resolve_key();
        unsafe { env::remove_var("MURK_KEY") };

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MURK_KEY not set"));
    }

    #[cfg(unix)]
    #[test]
    fn warn_env_permissions_no_warning_on_secure_file() {
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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

    #[test]
    fn write_envrc_creates_new() {
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
        let _cwd = CWD_LOCK.lock().unwrap();
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
