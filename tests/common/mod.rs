//! Shared helpers for integration tests.
//!
//! Every murk invocation in the suite routes through [`murk_bin`], which forces
//! `HOME` (and `XDG_RUNTIME_DIR`) inside the test's temp dir and strips inherited
//! key env. This keeps tests hermetic: they can never read or write the
//! developer's real `~/.config/murk/keys`, and a failure reflects product
//! behavior rather than workstation state.

use std::fs;
use std::path::Path;

use assert_cmd::Command;

/// Build a `murk` command with `HOME` and `XDG_RUNTIME_DIR` forced into `home`
/// and any inherited key env removed.
///
/// murk derives `~/.config/murk/keys` straight from `HOME` (see `env::dirs_path`),
/// and `edit` writes its scratch file under `XDG_RUNTIME_DIR`, so pinning both to
/// a temp dir is what makes a test hermetic. This is the only sanctioned way to
/// spawn murk in tests — callers add `.current_dir(...)`, `.env("MURK_KEY", ...)`,
/// or args on top.
pub fn murk_bin(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("murk").unwrap();
    cmd.env("HOME", home)
        .env("XDG_RUNTIME_DIR", home)
        .env_remove("MURK_KEY")
        .env_remove("MURK_KEY_FILE");
    cmd
}

/// Build a murk command rooted at `dir` (both cwd and `HOME`) with `MURK_KEY` set.
///
/// Generic over `AsRef<Path>` so it accepts a `&TempDir` from either `assert_fs`
/// or `tempfile` without callers reaching for `.path()`.
pub fn murk(dir: impl AsRef<Path>, key: &str) -> Command {
    let dir = dir.as_ref();
    let mut cmd = murk_bin(dir);
    cmd.current_dir(dir).env("MURK_KEY", key);
    cmd
}

/// Run `murk init` in `dir` and return `(murk_key, pubkey)`.
///
/// Reads the key from the `MURK_KEY_FILE` path written to `.env` (falling back to
/// a legacy inline `MURK_KEY=` for older fixtures).
pub fn init_vault(dir: impl AsRef<Path>) -> (String, String) {
    let dir = dir.as_ref();
    murk_bin(dir)
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir)
        .write_stdin("testuser\n")
        .assert()
        .success();

    let env_contents = fs::read_to_string(dir.join(".env")).unwrap();

    let murk_key = if let Some(path) = env_contents.lines().find_map(|l| {
        l.strip_prefix("export MURK_KEY_FILE=")
            .or_else(|| l.strip_prefix("MURK_KEY_FILE="))
    }) {
        let path = path.trim().trim_matches('\'');
        fs::read_to_string(path).unwrap().trim().to_string()
    } else if let Some(key) = env_contents.lines().find_map(|l| {
        l.strip_prefix("export MURK_KEY=")
            .or_else(|| l.strip_prefix("MURK_KEY="))
    }) {
        key.to_string()
    } else {
        panic!("no MURK_KEY or MURK_KEY_FILE found in .env");
    };

    assert!(murk_key.starts_with("AGE-SECRET-KEY-"));

    let identity: age::x25519::Identity = murk_key.parse().unwrap();
    let pubkey = identity.to_public().to_string();

    (murk_key, pubkey)
}
