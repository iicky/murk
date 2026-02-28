use std::fs;

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

/// Helper: run `murk init` in a temp dir and return (dir, murk_key, pubkey).
/// Captures the recovery phrase from stdout and the MURK_KEY from .env.
fn init_vault(dir: &TempDir) -> (String, String) {
    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("testuser\n")
        .assert()
        .success();

    let env_contents = fs::read_to_string(dir.path().join(".env")).unwrap();
    let murk_key = env_contents
        .lines()
        .find(|l| l.contains("MURK_KEY="))
        .unwrap()
        .trim_start_matches("export ")
        .trim_start_matches("MURK_KEY=")
        .to_string();

    // Derive pubkey by parsing the key (we check it starts with AGE-SECRET-KEY).
    assert!(murk_key.starts_with("AGE-SECRET-KEY-"));

    let pubkey = {
        let identity: age::x25519::Identity = murk_key.parse().unwrap();
        identity.to_public().to_string()
    };

    (murk_key, pubkey)
}

/// Helper: build a murk command with MURK_KEY and vault set.
fn murk(dir: &TempDir, key: &str) -> Command {
    let mut cmd = Command::cargo_bin("murk").unwrap();
    cmd.current_dir(dir.path()).env("MURK_KEY", key);
    cmd
}

// ── init ──

#[test]
fn init_creates_vault_and_env() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("alice\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Recovery phrase")
                .or(predicate::str::contains("RECOVERY WORDS")),
        );

    assert!(dir.path().join("test.murk").exists());
    assert!(dir.path().join(".env").exists());

    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(env.contains("export MURK_KEY=AGE-SECRET-KEY-"));
}

#[test]
fn init_refuses_existing_vault() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    // Second init should fail because vault already exists.
    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .write_stdin("bob\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

// ── add / get ──

#[test]
fn add_and_get_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/mydb",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "DB_URL", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://localhost/mydb"));
}

#[test]
fn get_missing_key_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["get", "NONEXISTENT", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
}

#[test]
fn add_overwrites_existing_value() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "old_value", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "TOKEN", "new_value", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "TOKEN", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new_value"));
}

// ── private (mote) secrets ──

#[test]
fn private_secret_overrides_shared() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Add shared value.
    murk(&dir, &key)
        .args(["add", "API_KEY", "shared_key", "--vault", "test.murk"])
        .assert()
        .success();

    // Add private override.
    murk(&dir, &key)
        .args([
            "add",
            "API_KEY",
            "my_personal_key",
            "--private",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Get should return private override.
    murk(&dir, &key)
        .args(["get", "API_KEY", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("my_personal_key"));
}

// ── rm ──

#[test]
fn rm_removes_secret() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TEMP", "deleteme", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["rm", "TEMP", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "TEMP", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key not found"));
}

// ── ls ──

#[test]
fn ls_lists_key_names() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "ALPHA", "a", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "BRAVO", "b", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA").and(predicate::str::contains("BRAVO")));
}

#[test]
fn ls_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "SECRET", "val", "--vault", "test.murk"])
        .assert()
        .success();

    // ls reads header only — no MURK_KEY needed.
    Command::cargo_bin("murk")
        .unwrap()
        .args(["ls", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .success()
        .stdout(predicate::str::contains("SECRET"));
}

// ── describe ──

#[test]
fn describe_adds_description() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "DB_URL",
            "PostgreSQL connection string",
            "--example",
            "postgres://user:pass@host/db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // info should show the description.
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("PostgreSQL connection string")
                .and(predicate::str::contains("postgres://user:pass@host/db")),
        );
}

// ── info ──

#[test]
fn info_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "secret", "--vault", "test.murk"])
        .assert()
        .success();

    // info reads header only — works without key.
    Command::cargo_bin("murk")
        .unwrap()
        .args(["info", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN"));
}

// ── export ──

#[test]
fn export_produces_shell_statements() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "FOO", "bar", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "BAZ", "qux", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export FOO='bar'")
                .and(predicate::str::contains("export BAZ='qux'")),
        );
}

#[test]
fn export_merges_private_overrides() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "KEY", "shared_val", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "add",
            "KEY",
            "private_val",
            "--private",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("export KEY='private_val'"));
}

#[test]
fn export_escapes_single_quotes() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "QUOTED", "it's a test", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("export QUOTED='it'\\''s a test'"));
}

// ── recover ──

#[test]
fn recover_shows_phrase() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let output = murk(&dir, &key).args(["recover"]).assert().success();

    // Recovery phrase is 24 words on stdout.
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let word_count = stdout.trim().split_whitespace().count();
    assert_eq!(
        word_count, 24,
        "recovery phrase should be 24 words, got {word_count}"
    );
}

#[test]
fn recover_without_key_fails() {
    Command::cargo_bin("murk")
        .unwrap()
        .args(["recover"])
        .env_remove("MURK_KEY")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

// ── recipients ──

#[test]
fn recipients_lists_creator() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["recipients", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains(&pubkey)
                .and(predicate::str::contains("testuser"))
                .and(predicate::str::contains("(you)")),
        );
}

#[test]
fn recipients_works_without_murk_key() {
    let dir = TempDir::new().unwrap();
    let (_, pubkey) = init_vault(&dir);

    // Without MURK_KEY, just shows pubkeys (no names).
    Command::cargo_bin("murk")
        .unwrap()
        .args(["recipients", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .success()
        .stdout(predicate::str::contains(&pubkey));
}

// ── authorize / revoke ──

#[test]
fn authorize_adds_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Generate a second keypair to authorize.
    let second_identity = age::x25519::Identity::generate();
    let second_pubkey = second_identity.to_public().to_string();

    murk(&dir, &key)
        .args(["authorize", &second_pubkey, "bob", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("authorized bob"));

    murk(&dir, &key)
        .args(["recipients", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&second_pubkey).and(predicate::str::contains("bob")));
}

#[test]
fn authorize_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["authorize", &pubkey, "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already a recipient"));
}

#[test]
fn authorize_invalid_key_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["authorize", "not-a-real-key", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid public key"));
}

#[test]
fn revoke_removes_recipient() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let second_identity = age::x25519::Identity::generate();
    let second_pubkey = second_identity.to_public().to_string();

    // Authorize then revoke.
    murk(&dir, &key)
        .args(["authorize", &second_pubkey, "bob", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["revoke", "bob", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("removed"))
        .stderr(predicate::str::contains("bob"));

    // Should no longer appear in recipients.
    murk(&dir, &key)
        .args(["recipients", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&second_pubkey).not());
}

#[test]
fn revoke_by_pubkey_works() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    let second_identity = age::x25519::Identity::generate();
    let second_pubkey = second_identity.to_public().to_string();

    murk(&dir, &key)
        .args(["authorize", &second_pubkey, "--vault", "test.murk"])
        .assert()
        .success();

    // Revoke by pubkey instead of name.
    murk(&dir, &key)
        .args(["revoke", &second_pubkey, "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["recipients", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&second_pubkey).not());
}

#[test]
fn revoke_last_recipient_fails() {
    let dir = TempDir::new().unwrap();
    let (key, pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["revoke", &pubkey, "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot revoke last recipient"));
}

#[test]
fn revoke_unknown_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["revoke", "nobody", "--vault", "test.murk"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("recipient not found"));
}

// ── no MURK_KEY scenarios ──

#[test]
fn add_without_key_fails() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    Command::cargo_bin("murk")
        .unwrap()
        .args(["add", "X", "Y", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

#[test]
fn get_without_key_fails() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    Command::cargo_bin("murk")
        .unwrap()
        .args(["get", "X", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

#[test]
fn export_without_key_fails() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    Command::cargo_bin("murk")
        .unwrap()
        .args(["export", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

// ── no vault file scenarios ──

#[test]
fn get_missing_vault_fails() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("murk")
        .unwrap()
        .args(["get", "X", "--vault", "nonexistent.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", "AGE-SECRET-KEY-1DUMMY")
        .assert()
        .failure();
}

#[test]
fn ls_missing_vault_fails() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("murk")
        .unwrap()
        .args(["ls", "--vault", "nonexistent.murk"])
        .current_dir(dir.path())
        .assert()
        .failure();
}

// ── multi-recipient workflow ──

#[test]
fn authorized_recipient_can_decrypt() {
    let dir = TempDir::new().unwrap();
    let (key_a, _) = init_vault(&dir);

    // Add a secret.
    murk(&dir, &key_a)
        .args([
            "add",
            "SHARED_SECRET",
            "hello_world",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Generate second identity and authorize.
    let id_b = age::x25519::Identity::generate();
    let pk_b = id_b.to_public().to_string();
    let key_b = {
        use age::secrecy::ExposeSecret;
        id_b.to_string().expose_secret().to_string()
    };

    murk(&dir, &key_a)
        .args(["authorize", &pk_b, "bob", "--vault", "test.murk"])
        .assert()
        .success();

    // Bob should be able to decrypt the shared secret.
    murk(&dir, &key_b)
        .args(["get", "SHARED_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));
}

// ── end-to-end workflow ──

#[test]
fn full_lifecycle() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Add secrets.
    murk(&dir, &key)
        .args(["add", "DB_HOST", "localhost", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "DB_PASS", "hunter2", "--vault", "test.murk"])
        .assert()
        .success();

    // Describe.
    murk(&dir, &key)
        .args([
            "describe",
            "DB_HOST",
            "Database hostname",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // List.
    murk(&dir, &key)
        .args(["ls", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_HOST").and(predicate::str::contains("DB_PASS")));

    // Get.
    murk(&dir, &key)
        .args(["get", "DB_PASS", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2"));

    // Export.
    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB_HOST='localhost'")
                .and(predicate::str::contains("export DB_PASS='hunter2'")),
        );

    // Remove one.
    murk(&dir, &key)
        .args(["rm", "DB_PASS", "--vault", "test.murk"])
        .assert()
        .success();

    // Should be gone.
    murk(&dir, &key)
        .args(["get", "DB_PASS", "--vault", "test.murk"])
        .assert()
        .failure();

    // But other key still there.
    murk(&dir, &key)
        .args(["get", "DB_HOST", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("localhost"));
}
