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
fn init_existing_vault_authorized() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Second init with authorized key shows "authorized".
    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", &key)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists").and(predicate::str::contains("authorized")),
        );
}

#[test]
fn init_existing_vault_unauthorized() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    // Generate a different key that isn't authorized on this vault.
    let other_dir = TempDir::new().unwrap();
    let (other_key, _) = init_vault(&other_dir);

    // Init with unauthorized key shows pubkey to share.
    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env("MURK_KEY", &other_key)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists")
                .and(predicate::str::contains("not authorized"))
                .and(predicate::str::contains("age1")),
        );
}

#[test]
fn init_existing_vault_no_key() {
    let dir = TempDir::new().unwrap();
    init_vault(&dir);

    // Remove .env so there's no key to find.
    fs::remove_file(dir.path().join(".env")).unwrap();

    // Init without a key generates one and shows unauthorized + pubkey.
    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .env_remove("MURK_KEY_FILE")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists")
                .and(predicate::str::contains("Generating keypair"))
                .and(predicate::str::contains("RECOVERY WORDS"))
                .and(predicate::str::contains("not authorized"))
                .and(predicate::str::contains("age1")),
        );

    // .env should now contain a new MURK_KEY.
    let env = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(env.contains("export MURK_KEY=AGE-SECRET-KEY-"));
}

#[test]
fn init_existing_vault_reads_dotenv() {
    let dir = TempDir::new().unwrap();
    let (_key, _) = init_vault(&dir);

    // Key is in .env file but not in environment — should still detect it.
    Command::cargo_bin("murk")
        .unwrap()
        .args(["init", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .env_remove("MURK_KEY_FILE")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("already exists").and(predicate::str::contains("authorized")),
        );
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

// ── tagging ──

#[test]
fn add_with_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // info should show the tag.
    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[db]"));
}

#[test]
fn add_with_multiple_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--tag",
            "backend",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[db, backend]"));
}

#[test]
fn add_merges_tags_on_existing_key() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "DB_URL", "v1", "--tag", "db", "--vault", "test.murk"])
        .assert()
        .success();

    // Update value and add another tag.
    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "v2",
            "--tag",
            "backend",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[db, backend]"));
}

#[test]
fn describe_sets_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "secret", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "API token",
            "--tag",
            "auth",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[auth]"));
}

#[test]
fn describe_replaces_tags() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "TOKEN",
            "secret",
            "--tag",
            "old",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "describe",
            "TOKEN",
            "API token",
            "--tag",
            "new",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[new]").and(predicate::str::contains("[old]").not()));
}

#[test]
fn ls_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "add",
            "API_KEY",
            "sk-123",
            "--tag",
            "api",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    // Filter by "db" tag — should only show DB_URL.
    murk(&dir, &key)
        .args(["ls", "--tag", "db", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_URL").and(predicate::str::contains("API_KEY").not()));
}

#[test]
fn export_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "add",
            "API_KEY",
            "sk-123",
            "--tag",
            "api",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "UNTAGGED", "val", "--vault", "test.murk"])
        .assert()
        .success();

    // Export with --tag db — only DB_URL.
    murk(&dir, &key)
        .args(["export", "--tag", "db", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB_URL=")
                .and(predicate::str::contains("API_KEY").not())
                .and(predicate::str::contains("UNTAGGED").not()),
        );
}

#[test]
fn export_without_tag_exports_all() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["add", "UNTAGGED", "val", "--vault", "test.murk"])
        .assert()
        .success();

    // Export without --tag — should get everything.
    murk(&dir, &key)
        .args(["export", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB_URL=")
                .and(predicate::str::contains("export UNTAGGED=")),
        );
}

#[test]
fn info_filters_by_tag() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args([
            "add",
            "DB_URL",
            "postgres://localhost/db",
            "--tag",
            "db",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args([
            "add",
            "API_KEY",
            "sk-123",
            "--tag",
            "api",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--tag", "api", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY").and(predicate::str::contains("DB_URL").not()));
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

// ── stdin support ──

#[test]
fn add_via_stdin_pipe() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Pipe value via stdin (omit value argument).
    murk(&dir, &key)
        .args(["add", "PIPED_SECRET", "--vault", "test.murk"])
        .write_stdin("s3cr3t-from-pipe\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "PIPED_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("s3cr3t-from-pipe"));
}

#[test]
fn add_via_stdin_dash() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Explicit "-" means read from stdin.
    murk(&dir, &key)
        .args(["add", "DASH_SECRET", "-", "--vault", "test.murk"])
        .write_stdin("val-from-dash\n")
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "DASH_SECRET", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("val-from-dash"));
}

#[test]
fn add_via_stdin_empty_fails() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Empty stdin should fail.
    murk(&dir, &key)
        .args(["add", "EMPTY", "--vault", "test.murk"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty value"));
}

#[test]
fn add_explicit_value_still_works() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Explicit value on CLI still works as before.
    murk(&dir, &key)
        .args(["add", "CLI_VAL", "direct-value", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["get", "CLI_VAL", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("direct-value"));
}

// ── env (direnv) ──

#[test]
fn env_creates_envrc() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    murk(&dir, &key)
        .args(["env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("created .envrc"));

    let envrc = fs::read_to_string(dir.path().join(".envrc")).unwrap();
    assert!(envrc.contains("murk export"));
}

#[test]
fn env_appends_to_existing() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    fs::write(dir.path().join(".envrc"), "# existing config\n").unwrap();

    murk(&dir, &key)
        .args(["env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("appended"));

    let envrc = fs::read_to_string(dir.path().join(".envrc")).unwrap();
    assert!(envrc.contains("# existing config"));
    assert!(envrc.contains("murk export"));
}

#[test]
fn env_skips_if_present() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    fs::write(
        dir.path().join(".envrc"),
        "eval \"$(murk export --vault test.murk)\"\n",
    )
    .unwrap();

    murk(&dir, &key)
        .args(["env", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("already contains"));
}

// ── diff ──

#[test]
fn diff_shows_no_changes() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Initialize git repo and commit the vault.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["add", "test.murk"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(dir.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .unwrap();

    // No changes since commit — should say "no changes".
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no changes"));
}

#[test]
fn diff_shows_added_key() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Initialize git repo and commit the vault.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["add", "test.murk"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(dir.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .unwrap();

    // Add a secret after the commit.
    murk(&dir, &key)
        .args(["add", "NEW_KEY", "new-value", "--vault", "test.murk"])
        .assert()
        .success();

    // Diff should show NEW_KEY as added.
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NEW_KEY"));
}

#[test]
fn diff_no_git_vault_shows_all_added() {
    let dir = TempDir::new().unwrap();
    let (key, _pubkey) = init_vault(&dir);

    // Initialize git repo but don't commit the vault.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Add a secret.
    murk(&dir, &key)
        .args(["add", "FRESH", "value", "--vault", "test.murk"])
        .assert()
        .success();

    // Diff against HEAD should show FRESH as added (vault didn't exist at HEAD).
    murk(&dir, &key)
        .args(["diff", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FRESH"));
}

// ── merge-driver ──

/// Helper: write a vault JSON file for merge driver tests.
fn write_vault_json(dir: &std::path::Path, filename: &str, json: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    fs::write(&path, json).unwrap();
    path
}

#[test]
fn merge_driver_clean_merge() {
    let dir = TempDir::new().unwrap();

    // Base vault: one secret.
    let base_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher-db" }
  },
  "meta": "base-meta"
}"#;

    // Ours: adds API_KEY.
    let ours_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "API_KEY": { "description": "api key", "tags": [] },
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "API_KEY": { "shared": "ours-cipher-api" },
    "DB_URL": { "shared": "base-cipher-db" }
  },
  "meta": "ours-meta"
}"#;

    // Theirs: adds STRIPE_KEY.
    let theirs_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] },
    "STRIPE_KEY": { "description": "stripe", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher-db" },
    "STRIPE_KEY": { "shared": "theirs-cipher-stripe" }
  },
  "meta": "theirs-meta"
}"#;

    let base_path = write_vault_json(dir.path(), "base.murk", base_json);
    let ours_path = write_vault_json(dir.path(), "ours.murk", ours_json);
    let theirs_path = write_vault_json(dir.path(), "theirs.murk", theirs_json);

    Command::cargo_bin("murk")
        .unwrap()
        .args([
            "merge-driver",
            base_path.to_str().unwrap(),
            ours_path.to_str().unwrap(),
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("merged cleanly"));

    // Verify the merged result contains all three keys.
    let merged = fs::read_to_string(&ours_path).unwrap();
    assert!(merged.contains("API_KEY"));
    assert!(merged.contains("STRIPE_KEY"));
    assert!(merged.contains("DB_URL"));
}

#[test]
fn merge_driver_conflict_exit_code() {
    let dir = TempDir::new().unwrap();

    let base_json = r#"{
  "version": "2.0",
  "created": "2026-01-01T00:00:00Z",
  "vault_name": ".murk",
  "recipients": ["age1alice"],
  "schema": {
    "DB_URL": { "description": "database", "tags": [] }
  },
  "secrets": {
    "DB_URL": { "shared": "base-cipher" }
  },
  "meta": "base-meta"
}"#;

    // Both sides modify DB_URL.
    let ours_json = base_json.replace("base-cipher", "ours-cipher");
    let theirs_json = base_json.replace("base-cipher", "theirs-cipher");

    let base_path = write_vault_json(dir.path(), "base.murk", base_json);
    let ours_path = write_vault_json(dir.path(), "ours.murk", &ours_json);
    let theirs_path = write_vault_json(dir.path(), "theirs.murk", &theirs_json);

    Command::cargo_bin("murk")
        .unwrap()
        .args([
            "merge-driver",
            base_path.to_str().unwrap(),
            ours_path.to_str().unwrap(),
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("conflict").and(predicate::str::contains("DB_URL")));
}

// ── setup-merge-driver ──

#[test]
fn setup_merge_driver_creates_gitattributes() {
    let dir = TempDir::new().unwrap();

    // Initialize a git repo in the temp dir.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    Command::cargo_bin("murk")
        .unwrap()
        .args(["setup-merge-driver"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("merge driver configured"));

    // Check .gitattributes.
    let gitattributes = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert!(gitattributes.contains("*.murk merge=murk"));

    // Check git config.
    let output = std::process::Command::new("git")
        .args(["config", "merge.murk.driver"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let driver = String::from_utf8_lossy(&output.stdout);
    assert!(driver.contains("murk merge-driver %O %A %B"));
}

#[test]
fn setup_merge_driver_idempotent() {
    let dir = TempDir::new().unwrap();

    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Run twice.
    for _ in 0..2 {
        Command::cargo_bin("murk")
            .unwrap()
            .args(["setup-merge-driver"])
            .current_dir(dir.path())
            .assert()
            .success();
    }

    // Should have the line only once.
    let gitattributes = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert_eq!(
        gitattributes.matches("*.murk merge=murk").count(),
        1,
        "should not duplicate the gitattributes entry"
    );
}

// ── codename + repo ──

#[test]
fn info_displays_codename() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "TOKEN", "secret", "--vault", "test.murk"])
        .assert()
        .success();

    murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("codename"));
}

#[test]
fn codename_changes_when_vault_changes() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    // Get info output after adding first secret.
    murk(&dir, &key)
        .args(["add", "A", "val1", "--vault", "test.murk"])
        .assert()
        .success();
    let out1 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();
    let info1 = String::from_utf8(out1.stdout).unwrap();

    // Get info output after adding second secret.
    murk(&dir, &key)
        .args(["add", "B", "val2", "--vault", "test.murk"])
        .assert()
        .success();
    let out2 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();
    let info2 = String::from_utf8(out2.stdout).unwrap();

    // Extract codename lines.
    let cn1 = info1.lines().find(|l| l.contains("codename")).unwrap();
    let cn2 = info2.lines().find(|l| l.contains("codename")).unwrap();
    assert_ne!(
        cn1, cn2,
        "codename should change when vault content changes"
    );
}

#[test]
fn codename_is_deterministic() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "X", "val", "--vault", "test.murk"])
        .assert()
        .success();

    let out1 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();
    let out2 = murk(&dir, &key)
        .args(["info", "--vault", "test.murk"])
        .output()
        .unwrap();

    let info1 = String::from_utf8(out1.stdout).unwrap();
    let info2 = String::from_utf8(out2.stdout).unwrap();

    let cn1 = info1.lines().find(|l| l.contains("codename")).unwrap();
    let cn2 = info2.lines().find(|l| l.contains("codename")).unwrap();
    assert_eq!(cn1, cn2, "same file should produce same codename");
}

#[test]
fn old_vault_without_repo_parses() {
    let dir = TempDir::new().unwrap();
    let vault_json = r#"{
        "version": "2.0",
        "created": "2026-01-01T00:00:00Z",
        "vault_name": ".murk",
        "recipients": [],
        "schema": {},
        "secrets": {},
        "meta": ""
    }"#;
    fs::write(dir.path().join("test.murk"), vault_json).unwrap();

    Command::cargo_bin("murk")
        .unwrap()
        .args(["info", "--vault", "test.murk"])
        .current_dir(dir.path())
        .env_remove("MURK_KEY")
        .assert()
        .success()
        .stdout(predicate::str::contains("codename"));
}
