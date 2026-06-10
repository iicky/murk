use murk_cli::{
    DiffKind, EnvrcStatus, MergeDriverSetupStep, MurkIdentity, is_valid_key_name, recovery, types,
    vault,
};

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::process;

use age::secrecy::ExposeSecret;
use clap::{CommandFactory, Parser, Subcommand};
use colored::Colorize;

/// Print an error message and exit with the given code.
fn die(msg: &dyn std::fmt::Display, code: i32) -> ! {
    eprintln!("{} {msg}", "✕".red());
    process::exit(code);
}

/// Unwrap a result or print the error and exit with code 1.
fn try_or_die<T>(result: Result<T, impl std::fmt::Display>) -> T {
    result.unwrap_or_else(|e| die(&e, 1))
}

/// Encrypted secrets manager for developers.
#[derive(Parser)]
#[command(name = "murk", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new vault and generate a keypair
    Init {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Re-derive recovery phrase from current MURK_KEY
    Recover,

    /// Restore MURK_KEY from a BIP39 recovery phrase
    Restore,

    /// Import secrets from a .env file
    Import {
        /// Path to the .env file to import
        #[arg(default_value = ".env")]
        file: String,
        /// Overwrite existing secrets without prompting
        #[arg(long)]
        force: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add or update a secret
    Add {
        /// Secret key name
        key: String,
        /// Description for this key
        #[arg(long)]
        desc: Option<String>,
        /// Encrypt to only your key (scoped override)
        #[arg(long)]
        scoped: bool,
        /// Tag for grouping (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Generate a random secret and store it
    Generate {
        /// Secret key name
        key: String,
        /// Length in bytes (default 32)
        #[arg(long, default_value = "32")]
        length: usize,
        /// Output as hex instead of base64
        #[arg(long)]
        hex: bool,
        /// Description for this key
        #[arg(long)]
        desc: Option<String>,
        /// Tag for grouping (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Rotate secrets with new values
    Rotate {
        /// Secret key name (omit for --all)
        key: Option<String>,
        /// Rotate all secrets in the vault
        #[arg(long)]
        all: bool,
        /// Generate random values instead of prompting
        #[arg(long)]
        generate: bool,
        /// Length in bytes for generated values (default 32)
        #[arg(long, default_value = "32")]
        length: usize,
        /// Output generated values as hex instead of base64
        #[arg(long)]
        hex: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a secret
    Rm {
        /// Secret key name
        key: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Get a single decrypted value
    Get {
        /// Secret key name
        key: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List all key names
    Ls {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add or update a key description
    Describe {
        /// Secret key name
        key: String,
        /// Description text
        description: String,
        /// Example value
        #[arg(long)]
        example: Option<String>,
        /// Tag for grouping (repeatable, replaces existing tags)
        #[arg(long)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Show public schema and key info
    Info {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export all secrets as shell export statements
    Export {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Edit secrets in $EDITOR
    Edit {
        /// Edit a single key (omit to edit all)
        key: Option<String>,
        /// Edit scoped overrides instead of shared secrets
        #[arg(long)]
        scoped: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Run a command with secrets injected as environment variables
    #[command(trailing_var_arg = true)]
    Exec {
        /// Only inject these specific keys (repeatable)
        #[arg(long)]
        only: Vec<String>,
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Strip inherited environment (only murk secrets + PATH)
        #[arg(long)]
        clean_env: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Command and arguments to execute
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Add a recipient to the vault
    #[command(hide = true)]
    Authorize {
        /// Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username
        pubkey: String,
        /// Display name for this recipient
        #[arg(long)]
        name: Option<String>,
        /// Accept changed GitHub keys without confirmation
        #[arg(long)]
        force: bool,
        /// Allow ssh-rsa recipients (rejected by default — use ed25519)
        #[arg(long)]
        allow_ssh_rsa: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a recipient from the vault
    #[command(hide = true)]
    Revoke {
        /// Recipient pubkey or display name
        recipient: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Manage recipients
    #[command(alias = "recipients")]
    Circle {
        #[command(subcommand)]
        sub: Option<CircleCommand>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Write a .envrc for direnv integration
    Env {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Show secret changes vs a git ref
    Diff {
        /// Git ref to compare against
        #[arg(default_value = "HEAD")]
        git_ref: String,
        /// Show actual values (not just key names)
        #[arg(long)]
        show_values: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Git merge driver for .murk vault files (called by git)
    #[command(name = "merge-driver")]
    MergeDriver {
        /// Path to base version (%O)
        base: String,
        /// Path to ours version (%A) — result is written here
        ours: String,
        /// Path to theirs version (%B)
        theirs: String,
    },

    /// Configure git to use murk's merge driver for .murk files
    #[command(name = "setup-merge-driver")]
    SetupMergeDriver,

    /// Verify vault integrity without exporting secrets
    Verify {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Check the surrounding repo for hygiene issues
    Doctor,

    /// Export schema-only vault with no secrets or recipients
    Skeleton {
        /// Output file (prints to stdout if omitted)
        #[arg(long, short)]
        output: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Scan files for leaked secret values
    Scan {
        /// Files or directories to scan (defaults to current directory)
        paths: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Generate or install shell completions
    Completion {
        #[command(subcommand)]
        action: CompletionAction,
    },
}

#[derive(Subcommand)]
enum CompletionAction {
    /// Print completions to stdout
    Generate {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Install completions to the standard path
    Install {
        /// Shell to install completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum CircleCommand {
    /// Add a recipient to the vault
    Authorize {
        /// Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username
        pubkey: String,
        /// Display name for this recipient
        #[arg(long)]
        name: Option<String>,
        /// Accept changed GitHub keys without confirmation
        #[arg(long)]
        force: bool,
        /// Allow ssh-rsa recipients (rejected by default — use ed25519)
        #[arg(long)]
        allow_ssh_rsa: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a recipient from the vault
    Revoke {
        /// Recipient pubkey or display name
        recipient: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

/// Prompt the user for a line of input, with an optional default value.
fn prompt(label: &str, default: Option<&str>) -> String {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    if let Some(def) = default {
        eprint!("{label} [{def}]: ");
    } else {
        eprint!("{label}: ");
    }
    stdout.flush().ok();

    let mut line = String::new();
    stdin.lock().read_line(&mut line).unwrap_or(0);
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        trimmed
    }
}

/// Generate a BIP39 keypair, write key to ~/.config/murk/keys/, reference in .env.
/// Returns (secret_key, pubkey). Secret key is wrapped in `Zeroizing` so the
/// plaintext clears when the caller drops it.
fn generate_and_write_key(vault_name: &str) -> (zeroize::Zeroizing<String>, String) {
    eprintln!("{} generating keypair...", "◆".magenta());
    let (phrase, secret_key, pubkey) = try_or_die(recovery::generate());

    // Check .env for existing MURK_KEY.
    if murk_cli::dotenv_has_murk_key() {
        let answer = prompt(
            "MURK_KEY already exists in .env. Overwrite? [y/N]",
            Some("N"),
        );
        if !answer.eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            process::exit(1);
        }
    }

    // Write key to ~/.config/murk/keys/<hash> and reference in .env.
    let key_path = try_or_die(murk_cli::key_file_path(vault_name));
    try_or_die(murk_cli::write_key_to_file(&key_path, &secret_key));
    try_or_die(murk_cli::write_key_ref_to_dotenv(&key_path));
    eprintln!(
        "{} key saved to {}",
        "◆".magenta(),
        key_path.display().to_string().dimmed()
    );

    // Print recovery phrase.
    eprintln!();
    eprintln!(
        "{} {}",
        "⚠".yellow(),
        "RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:"
            .yellow()
            .bold()
    );
    eprintln!("  {}", phrase.as_str().bold());
    eprintln!();
    eprintln!(
        "  {}",
        ".env contains a reference to your key — it is safe to commit, but the key file is not"
            .dimmed()
    );

    (secret_key, pubkey)
}

fn cmd_init(vault_name: &str) {
    let vault_path = Path::new(vault_name);

    // If vault already exists, handle onboarding flow.
    if vault_path.exists() {
        let vault = try_or_die(vault::read(vault_path));

        eprintln!("{}", format!("{vault_name} already exists").dimmed());

        // Try to find an existing key: env var first, then .env file.
        let dk = try_or_die(murk_cli::discover_existing_key());
        let (secret_key, pubkey) = match dk {
            Some(dk) => (Some(dk.secret_key), dk.pubkey),
            None => {
                let (_secret_key, pubkey) = generate_and_write_key(vault_name);
                eprintln!();
                (None, pubkey)
            }
        };

        let status = match secret_key.as_deref() {
            Some(sk) => try_or_die(murk_cli::check_init_status(&vault, sk)),
            None => {
                // No secret key — fall back to simple recipient check.
                if vault.recipients.contains(&pubkey) {
                    eprintln!("{} authorized  {}", "◆".magenta(), pubkey.dimmed());
                } else {
                    eprintln!(
                        "{} {}",
                        "⚠".yellow(),
                        "not authorized \u{2014} share your public key to get added:".yellow()
                    );
                    eprintln!("  {}", pubkey.bold());
                }
                return;
            }
        };

        if status.authorized {
            let name_display = match status.display_name {
                Some(ref name) if !name.is_empty() => format!("  {}", name.bold()),
                _ => String::new(),
            };
            eprintln!(
                "{} authorized  {}{}",
                "◆".magenta(),
                status.pubkey.dimmed(),
                name_display
            );
        } else {
            eprintln!(
                "{} {}",
                "⚠".yellow(),
                "not authorized \u{2014} share your public key to get added:".yellow()
            );
            eprintln!("  {}", status.pubkey.bold());
        }
        return;
    }

    // --- New vault flow ---

    // Prompt for display name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        die(&"name is required", 1);
    }

    let (_secret_key, pubkey) = generate_and_write_key(vault_name);

    let v = try_or_die(murk_cli::create_vault(vault_name, &pubkey, &name));
    try_or_die(vault::write(vault_path, &v));

    eprintln!();
    eprintln!(
        "{} vault initialized — added {} as recipient",
        "◆".magenta(),
        name.bold()
    );
    eprintln!("  {}", "run: murk add KEY".dimmed());
}

fn resolve_key() -> age::secrecy::SecretString {
    try_or_die(murk_cli::resolve_key())
}

fn load_vault(vault: &str) -> (types::Vault, types::Murk, MurkIdentity) {
    murk_cli::warn_env_permissions();
    let result = try_or_die(murk_cli::load_vault(vault));
    if result.1.legacy_mac {
        eprintln!(
            "{} vault uses legacy unkeyed MAC — run any write command to upgrade to BLAKE3",
            "warn".yellow().bold()
        );
    }
    result
}

/// Load the vault while holding an exclusive lock for the entire read-modify-write cycle.
/// Returns the lock guard — hold it until after `save_vault` completes.
fn load_vault_locked(
    vault: &str,
) -> (
    types::Vault,
    types::Murk,
    MurkIdentity,
    murk_cli::vault::VaultLock,
) {
    let lock = try_or_die(
        murk_cli::vault::lock(std::path::Path::new(vault)).map_err(murk_cli::MurkError::Vault),
    );
    let (v, m, i) = load_vault(vault);
    (v, m, i, lock)
}

fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) {
    try_or_die(murk_cli::save_vault(vault_path, vault, original, current));
}

/// Resolve the secret value from stdin pipe or interactive prompt.
/// Returns the value or exits with an error.
fn resolve_value(key: &str) -> String {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        // Piped input: read one line so multiple calls can each consume a value
        // e.g. `printf "v1\nv2\n" | murk rotate --all`
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
        let trimmed = line.trim_end_matches('\n').to_string();
        if trimmed.is_empty() {
            die(&"empty value from stdin", 1);
        }
        return trimmed;
    }

    // Interactive TTY: prompt without echo.
    eprint!("value for {key}: ");
    io::stderr().flush().ok();
    let password = rpassword::read_password().unwrap_or_else(|e| {
        eprintln!();
        die(&format_args!("reading input: {e}"), 1);
    });
    if password.is_empty() {
        die(&"empty value", 1);
    }
    password
}

fn cmd_add(
    key: &str,
    value: &str,
    desc: Option<&str>,
    scoped: bool,
    tags: &[String],
    vault_path: &str,
) {
    if !is_valid_key_name(key) {
        die(
            &format_args!(
                "invalid key name: {}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]",
                key.bold()
            ),
            1,
        );
    }

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let needs_desc_hint = murk_cli::add_secret(
        &mut vault,
        &mut current,
        key,
        value,
        desc,
        scoped,
        tags,
        &identity,
    );

    if scoped {
        eprintln!("{} added {} (scoped)", "✦".yellow(), key.bold());
    } else {
        eprintln!("{} added {}", "◆".magenta(), key.bold());
    }

    if needs_desc_hint {
        eprintln!(
            "  {}",
            format!("run: murk describe {key} \"your description\"").dimmed()
        );
    }

    save_vault(vault_path, &mut vault, &original, &current);
}

fn cmd_import(file: &str, force: bool, vault_path: &str) {
    // Wrap the raw file contents in Zeroizing so the plaintext is wiped
    // from memory as soon as parsing completes, not when the function returns.
    let contents = zeroize::Zeroizing::new(
        fs::read_to_string(file)
            .unwrap_or_else(|e| die(&format_args!("cannot read {file}: {e}"), 1)),
    );

    // Warn about MURK_* keys that will be skipped during import.
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim();
            if key.starts_with("MURK_") {
                eprintln!(
                    "{} skipping {}: murk variables cannot be imported",
                    "⚠".yellow(),
                    key.bold()
                );
            }
        }
    }

    let all_pairs = murk_cli::parse_env(&contents);

    // Filter out keys that aren't valid shell identifiers. Values stay
    // wrapped in Zeroizing end-to-end.
    let mut pairs: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();
    for (key, value) in &all_pairs {
        if is_valid_key_name(key) {
            pairs.push((key.clone(), value.clone()));
        } else {
            eprintln!("{} skipping invalid key name: {}", "⚠".yellow(), key.bold());
        }
    }

    if pairs.is_empty() {
        eprintln!("{}", format!("no secrets found in {file}").dimmed());
        return;
    }

    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    // Check for collisions with existing secrets.
    if !force {
        let collisions: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| current.values.contains_key(k))
            .map(|(k, _)| k.as_str())
            .collect();
        if !collisions.is_empty() {
            for key in &collisions {
                eprintln!("{} {} already exists", "warn".yellow().bold(), key.bold());
            }
            die(
                &format_args!(
                    "{} existing secret{} would be overwritten. Use --force to overwrite",
                    collisions.len(),
                    if collisions.len() == 1 { "" } else { "s" }
                ),
                1,
            );
        }
    }

    let imported = murk_cli::import_secrets(&mut vault, &mut current, &pairs);

    for key in &imported {
        eprintln!("  {} {}", "◆".magenta(), key.bold());
    }

    save_vault(vault_path, &mut vault, &original, &current);
    let count = imported.len();
    eprintln!(
        "{} imported {count} secret{}",
        "◆".magenta(),
        if count == 1 { "" } else { "s" }
    );
}

fn cmd_generate(
    key: &str,
    length: usize,
    hex: bool,
    desc: Option<&str>,
    tags: &[String],
    vault_path: &str,
) {
    use base64::Engine;

    if !is_valid_key_name(key) {
        die(
            &format_args!(
                "invalid key name: {}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]",
                key.bold()
            ),
            1,
        );
    }

    let bytes: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();

    let value = if hex {
        bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    };

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    murk_cli::add_secret(
        &mut vault,
        &mut current,
        key,
        &value,
        desc,
        false,
        tags,
        &identity,
    );

    eprintln!("{} generated {}", "◆".magenta(), key.bold());

    save_vault(vault_path, &mut vault, &original, &current);
}

fn cmd_rotate(
    key: Option<&str>,
    all: bool,
    generate: bool,
    length: usize,
    hex: bool,
    vault_path: &str,
) {
    use base64::Engine;

    if key.is_none() && !all {
        die(&"specify a key name or use --all", 1);
    }
    if key.is_some() && all {
        die(&"cannot specify both a key name and --all", 1);
    }
    if all && generate {
        die(
            &"--generate cannot be used with --all — external secrets need manual rotation",
            1,
        );
    }

    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let keys_to_rotate: Vec<String> = if all {
        vault.secrets.keys().cloned().collect()
    } else {
        let k = key.unwrap();
        if !vault.secrets.contains_key(k) {
            die(&format_args!("key {} not found in vault", k.bold()), 1);
        }
        vec![k.to_string()]
    };

    if keys_to_rotate.is_empty() {
        eprintln!("{}", "no secrets to rotate".dimmed());
        return;
    }

    let mut rotated = 0;
    for k in &keys_to_rotate {
        let new_value = if generate {
            let bytes: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();
            if hex {
                bytes.iter().fold(String::new(), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{b:02x}");
                    s
                })
            } else {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
            }
        } else {
            resolve_value(k)
        };

        murk_cli::add_secret(
            &mut vault,
            &mut current,
            k,
            &new_value,
            None,
            false,
            &[],
            &identity,
        );
        rotated += 1;
        eprintln!("{} rotated {}", "◆".magenta(), k.bold());
    }

    save_vault(vault_path, &mut vault, &original, &current);

    if rotated > 1 {
        eprintln!();
        eprintln!(
            "{} rotated {} secrets",
            "✓".green(),
            rotated.to_string().bold()
        );
    }
}

fn cmd_rm(key: &str, vault_path: &str) {
    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    murk_cli::remove_secret(&mut vault, &mut current, key);

    save_vault(vault_path, &mut vault, &original, &current);
    eprintln!("{} removed {}", "◆".magenta(), key.bold());
}

fn cmd_get(key: &str, vault_path: &str) {
    let (_vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    if let Some(value) = murk_cli::get_secret(&murk, key, &pubkey) {
        println!("{value}");
    } else {
        die(
            &format_args!(
                "key not found: {}. Run {} to see available keys",
                key.bold(),
                "murk ls".bold()
            ),
            1,
        );
    }
}

fn cmd_ls(tags: &[String], json: bool, vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let keys = murk_cli::list_keys(&vault, tags);
    if json {
        println!("{}", serde_json::to_string_pretty(&keys).unwrap());
    } else {
        for key in keys {
            println!("{key}");
        }
    }
}

fn cmd_describe(
    key: &str,
    description: &str,
    example: Option<&str>,
    tags: &[String],
    vault_path: &str,
) {
    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();

    murk_cli::describe_key(&mut vault, key, description, example, tags);

    // Describe only changes schema (plaintext) — but we still need to write the vault.
    // Re-save with no value changes so ciphertext is preserved.
    save_vault(vault_path, &mut vault, &original, &murk);
}

fn cmd_export(tags: &[String], json: bool, vault_path: &str) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    if json {
        let raw = murk_cli::resolve_secrets(&vault, &murk, &pubkey, tags);
        // serde_json copies into its own owned String, so zeroization ends here.
        let map: serde_json::Map<String, serde_json::Value> = raw
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.to_string())))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
    } else {
        let exports = murk_cli::export_secrets(&vault, &murk, &pubkey, tags);
        for (k, escaped) in &exports {
            if !is_valid_key_name(k) {
                eprintln!("{} skipping unsafe key name: {}", "⚠".yellow(), k.bold());
                continue;
            }
            println!("export {k}='{}'", escaped.as_str());
        }
    }
}

fn cmd_edit(key: Option<&str>, scoped: bool, vault_path: &str) {
    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    // Build the edit buffer.
    let (header, entries) = if let Some(k) = key {
        // Single key: just the raw value.
        let value = if scoped {
            current.scoped.get(k).and_then(|m| m.get(&pubkey)).cloned()
        } else {
            current.values.get(k).cloned()
        };
        let value = value.unwrap_or_else(|| {
            die(
                &format_args!(
                    "key {} not found{}",
                    k.bold(),
                    if scoped { " (scoped)" } else { "" }
                ),
                1,
            );
        });
        (
            format!(
                "# Editing {}{}\n# Save and quit to apply. Empty value or exit non-zero to abort.\n",
                k,
                if scoped { " (scoped)" } else { "" }
            ),
            vec![(k.to_string(), value)] as Vec<(String, zeroize::Zeroizing<String>)>,
        )
    } else {
        // All keys: KEY=VALUE format.
        let mut entries: Vec<(String, zeroize::Zeroizing<String>)> = if scoped {
            current
                .scoped
                .iter()
                .filter_map(|(k, m)| m.get(&pubkey).map(|v| (k.clone(), v.clone())))
                .collect()
        } else {
            current
                .values
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let header = format!(
            "# Edit secrets below. Lines starting with # are ignored.\n\
             # Format: KEY=VALUE (one per line).\n\
             # Delete a line to remove that secret. Add KEY=VALUE to create.\n\
             # Save and quit to apply. Exit non-zero to abort.\n{}\n",
            if scoped {
                "# Editing scoped overrides.\n"
            } else {
                ""
            }
        );
        (header, entries)
    };

    let single_key = key.is_some();
    let buffer: zeroize::Zeroizing<String> = if single_key {
        zeroize::Zeroizing::new(format!("{}{}", header, entries[0].1.as_str()))
    } else {
        let mut buf = header;
        for (k, v) in &entries {
            buf.push_str(&format!("{k}={}\n", v.as_str()));
        }
        zeroize::Zeroizing::new(buf)
    };

    // Prefer XDG_RUNTIME_DIR (typically tmpfs, not written to disk) over /tmp.
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let mut tmp = tempfile::Builder::new()
        .prefix("murk-edit-")
        .suffix(".env")
        .tempfile_in(&dir)
        .unwrap_or_else(|e| die(&format_args!("creating tempfile: {e}"), 1));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    use std::io::Write;
    tmp.write_all(buffer.as_bytes())
        .unwrap_or_else(|e| die(&format_args!("writing tempfile: {e}"), 1));
    tmp.flush()
        .unwrap_or_else(|e| die(&format_args!("flushing tempfile: {e}"), 1));

    // Open $EDITOR.
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".into());

    let path = tmp.path().to_path_buf();
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .unwrap_or_else(|e| die(&format_args!("launching {editor}: {e}"), 1));

    if !status.success() {
        // Securely wipe tempfile before exiting.
        overwrite_and_remove(&path);
        die(&"editor exited with error — aborting", 1);
    }

    // Read back the edited content. Wrap in Zeroizing so the plaintext
    // buffer is wiped as soon as parsing finishes.
    let edited = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| die(&format_args!("reading tempfile: {e}"), 1)),
    );

    // Securely wipe the tempfile (overwrite with zeros before unlinking).
    overwrite_and_remove(&path);

    // Parse and apply changes.
    if single_key {
        let k = key.unwrap();
        // Strip comment header, trim trailing newline.
        let mut new_value: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            edited
                .lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let trimmed_len = new_value.trim_end_matches('\n').len();
        new_value.truncate(trimmed_len);

        if new_value.is_empty() {
            eprintln!("{} empty value — no changes", "◆".magenta());
            return;
        }

        let old_value: Option<zeroize::Zeroizing<String>> = if scoped {
            current.scoped.get(k).and_then(|m| m.get(&pubkey)).cloned()
        } else {
            current.values.get(k).cloned()
        };

        if old_value.as_ref().map(|v| v.as_str()) == Some(new_value.as_str()) {
            eprintln!("{} no changes", "◆".magenta());
            return;
        }

        if scoped {
            current
                .scoped
                .entry(k.into())
                .or_default()
                .insert(pubkey.clone(), new_value);
        } else {
            current.values.insert(k.into(), new_value);
        }

        save_vault(vault_path, &mut vault, &original, &current);
        if scoped {
            eprintln!("{} updated {} (scoped)", "✦".yellow(), k.bold());
        } else {
            eprintln!("{} updated {}", "◆".magenta(), k.bold());
        }
    } else {
        // Multi-key: parse KEY=VALUE lines, diff against original.
        let mut new_entries: std::collections::BTreeMap<String, zeroize::Zeroizing<String>> =
            std::collections::BTreeMap::new();
        for line in edited.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (k, v) = match trimmed.split_once('=') {
                Some((k, v)) => (k.trim(), v),
                None => {
                    eprintln!(
                        "{} skipping malformed line: {}",
                        "⚠".yellow(),
                        trimmed.dimmed()
                    );
                    continue;
                }
            };
            if !is_valid_key_name(k) {
                eprintln!("{} skipping invalid key name: {}", "⚠".yellow(), k.bold());
                continue;
            }
            new_entries.insert(k.to_string(), zeroize::Zeroizing::new(v.to_string()));
        }

        // Compute diff.
        let old_entries: std::collections::BTreeMap<String, zeroize::Zeroizing<String>> =
            entries.into_iter().collect();
        let mut added = 0usize;
        let mut updated = 0usize;
        let mut removed = 0usize;

        // Add or update.
        for (k, v) in &new_entries {
            match old_entries.get(k) {
                Some(old_v) if old_v.as_str() == v.as_str() => {} // Unchanged.
                Some(_) => {
                    if scoped {
                        current
                            .scoped
                            .entry(k.clone())
                            .or_default()
                            .insert(pubkey.clone(), v.clone());
                    } else {
                        current.values.insert(k.clone(), v.clone());
                    }
                    updated += 1;
                }
                None => {
                    if scoped {
                        current
                            .scoped
                            .entry(k.clone())
                            .or_default()
                            .insert(pubkey.clone(), v.clone());
                    } else {
                        current.values.insert(k.clone(), v.clone());
                    }
                    // Ensure schema entry exists for new keys.
                    vault
                        .schema
                        .entry(k.clone())
                        .or_insert_with(murk_cli::types::SchemaEntry::default);
                    added += 1;
                }
            }
        }

        // Remove deleted keys.
        for k in old_entries.keys() {
            if !new_entries.contains_key(k) {
                if scoped {
                    if let Some(m) = current.scoped.get_mut(k) {
                        m.remove(&pubkey);
                    }
                } else {
                    current.values.remove(k);
                    current.scoped.remove(k);
                    vault.schema.remove(k);
                }
                removed += 1;
            }
        }

        if added == 0 && updated == 0 && removed == 0 {
            eprintln!("{} no changes", "◆".magenta());
            return;
        }

        save_vault(vault_path, &mut vault, &original, &current);

        let mut parts = vec![];
        if added > 0 {
            parts.push(format!("{added} added"));
        }
        if updated > 0 {
            parts.push(format!("{updated} updated"));
        }
        if removed > 0 {
            parts.push(format!("{removed} removed"));
        }
        eprintln!("{} {}", "◆".magenta(), parts.join(", "));
    }
}

/// Overwrite a file with zeros and remove it.
fn overwrite_and_remove(path: &std::path::Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len() as usize;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write;
            let _ = f.write_all(&vec![0u8; len]);
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

fn cmd_exec(
    command: &[String],
    only: &[String],
    tags: &[String],
    clean_env: bool,
    vault_path: &str,
) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let mut secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, tags);

    // Filter to specific keys if --only is provided.
    if !only.is_empty() {
        secrets.retain(|k, _| only.contains(k));
        for key in only {
            if !secrets.contains_key(key) {
                die(&format_args!("key not found: {key}"), 1);
            }
        }
    }

    let program = &command[0];
    let args = &command[1..];

    let build_cmd = |cmd: &mut process::Command| {
        if clean_env {
            cmd.env_clear();
            // Preserve essential vars for the subprocess to function.
            if let Ok(path) = std::env::var("PATH") {
                cmd.env("PATH", path);
            }
            if let Ok(home) = std::env::var("HOME") {
                cmd.env("HOME", home);
            }
            if let Ok(term) = std::env::var("TERM") {
                cmd.env("TERM", term);
            }
        } else {
            cmd.env_remove("MURK_KEY");
            cmd.env_remove("MURK_KEY_FILE");
        }
        cmd.envs(&secrets);
    };

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = process::Command::new(program);
        cmd.args(args);
        build_cmd(&mut cmd);
        let err = cmd.exec();
        die(&err, 1);
    }

    #[cfg(not(unix))]
    {
        let mut cmd = process::Command::new(program);
        cmd.args(args);
        build_cmd(&mut cmd);
        let status = cmd.status().unwrap_or_else(|e| die(&e, 1));
        process::exit(status.code().unwrap_or(1));
    }
}

fn cmd_env(vault: &str) {
    match murk_cli::write_envrc(vault) {
        Ok(EnvrcStatus::AlreadyPresent) => {
            eprintln!("{} .envrc already contains murk export", "◆".magenta());
        }
        Ok(EnvrcStatus::Appended) => {
            eprintln!("{} appended to .envrc", "◆".magenta());
            eprintln!("  {}", "run: direnv allow".dimmed());
        }
        Ok(EnvrcStatus::Created) => {
            eprintln!("{} created .envrc", "◆".magenta());
            eprintln!("  {}", "run: direnv allow".dimmed());
        }
        Err(e) => die(&e, 1),
    }
}

fn cmd_merge_driver(base_path: &str, ours_path: &str, theirs_path: &str) {
    let base_contents = fs::read_to_string(base_path)
        .unwrap_or_else(|e| die(&format_args!("reading base {base_path}: {e}"), 2));
    let ours_contents = fs::read_to_string(ours_path)
        .unwrap_or_else(|e| die(&format_args!("reading ours {ours_path}: {e}"), 2));
    let theirs_contents = fs::read_to_string(theirs_path)
        .unwrap_or_else(|e| die(&format_args!("reading theirs {theirs_path}: {e}"), 2));

    let output = murk_cli::run_merge_driver(&base_contents, &ours_contents, &theirs_contents)
        .unwrap_or_else(|e| die(&e, 2));

    if !output.meta_regenerated && output.result.conflicts.is_empty() {
        // Check if the merge actually changed secrets or recipients vs ours.
        // If so, the MAC in ours.meta is stale and the vault would fail integrity checks.
        // Skip this check when there are conflicts — the user must resolve and re-merge anyway.
        let ours_vault = vault::parse(
            &fs::read_to_string(ours_path)
                .unwrap_or_else(|e| die(&format_args!("re-reading ours: {e}"), 2)),
        )
        .unwrap_or_else(|e| die(&e, 2));

        let content_changed = output.result.vault.secrets != ours_vault.secrets
            || output.result.vault.recipients != ours_vault.recipients;

        if content_changed {
            eprintln!(
                "{} MURK_KEY not available and merge changed secrets/recipients",
                "error".red().bold()
            );
            eprintln!(
                "  {}",
                "set MURK_KEY and retry the merge to regenerate integrity metadata".dimmed()
            );
            process::exit(1);
        }

        eprintln!(
            "{} MURK_KEY not available — meta not regenerated (content unchanged, safe to proceed)",
            "warn".yellow().bold()
        );
    }

    // Write merged result to ours path (%A).
    vault::write(Path::new(ours_path), &output.result.vault)
        .unwrap_or_else(|e| die(&format_args!("writing merged vault: {e}"), 2));

    if output.result.conflicts.is_empty() {
        eprintln!("{} vault merged cleanly", "◆".magenta());
        process::exit(0);
    } else {
        eprintln!(
            "{} {} conflict{}:",
            "✕".red(),
            output.result.conflicts.len(),
            if output.result.conflicts.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for c in &output.result.conflicts {
            eprintln!("  {} {} — {}", "✕".red(), c.field.bold(), c.reason);
        }
        process::exit(1);
    }
}

fn cmd_setup_merge_driver() {
    let steps = try_or_die(murk_cli::setup_merge_driver());

    for step in &steps {
        match step {
            MergeDriverSetupStep::GitattributesAlreadyExists => {
                eprintln!(
                    "{} .gitattributes already contains merge driver entry",
                    "◆".magenta()
                );
            }
            MergeDriverSetupStep::GitattributesAppended => {
                eprintln!("{} appended to .gitattributes", "◆".magenta());
            }
            MergeDriverSetupStep::GitattributesCreated => {
                eprintln!("{} created .gitattributes", "◆".magenta());
            }
            MergeDriverSetupStep::GitConfigured => {
                eprintln!("{} git merge driver configured", "◆".magenta());
            }
        }
    }

    eprintln!(
        "  {}",
        "commit .gitattributes so all collaborators use the merge driver".dimmed()
    );
}

fn cmd_diff(git_ref: &str, show_values: bool, json: bool, vault_path: &str) {
    let (_vault, current_murk, identity) = load_vault(vault_path);

    // Get the old vault contents from git.
    let output = process::Command::new("git")
        .args(["show", &format!("{git_ref}:{vault_path}")])
        .output()
        .unwrap_or_else(|e| die(&format_args!("running git: {e}"), 1));

    let old_values: HashMap<String, zeroize::Zeroizing<String>> = if output.status.success() {
        let old_contents = String::from_utf8_lossy(&output.stdout);
        match murk_cli::parse_and_decrypt_values(&old_contents, &identity) {
            Ok(values) => {
                if values.is_empty() {
                    // Check if the old vault had secrets — if so, we couldn't decrypt.
                    if let Ok(old_vault) = vault::parse(&old_contents)
                        && !old_vault.secrets.is_empty()
                    {
                        eprintln!(
                            "{} cannot decrypt vault at {git_ref} — you may not have been a recipient",
                            "⚠".yellow()
                        );
                    }
                }
                values
            }
            Err(e) => die(&format_args!("parsing vault at {git_ref}: {e}"), 1),
        }
    } else {
        HashMap::<String, zeroize::Zeroizing<String>>::new()
    };

    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let current_values: HashMap<String, zeroize::Zeroizing<String>> =
        murk_cli::resolve_secrets(&_vault, &current_murk, &pubkey, &[])
            .into_iter()
            .collect();
    let entries = murk_cli::diff_secrets(&old_values, &current_values);

    if json {
        // serde_json copies into its own owned String; zeroization ends at this boundary.
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "kind": format!("{:?}", e.kind).to_lowercase(),
                    "old_value": e.old_value.as_ref().map(|v| v.as_str()),
                    "new_value": e.new_value.as_ref().map(|v| v.as_str()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return;
    }

    if entries.is_empty() {
        eprintln!("{}", "no changes".dimmed());
        return;
    }

    for entry in &entries {
        let old = entry.old_value.as_ref().map_or("", |v| v.as_str());
        let new = entry.new_value.as_ref().map_or("", |v| v.as_str());
        match entry.kind {
            DiffKind::Added => {
                if show_values {
                    println!("{} {} = {}", "+".magenta().bold(), entry.key.bold(), new);
                } else {
                    println!("{} {}", "+".magenta().bold(), entry.key.bold());
                }
            }
            DiffKind::Removed => {
                if show_values {
                    println!("{} {} = {}", "-".red().bold(), entry.key.bold(), old);
                } else {
                    println!("{} {}", "-".red().bold(), entry.key.bold());
                }
            }
            DiffKind::Changed => {
                if show_values {
                    println!(
                        "{} {} {} {} {}",
                        "~".yellow().bold(),
                        entry.key.bold(),
                        old,
                        "→".dimmed(),
                        new
                    );
                } else {
                    println!("{} {}", "~".yellow().bold(), entry.key.bold());
                }
            }
        }
    }
}

fn is_ssh_rsa(key: &str) -> bool {
    key.starts_with("ssh-rsa ")
}

/// Abort if any of the given keys are ssh-rsa, unless the user passed
/// `--allow-ssh-rsa`. Default-closed because ssh-rsa has known weaknesses
/// (see RUSTSEC-2023-0071) and ed25519 is strictly better for this use case.
fn reject_rsa_keys(keys: &[String], allow: bool) {
    let rsa_count = keys.iter().filter(|k| is_ssh_rsa(k)).count();
    if rsa_count == 0 {
        return;
    }
    if allow {
        eprintln!(
            "{} {} ssh-rsa key{} authorized via --allow-ssh-rsa — ed25519 is strongly recommended (see RUSTSEC-2023-0071)",
            "warn".yellow().bold(),
            rsa_count,
            if rsa_count == 1 { "" } else { "s" }
        );
        return;
    }
    die(
        &format_args!(
            "refusing to authorize {rsa_count} ssh-rsa key{s} — ed25519 is strongly recommended (see RUSTSEC-2023-0071). Pass --allow-ssh-rsa to override.",
            s = if rsa_count == 1 { "" } else { "s" }
        ),
        1,
    );
}

fn cmd_authorize(
    pubkey: &str,
    name: Option<&str>,
    force: bool,
    allow_ssh_rsa: bool,
    vault_path: &str,
) {
    let (mut vault, murk, identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    if let Some(username) = pubkey.strip_prefix("github:") {
        // Fetch all SSH keys from GitHub.
        let all_keys = try_or_die(murk_cli::fetch_keys(username).map_err(|e| e.to_string()));

        // TOFU: check fetched keys against pinned fingerprints. Pin checking
        // runs over the full key set (including ssh-rsa) so rotation of an
        // rsa key is still detected even though we refuse to authorize it.
        let pinned = murk_cli::decrypt_meta(&vault, &identity)
            .and_then(|m| {
                let pins = m.github_pins.get(username)?.clone();
                Some(pins)
            })
            .unwrap_or_default();

        if !force && let Err(msg) = murk_cli::github::check_pins(username, &all_keys, &pinned) {
            die(&msg, 1);
        }

        // Filter ssh-rsa out of the authorize set unless explicitly allowed.
        // We don't abort the whole operation the way we do for a single raw
        // pubkey — GitHub users often have a mix of key types and the common
        // case is "use the ed25519 ones, skip the rsa ones with a warning."
        let rsa_skipped = all_keys.iter().filter(|(_, k)| is_ssh_rsa(k)).count();
        let keys: Vec<_> = if allow_ssh_rsa {
            all_keys.iter().collect()
        } else {
            all_keys.iter().filter(|(_, k)| !is_ssh_rsa(k)).collect()
        };
        if rsa_skipped > 0 && !allow_ssh_rsa {
            eprintln!(
                "{} skipped {} ssh-rsa key{} from {}@github — ed25519 is strongly recommended (see RUSTSEC-2023-0071). Pass --allow-ssh-rsa to include them.",
                "warn".yellow().bold(),
                rsa_skipped,
                if rsa_skipped == 1 { "" } else { "s" },
                username
            );
        }
        if keys.is_empty() {
            die(
                &format_args!(
                    "no authorizable keys for {username}@github — all {total} key{s} were ssh-rsa and --allow-ssh-rsa was not set",
                    total = all_keys.len(),
                    s = if all_keys.len() == 1 { "" } else { "s" }
                ),
                1,
            );
        }

        let display_name = format!("{username}@github");
        let mut added = 0;
        let mut type_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for (_, key_string) in &keys {
            // Skip keys already in the vault.
            if vault.recipients.contains(key_string) {
                continue;
            }

            try_or_die(murk_cli::authorize_recipient(
                &mut vault,
                &mut current,
                key_string,
                Some(&display_name),
            ));

            let key_type = murk_cli::github::key_type_label(key_string);
            *type_counts.entry(key_type.to_string()).or_default() += 1;
            added += 1;
        }

        if added == 0 {
            eprintln!(
                "{} all {} SSH keys for {}@github are already authorized",
                "◆".magenta(),
                keys.len(),
                username
            );
            return;
        }

        // Update pinned fingerprints for this GitHub user. Pin the full
        // upstream set, not just the filtered one, so future TOFU comparisons
        // still detect when an ssh-rsa key rotates even though we don't
        // authorize it.
        let new_pins: Vec<String> = all_keys
            .iter()
            .map(|(_, k)| murk_cli::github::fingerprint(k))
            .collect();
        current.github_pins.insert(username.to_string(), new_pins);

        save_vault(vault_path, &mut vault, &original, &current);

        // Build summary like "2 ssh-ed25519, 1 ssh-rsa".
        let mut parts: Vec<String> = type_counts
            .iter()
            .map(|(t, n)| format!("{n} {t}"))
            .collect();
        parts.sort();
        let summary = parts.join(", ");

        eprintln!(
            "{} authorized {} ({} key{})",
            "◆".magenta(),
            display_name.bold(),
            summary,
            if added == 1 { "" } else { "s" }
        );
    } else if let Some(path_hint) = pubkey.strip_prefix("ssh:") {
        // Read SSH public key from a file.
        let path = if path_hint.is_empty() {
            // Default: ~/.ssh/id_ed25519.pub
            let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));
            std::path::PathBuf::from(home).join(".ssh/id_ed25519.pub")
        } else {
            if path_hint.starts_with('~') {
                let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));
                std::path::PathBuf::from(path_hint.replacen('~', &home, 1))
            } else {
                std::path::PathBuf::from(path_hint)
            }
        };

        let contents = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            die(&format_args!("cannot read {}: {e}", path.display()), 1);
        });
        // Take first non-empty line (pub files may have trailing newlines).
        let key_line = contents
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_else(|| die(&format_args!("empty key file: {}", path.display()), 1));
        // Strip the comment field if present (ssh-type base64 comment).
        let key_string = {
            let parts: Vec<&str> = key_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                format!("{} {}", parts[0], parts[1])
            } else {
                key_line.to_string()
            }
        };

        reject_rsa_keys(std::slice::from_ref(&key_string), allow_ssh_rsa);
        try_or_die(murk_cli::authorize_recipient(
            &mut vault,
            &mut current,
            &key_string,
            name,
        ));

        save_vault(vault_path, &mut vault, &original, &current);

        let display = name
            .map(|n| n.to_string())
            .unwrap_or_else(|| path.display().to_string());
        eprintln!("{} authorized {}", "◆".magenta(), display.bold());
    } else {
        // Raw pubkey (age or SSH).
        reject_rsa_keys(&[pubkey.to_string()], allow_ssh_rsa);
        try_or_die(murk_cli::authorize_recipient(
            &mut vault,
            &mut current,
            pubkey,
            name,
        ));

        save_vault(vault_path, &mut vault, &original, &current);

        let display = name.unwrap_or(pubkey);
        eprintln!("{} authorized {}", "◆".magenta(), display.bold());
    }
}

fn cmd_revoke(recipient: &str, vault_path: &str) {
    let (mut vault, murk, _identity, _lock) = load_vault_locked(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let result = try_or_die(murk_cli::revoke_recipient(
        &mut vault,
        &mut current,
        recipient,
    ));

    save_vault(vault_path, &mut vault, &original, &current);

    let display = result.display_name.as_deref().unwrap_or(recipient);
    eprintln!(
        "{} removed {} from recipients",
        "◆".magenta(),
        display.bold(),
    );

    if !result.exposed_keys.is_empty() {
        eprintln!();
        eprintln!(
            "{} {display} had access to {} secret{} — rotate them:",
            "⚠".yellow(),
            result.exposed_keys.len(),
            if result.exposed_keys.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for key in &result.exposed_keys {
            eprintln!("  {} {}", "▸".dimmed(), key.bold());
        }
        eprintln!();
        eprintln!(
            "  {}",
            "run `murk rotate --all` to rotate each secret".dimmed()
        );
    }
    eprintln!();
    eprintln!(
        "  {}",
        "this recipient can still decrypt previous versions from git history".dimmed()
    );
}

/// Truncate a pubkey for display: first 8 chars + "…" + last 4 chars.
fn cmd_recipients(json: bool, vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let secret_key = murk_cli::resolve_key_for_vault(vault_path)
        .ok()
        .map(|s| s.expose_secret().to_string());
    let entries = murk_cli::list_recipients(&vault, secret_key.as_deref());

    if json {
        let list: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "pubkey": e.pubkey,
                    "name": e.display_name,
                    "is_self": e.is_self,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return;
    }

    let has_names = entries.iter().any(|e| e.display_name.is_some());

    if !has_names {
        // Locked: plain pubkeys to stdout for piping.
        for entry in &entries {
            println!("{}", entry.pubkey);
        }
        return;
    }

    // Group entries by display name so multi-key recipients (e.g. github
    // users with several SSH keys) are shown as a single consolidated line.
    let mut groups: Vec<(Option<&str>, Vec<&murk_cli::RecipientEntry>)> = Vec::new();
    for entry in &entries {
        let name = entry.display_name.as_deref();
        if let Some(group) = groups
            .iter_mut()
            .find(|(n, _)| *n == name && name.is_some())
        {
            group.1.push(entry);
        } else {
            groups.push((name, vec![entry]));
        }
    }

    // Compute name column width for alignment.
    let name_width = groups
        .iter()
        .map(|(name, _)| name.map_or(0, |n| n.len()))
        .max()
        .unwrap_or(0);

    for (name, group) in &groups {
        let is_self = group.iter().any(|e| e.is_self);
        let marker = if is_self { "◆" } else { " " };
        let label = name.unwrap_or("");
        let label_padded = format!("{label:<name_width$}");

        let key_type = murk_cli::key_type_label(&group[0].pubkey);
        let key_info = if group.len() == 1 {
            murk_cli::truncate_pubkey(&group[0].pubkey)
        } else {
            format!("({} keys)", group.len())
        };

        if is_self {
            println!(
                "{} {}  {}",
                marker.magenta(),
                label_padded.magenta().bold(),
                format!("{key_info}  {key_type}").dimmed()
            );
        } else {
            println!(
                "{}",
                format!("  {label_padded}  {key_info}  {key_type}").dimmed()
            );
        }
    }
}

fn cmd_restore() {
    let phrase = if io::stdin().is_terminal() {
        eprint!("Enter 24-word recovery phrase: ");
        io::stderr().flush().ok();
        let password = rpassword::read_password().unwrap_or_else(|e| {
            eprintln!();
            die(&format_args!("reading input: {e}"), 1);
        });
        eprintln!();
        password
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).unwrap_or(0);
        line.trim().to_string()
    };

    if phrase.is_empty() {
        die(&"recovery phrase is required", 1);
    }

    println!("{}", try_or_die(recovery::recover(&phrase)).as_str());
}

fn cmd_recover() {
    let secret_key = resolve_key();

    // SSH keys and plugin identities don't have BIP39 recovery phrases.
    let identity =
        murk_cli::crypto::parse_identity(secret_key.expose_secret()).unwrap_or_else(|e| die(&e, 1));
    match identity {
        MurkIdentity::Ssh(_) => die(
            &"recovery phrases are for age keys only. SSH keys are managed by your SSH agent — back up ~/.ssh instead",
            1,
        ),
        MurkIdentity::Plugin { .. } => die(
            &"plugin identities (YubiKey, Secure Enclave, FIDO2) do not have recovery phrases. BIP39 words encode the raw 32 key bytes, but hardware-backed keys never leave the device — there are no bytes to encode. Recovery means enrolling a backup hardware device at setup and adding its pubkey as a recipient with `murk authorize`",
            1,
        ),
        MurkIdentity::Age(_) => {}
    }

    println!(
        "{}",
        try_or_die(recovery::phrase_from_key(secret_key.expose_secret())).as_str()
    );
}

fn cmd_info(tags: &[String], json: bool, vault_path: &str) {
    // Route through the hardened loader so info rejects symlinked vaults and
    // enforces the version check — same as every other read path.
    let (_vault, raw_bytes) = try_or_die(murk_cli::vault::read_with_raw(Path::new(vault_path)));
    let key_with_source = murk_cli::resolve_key_with_source(vault_path).ok();
    let secret_key = key_with_source
        .as_ref()
        .map(|(k, _)| k.expose_secret().to_string());
    let key_source = key_with_source.as_ref().map(|(_, s)| s.clone());
    let info = try_or_die(murk_cli::vault_info(
        &raw_bytes,
        tags,
        secret_key.as_deref(),
    ));

    if json {
        let entries: Vec<serde_json::Value> = info
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "description": e.description,
                    "example": e.example,
                    "tags": e.tags,
                    "scoped_recipients": e.scoped_recipients,
                })
            })
            .collect();
        let mut out = serde_json::json!({
            "vault_name": info.vault_name,
            "codename": info.codename,
            "repo": info.repo,
            "created": info.created,
            "recipient_count": info.recipient_count,
            "entries": entries,
        });
        if !info.recipient_names.is_empty() {
            out["recipient_names"] = serde_json::json!(info.recipient_names);
        }
        if let Some(name) = &info.self_name {
            out["self_name"] = serde_json::json!(name);
        }
        if let Some(pk) = &info.self_pubkey {
            out["self_pubkey"] = serde_json::json!(pk);
        }
        if let Some(src) = &key_source {
            out["key_source"] = serde_json::json!(src.describe());
        }
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    // Nameplate: ░▓ vault_name
    println!(
        "{} {}",
        "▓░".dimmed(),
        info.vault_name.truecolor(135, 95, 255).bold()
    );
    println!("   {}    {}", "codename".dimmed(), info.codename);
    if !info.repo.is_empty() {
        println!("   {}        {}", "repo".dimmed(), info.repo);
    }
    println!("   {}     {}", "created".dimmed(), info.created);
    println!("   {}  {}", "recipients".dimmed(), info.recipient_count);

    if !info.recipient_names.is_empty() {
        for name in &info.recipient_names {
            let marker = if info.self_name.as_ref() == Some(name) {
                "*"
            } else {
                " "
            };
            println!("   {} {} {}", " ".repeat(9), marker, name.green().bold());
        }
    }

    if let Some(src) = &key_source {
        println!("   {}  {}", "key".dimmed(), src.describe().dimmed());
    }

    if info.entries.is_empty() {
        println!();
        println!("   {}", "no keys in vault".dimmed());
        return;
    }

    println!();

    // Compute column widths for aligned output.
    let key_width = info.entries.iter().map(|e| e.key.len()).max().unwrap_or(0);
    let desc_width = info
        .entries
        .iter()
        .map(|e| e.description.len())
        .max()
        .unwrap_or(0);

    let example_width = info
        .entries
        .iter()
        .map(|e| {
            e.example
                .as_ref()
                .map_or(0, |ex| format!("(e.g. {ex})").len())
        })
        .max()
        .unwrap_or(0);

    let has_meta = secret_key.is_some();

    // Tags are always public — show them regardless of key.
    let any_tags = info.entries.iter().any(|e| !e.tags.is_empty());
    let tag_width = if any_tags {
        info.entries
            .iter()
            .map(|e| {
                if e.tags.is_empty() {
                    0
                } else {
                    format!("[{}]", e.tags.join(", ")).len()
                }
            })
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    for entry in &info.entries {
        let example_str = entry
            .example
            .as_ref()
            .map(|ex| format!("(e.g. {ex})"))
            .unwrap_or_default();

        // Pad plain strings for alignment, then apply colors.
        let key_padded = format!("{:<key_width$}", entry.key);
        let desc_padded = format!("{:<desc_width$}", entry.description);
        let ex_padded = format!("{example_str:<example_width$}");

        let tag_str = if entry.tags.is_empty() {
            String::new()
        } else {
            format!("[{}]", entry.tags.join(", "))
        };
        let tag_padded = if any_tags {
            format!("  {tag_str:<tag_width$}")
        } else {
            String::new()
        };

        // Scoped recipients only shown when meta is available.
        let scoped_str = if has_meta && !entry.scoped_recipients.is_empty() {
            format!(
                "  {}",
                format!("✦ {}", entry.scoped_recipients.join(", ")).dimmed()
            )
        } else {
            String::new()
        };

        println!(
            "   {}  {}  {}{}{}",
            key_padded.magenta().dimmed().bold(),
            desc_padded,
            ex_padded.dimmed(),
            tag_padded.yellow(),
            scoped_str
        );
    }
}

fn cmd_scan(paths: &[String], vault_path: &str) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, &[]);

    if secrets.is_empty() {
        eprintln!("{} no secrets to scan for", "ok".green().bold());
        return;
    }

    let scan_paths: Vec<&str> = if paths.is_empty() {
        vec!["."]
    } else {
        paths.iter().map(String::as_str).collect()
    };

    let findings = murk_cli::scan::scan_for_leaks(&scan_paths, &secrets, 8);

    for f in &findings {
        eprintln!(
            "{} {} leaked in {}",
            "warn".yellow().bold(),
            f.key.bold(),
            f.path
        );
    }

    if findings.is_empty() {
        eprintln!("{} no leaked secrets found", "ok".green().bold());
    } else {
        eprintln!(
            "{} {} leaked secret{} found",
            "error".red().bold(),
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        );
        process::exit(1);
    }
}

fn cmd_skeleton(output: Option<&str>, vault_path: &str) {
    let vault = murk_cli::vault::read(Path::new(vault_path)).unwrap_or_else(|e| die(&e, 1));

    let skeleton = murk_cli::types::Vault {
        version: vault.version,
        created: vault.created,
        vault_name: vault.vault_name,
        repo: vault.repo,
        recipients: Vec::new(),
        schema: vault.schema,
        secrets: BTreeMap::new(),
        meta: String::new(),
    };

    let json = serde_json::to_string_pretty(&skeleton).unwrap();
    match output {
        Some(path) => {
            fs::write(path, format!("{json}\n")).unwrap_or_else(|e| die(&e, 1));
            eprintln!("{} wrote skeleton to {}", "ok".green().bold(), path.bold());
        }
        None => println!("{json}"),
    }
}

/// A single finding produced by a check command (`verify`, `doctor`, ...).
/// Each check either passes silently or pushes a `Finding` describing what's
/// wrong and how to fix it. See `docs/cli-style.md` for the output contract.
struct Finding {
    /// Short category tag for the failing-item line (e.g. "mac", "recipients").
    category: &'static str,
    /// One-line human-readable message.
    message: String,
    /// Optional fix hint, printed dimmed under the parent line.
    fix: Option<String>,
}

/// Emit a list of findings to stderr per the CLI style guide and exit(1) if
/// any exist. `header` is a single verb-phrase like "vault" or "repo" — the
/// reporter prints "warn N issue{s} in {header}" above the list.
///
/// Returns `()` on no findings. Exits the process on any finding — callers
/// should finish any "ok" lines before calling this.
fn report_findings(findings: &[Finding], header: &str) {
    if findings.is_empty() {
        return;
    }

    eprintln!();
    eprintln!(
        "{} {} issue{} in {}",
        "warn".yellow().bold(),
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        header
    );
    for f in findings {
        eprintln!("  {} {} — {}", "✕".red(), f.category.bold(), f.message);
        if let Some(fix) = &f.fix {
            eprintln!("      {}", fix.dimmed());
        }
    }
    std::process::exit(1);
}

fn cmd_verify(vault_path: &str) {
    // Load the vault first — MAC/integrity failure short-circuits the rest
    // of the checks with the hard error from the loader.
    let (vault, murk, _identity) = load_vault(vault_path);

    let mut findings: Vec<Finding> = Vec::new();

    if murk.legacy_mac {
        findings.push(Finding {
            category: "mac",
            message: "vault uses legacy unkeyed MAC".into(),
            fix: Some("run any write command (e.g. `murk describe`) to upgrade to BLAKE3".into()),
        });
    }

    // The vault file itself is public-by-design, so we don't care about read
    // perms. We do care about *write* perms: a group-writable vault is an
    // easy way for a local attacker to tamper with ciphertext.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(vault_path) {
            let mode = meta.mode() & 0o777;
            if mode & 0o022 != 0 {
                findings.push(Finding {
                    category: "perms",
                    message: format!("vault file is group/world writable (mode {mode:o})"),
                    fix: Some(format!("chmod 644 {vault_path}")),
                });
            }
        }
    }

    // After the .env kill, every valid key source is safe. Re-resolve
    // explicitly so verify can surface where the key came from — transparency
    // about key provenance is the point.
    match murk_cli::resolve_key_with_source(vault_path) {
        Ok((_, source)) => {
            eprintln!(
                "{} key  {}",
                "ok".green().bold(),
                source.describe().dimmed()
            );
        }
        Err(msg) => {
            findings.push(Finding {
                category: "key",
                message: format!("cannot resolve a key: {msg}"),
                fix: None,
            });
        }
    }

    let rsa_recipients: Vec<&String> = vault
        .recipients
        .iter()
        .filter(|r| r.starts_with("ssh-rsa "))
        .collect();
    if !rsa_recipients.is_empty() {
        findings.push(Finding {
            category: "recipients",
            message: format!(
                "{} ssh-rsa recipient{} present",
                rsa_recipients.len(),
                if rsa_recipients.len() == 1 { "" } else { "s" }
            ),
            fix: Some("rotate to ed25519 keys and `murk revoke` the old ssh-rsa recipients".into()),
        });
    }

    if findings.is_empty() {
        eprintln!("{} vault integrity verified", "ok".green().bold());
        eprintln!("{} no safety issues found", "ok".green().bold());
        return;
    }

    eprintln!("{} vault integrity verified", "ok".green().bold());
    report_findings(&findings, "vault");
}

fn cmd_doctor() {
    // doctor is repo-level hygiene — it doesn't need a vault to run. The
    // checks it performs are all about the working tree: env files, key
    // files sitting next to the vault, obvious commit-would-be-bad state.
    let mut findings: Vec<Finding> = Vec::new();

    let cwd = std::env::current_dir().unwrap_or_else(|e| die(&e, 1));

    // ── .env contains an inline MURK_KEY ──
    // After the .env kill this is dead config AND a historical footgun.
    // Previously-committed .env files with inline keys are still out there.
    let env_path = cwd.join(".env");
    if env_path.exists()
        && let Ok(contents) = std::fs::read_to_string(&env_path)
    {
        let has_inline = contents.lines().any(|l| {
            let t = l.trim_start();
            (t.starts_with("MURK_KEY=") || t.starts_with("export MURK_KEY="))
                && !t.starts_with("MURK_KEY_FILE=")
                && !t.starts_with("export MURK_KEY_FILE=")
        });
        if has_inline {
            findings.push(Finding {
                category: "dotenv",
                message: "inline MURK_KEY in .env (dead config, risk of commit)".into(),
                fix: Some("remove the MURK_KEY= line and re-run `murk init`".into()),
            });
        }
    }

    // ── .env is not in .gitignore ──
    // Soft guardrail: an untracked .env is fine for local dev, but a .env
    // that isn't excluded from git has probably slipped into a commit
    // somewhere. Ask git directly via `check-ignore` so we respect nested
    // .gitignore files, global excludes, and negated rules.
    if env_path.exists()
        && cwd.join(".git").exists()
        && let Ok(output) = std::process::Command::new("git")
            .args(["check-ignore", "--quiet", ".env"])
            .current_dir(&cwd)
            .status()
        && !output.success()
    {
        findings.push(Finding {
            category: "gitignore",
            message: ".env is not excluded from git".into(),
            fix: Some("add `.env` to .gitignore so it cannot be committed".into()),
        });
    }

    // ── Key file is inside the working tree ──
    // `murk init` puts the key file under ~/.config/murk/keys by default,
    // which is outside any repo. But MURK_KEY_FILE can be set to anywhere,
    // and a user who put it next to the vault has just opted in to
    // committing their private key. Fail loudly.
    if let Ok((_, source)) = murk_cli::resolve_key_with_source(".murk")
        && let murk_cli::KeySource::EnvFile(path) | murk_cli::KeySource::Auto(path) = source
        && let Ok(abs) = std::fs::canonicalize(&path)
        && let Ok(repo) = std::fs::canonicalize(&cwd)
        && abs.starts_with(&repo)
    {
        findings.push(Finding {
            category: "keyfile",
            message: format!("key file {} is inside the working tree", abs.display()),
            fix: Some(
                "move it out of the repo (e.g. ~/.config/murk/keys/) and update MURK_KEY_FILE"
                    .into(),
            ),
        });
    }

    // ── ssh-rsa in ~/.ssh ──
    // Not a repo check strictly, but if a user is going to reach for an SSH
    // key next, we want them to notice they have an rsa one ready to go.
    // Skip for now — this is an environment check that doesn't really fit
    // the "repo hygiene" frame.

    if findings.is_empty() {
        eprintln!("{} repo hygiene looks clean", "ok".green().bold());
        return;
    }

    report_findings(&findings, "repo");
}

fn cmd_completion_generate(shell: clap_complete::Shell) {
    clap_complete::generate(shell, &mut Cli::command(), "murk", &mut io::stdout());
}

fn cmd_completion_install(shell: clap_complete::Shell) {
    use clap_complete::Shell;

    let home = std::env::var("HOME").unwrap_or_else(|_| die(&"HOME not set", 1));

    let (dir, filename) = match shell {
        Shell::Zsh => {
            let dir = format!("{home}/.zfunc");
            (dir, "_murk".to_string())
        }
        Shell::Bash => {
            let dir = format!("{home}/.local/share/bash-completion/completions");
            (dir, "murk".to_string())
        }
        Shell::Fish => {
            let dir = format!("{home}/.config/fish/completions");
            (dir, "murk.fish".to_string())
        }
        Shell::Elvish => {
            let dir = format!("{home}/.config/elvish/lib");
            (dir, "murk.elv".to_string())
        }
        Shell::PowerShell => {
            let dir = format!("{home}/.config/powershell");
            (dir, "_murk.ps1".to_string())
        }
        _ => die(&format!("unsupported shell: {shell}"), 1),
    };

    fs::create_dir_all(&dir).unwrap_or_else(|e| die(&format!("failed to create {dir}: {e}"), 1));

    let path = format!("{dir}/{filename}");
    let mut file =
        fs::File::create(&path).unwrap_or_else(|e| die(&format!("failed to write {path}: {e}"), 1));
    clap_complete::generate(shell, &mut Cli::command(), "murk", &mut file);

    eprintln!("{} wrote {}", "ok".green().bold(), path);

    match shell {
        Shell::Zsh => {
            eprintln!(
                "\n{} add to your {}:",
                "hint".cyan().bold(),
                "~/.zshrc".bold()
            );
            eprintln!("  fpath+=~/.zfunc");
            eprintln!("  autoload -Uz compinit && compinit");
        }
        Shell::Bash => {
            eprintln!(
                "\n{} add to your {}:",
                "hint".cyan().bold(),
                "~/.bashrc".bold()
            );
            eprintln!(
                "  [[ -r ~/.local/share/bash-completion/completions/murk ]] && \
                 source ~/.local/share/bash-completion/completions/murk"
            );
        }
        Shell::Fish => {
            eprintln!(
                "\n{} completions are loaded automatically by fish",
                "hint".cyan().bold()
            );
        }
        _ => {}
    }
}

fn main() {
    murk_cli::hardening::disable_core_dumps();
    let cli = Cli::parse();

    match cli.command {
        Command::Init { vault } => cmd_init(&vault),
        Command::Recover => cmd_recover(),
        Command::Restore => cmd_restore(),
        Command::Import { file, force, vault } => {
            cmd_import(&file, force, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Add {
            key,
            desc,
            scoped,
            tag,
            vault,
        } => {
            let vault = murk_cli::resolve_vault_path(&vault);
            let resolved = resolve_value(&key);
            cmd_add(&key, &resolved, desc.as_deref(), scoped, &tag, &vault);
        }
        Command::Generate {
            key,
            length,
            hex,
            desc,
            tag,
            vault,
        } => cmd_generate(
            &key,
            length,
            hex,
            desc.as_deref(),
            &tag,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Rotate {
            key,
            all,
            generate,
            length,
            hex,
            vault,
        } => cmd_rotate(
            key.as_deref(),
            all,
            generate,
            length,
            hex,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Rm { key, vault } => cmd_rm(&key, &murk_cli::resolve_vault_path(&vault)),
        Command::Get { key, vault } => cmd_get(&key, &murk_cli::resolve_vault_path(&vault)),
        Command::Ls { tag, json, vault } => {
            cmd_ls(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Describe {
            key,
            description,
            example,
            tag,
            vault,
        } => cmd_describe(
            &key,
            &description,
            example.as_deref(),
            &tag,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Info { tag, json, vault } => {
            cmd_info(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Export { tag, json, vault } => {
            cmd_export(&tag, json, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Edit { key, scoped, vault } => {
            cmd_edit(
                key.as_deref(),
                scoped,
                &murk_cli::resolve_vault_path(&vault),
            );
        }
        Command::Exec {
            only,
            tag,
            clean_env,
            vault,
            command,
        } => cmd_exec(
            &command,
            &only,
            &tag,
            clean_env,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Authorize {
            pubkey,
            name,
            force,
            allow_ssh_rsa,
            vault,
        } => cmd_authorize(
            &pubkey,
            name.as_deref(),
            force,
            allow_ssh_rsa,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Revoke { recipient, vault } => {
            cmd_revoke(&recipient, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Circle {
            sub: None,
            json,
            vault,
        } => cmd_recipients(json, &murk_cli::resolve_vault_path(&vault)),
        Command::Circle {
            sub:
                Some(CircleCommand::Authorize {
                    pubkey,
                    name,
                    force,
                    allow_ssh_rsa,
                    vault,
                }),
            ..
        } => cmd_authorize(
            &pubkey,
            name.as_deref(),
            force,
            allow_ssh_rsa,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::Circle {
            sub: Some(CircleCommand::Revoke { recipient, vault }),
            ..
        } => cmd_revoke(&recipient, &murk_cli::resolve_vault_path(&vault)),
        Command::Env { vault } => cmd_env(&vault),
        Command::Diff {
            git_ref,
            show_values,
            json,
            vault,
        } => cmd_diff(
            &git_ref,
            show_values,
            json,
            &murk_cli::resolve_vault_path(&vault),
        ),
        Command::MergeDriver { base, ours, theirs } => cmd_merge_driver(&base, &ours, &theirs),
        Command::SetupMergeDriver => cmd_setup_merge_driver(),
        Command::Verify { vault } => cmd_verify(&murk_cli::resolve_vault_path(&vault)),
        Command::Doctor => cmd_doctor(),
        Command::Skeleton { output, vault } => {
            cmd_skeleton(output.as_deref(), &murk_cli::resolve_vault_path(&vault));
        }
        Command::Scan { paths, vault } => {
            cmd_scan(&paths, &murk_cli::resolve_vault_path(&vault));
        }
        Command::Completion { action } => match action {
            CompletionAction::Generate { shell } => cmd_completion_generate(shell),
            CompletionAction::Install { shell } => cmd_completion_install(shell),
        },
    }
}
