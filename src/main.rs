use murk_cli::{
    DiffKind, EnvrcStatus, MergeDriverSetupStep, MurkIdentity, is_valid_key_name, recovery, types,
    vault,
};

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::process;

use age::secrecy::ExposeSecret;
use clap::{Parser, Subcommand};
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
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export all secrets as shell export statements
    Export {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Run a command with secrets injected as environment variables
    #[command(trailing_var_arg = true)]
    Exec {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
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
        /// Public key (age1.../ssh-ed25519.../ssh-rsa...) or github:username
        pubkey: String,
        /// Display name for this recipient
        #[arg(long)]
        name: Option<String>,
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
}

#[derive(Subcommand)]
enum CircleCommand {
    /// Add a recipient to the vault
    Authorize {
        /// Public key (age1.../ssh-ed25519.../ssh-rsa...) or github:username
        pubkey: String,
        /// Display name for this recipient
        #[arg(long)]
        name: Option<String>,
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
/// Returns (secret_key, pubkey).
fn generate_and_write_key(vault_name: &str) -> (String, String) {
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
    eprintln!("  {}", phrase.bold());
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
    try_or_die(murk_cli::load_vault(vault))
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
        // Piped input: `echo "secret" | murk add KEY`
        let mut buf = String::new();
        stdin
            .lock()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| die(&format_args!("reading stdin: {e}"), 1));
        let trimmed = buf.trim_end_matches('\n').to_string();
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

    let (mut vault, murk, identity) = load_vault(vault_path);
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

fn cmd_import(file: &str, vault_path: &str) {
    let contents = fs::read_to_string(file)
        .unwrap_or_else(|e| die(&format_args!("cannot read {file}: {e}"), 1));

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

    // Filter out keys that aren't valid shell identifiers.
    let mut pairs = Vec::new();
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

    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();
    let mut current = murk;

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

    let bytes: Vec<u8> = (0..length).map(|_| rand::random()).collect();

    let value = if hex {
        bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    };

    let (mut vault, murk, identity) = load_vault(vault_path);
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

    let (mut vault, murk, identity) = load_vault(vault_path);
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
            let bytes: Vec<u8> = (0..length).map(|_| rand::random()).collect();
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
    let (mut vault, murk, _identity) = load_vault(vault_path);
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

fn cmd_ls(tags: &[String], vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    for key in murk_cli::list_keys(&vault, tags) {
        println!("{key}");
    }
}

fn cmd_describe(
    key: &str,
    description: &str,
    example: Option<&str>,
    tags: &[String],
    vault_path: &str,
) {
    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();

    murk_cli::describe_key(&mut vault, key, description, example, tags);

    // Describe only changes schema (plaintext) — but we still need to write the vault.
    // Re-save with no value changes so ciphertext is preserved.
    save_vault(vault_path, &mut vault, &original, &murk);
}

fn cmd_export(tags: &[String], vault_path: &str) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));

    let exports = murk_cli::export_secrets(&vault, &murk, &pubkey, tags);
    for (k, escaped) in &exports {
        if !is_valid_key_name(k) {
            eprintln!("{} skipping unsafe key name: {}", "⚠".yellow(), k.bold());
            continue;
        }
        println!("export {k}='{escaped}'");
    }
}

fn cmd_exec(command: &[String], tags: &[String], vault_path: &str) {
    let (vault, murk, identity) = load_vault(vault_path);
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let secrets = murk_cli::resolve_secrets(&vault, &murk, &pubkey, tags);

    let program = &command[0];
    let args = &command[1..];

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = process::Command::new(program)
            .args(args)
            .envs(&secrets)
            .exec();
        die(&err, 1);
    }

    #[cfg(not(unix))]
    {
        let status = process::Command::new(program)
            .args(args)
            .envs(&secrets)
            .status()
            .unwrap_or_else(|e| die(&e, 1));
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

    if !output.meta_regenerated {
        eprintln!(
            "{} MURK_KEY not available — meta not regenerated. Run any murk write command to fix",
            "⚠".yellow()
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

fn cmd_diff(git_ref: &str, show_values: bool, vault_path: &str) {
    let (_vault, current_murk, identity) = load_vault(vault_path);

    // Get the old vault contents from git.
    let output = process::Command::new("git")
        .args(["show", &format!("{git_ref}:{vault_path}")])
        .output()
        .unwrap_or_else(|e| die(&format_args!("running git: {e}"), 1));

    let old_values: HashMap<String, String> = if output.status.success() {
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
        HashMap::new()
    };

    let entries = murk_cli::diff_secrets(&old_values, &current_murk.values);

    if entries.is_empty() {
        eprintln!("{}", "no changes".dimmed());
        return;
    }

    for entry in &entries {
        match entry.kind {
            DiffKind::Added => {
                if show_values {
                    println!(
                        "{} {} = {}",
                        "+".magenta().bold(),
                        entry.key.bold(),
                        entry.new_value.as_deref().unwrap_or("")
                    );
                } else {
                    println!("{} {}", "+".magenta().bold(), entry.key.bold());
                }
            }
            DiffKind::Removed => {
                if show_values {
                    println!(
                        "{} {} = {}",
                        "-".red().bold(),
                        entry.key.bold(),
                        entry.old_value.as_deref().unwrap_or("")
                    );
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
                        entry.old_value.as_deref().unwrap_or(""),
                        "→".dimmed(),
                        entry.new_value.as_deref().unwrap_or("")
                    );
                } else {
                    println!("{} {}", "~".yellow().bold(), entry.key.bold());
                }
            }
        }
    }
}

fn cmd_authorize(pubkey: &str, name: Option<&str>, vault_path: &str) {
    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();
    let mut current = murk;

    if let Some(username) = pubkey.strip_prefix("github:") {
        // Fetch all SSH keys from GitHub.
        let keys = try_or_die(murk_cli::fetch_keys(username).map_err(|e| e.to_string()));

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
    } else {
        // Raw pubkey (age or SSH).
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
    let (mut vault, murk, _identity) = load_vault(vault_path);
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
fn cmd_recipients(vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let secret_key = env::var("MURK_KEY").ok().filter(|k| !k.is_empty());
    let entries = murk_cli::list_recipients(&vault, secret_key.as_deref());
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

    println!("{}", try_or_die(recovery::recover(&phrase)));
}

fn cmd_recover() {
    let secret_key = resolve_key();

    // SSH keys don't have BIP39 recovery phrases — only age keys do.
    let identity =
        murk_cli::crypto::parse_identity(secret_key.expose_secret()).unwrap_or_else(|e| die(&e, 1));
    if matches!(identity, MurkIdentity::Ssh(_)) {
        die(
            &"recovery phrases are for age keys only. SSH keys are managed by your SSH agent — back up ~/.ssh instead",
            1,
        );
    }

    println!(
        "{}",
        try_or_die(recovery::phrase_from_key(secret_key.expose_secret()))
    );
}

fn cmd_info(tags: &[String], vault_path: &str) {
    let raw_bytes = fs::read(vault_path).unwrap_or_else(|e| die(&e, 1));
    let secret_key = env::var("MURK_KEY").ok().filter(|k| !k.is_empty());
    let info = try_or_die(murk_cli::vault_info(
        &raw_bytes,
        tags,
        secret_key.as_deref(),
    ));

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

    // Tag and scoped columns only when unlocked.
    let tag_width = if has_meta {
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

        if has_meta {
            let tag_str = if entry.tags.is_empty() {
                String::new()
            } else {
                format!("[{}]", entry.tags.join(", "))
            };
            let tag_padded = format!("{tag_str:<tag_width$}");

            let scoped_str = if entry.scoped_recipients.is_empty() {
                String::new()
            } else {
                format!("✦ {}", entry.scoped_recipients.join(", "))
            };

            println!(
                "   {}  {}  {}  {}  {}",
                key_padded.magenta().dimmed().bold(),
                desc_padded,
                ex_padded.dimmed(),
                tag_padded.yellow(),
                scoped_str.dimmed()
            );
        } else {
            println!(
                "   {}  {}  {}",
                key_padded.magenta().dimmed().bold(),
                desc_padded,
                ex_padded.dimmed()
            );
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { vault } => cmd_init(&vault),
        Command::Recover => cmd_recover(),
        Command::Restore => cmd_restore(),
        Command::Import { file, vault } => cmd_import(&file, &vault),
        Command::Add {
            key,
            desc,
            scoped,
            tag,
            vault,
        } => {
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
        } => cmd_generate(&key, length, hex, desc.as_deref(), &tag, &vault),
        Command::Rotate {
            key,
            all,
            generate,
            length,
            hex,
            vault,
        } => cmd_rotate(key.as_deref(), all, generate, length, hex, &vault),
        Command::Rm { key, vault } => cmd_rm(&key, &vault),
        Command::Get { key, vault } => cmd_get(&key, &vault),
        Command::Ls { tag, vault } => cmd_ls(&tag, &vault),
        Command::Describe {
            key,
            description,
            example,
            tag,
            vault,
        } => cmd_describe(&key, &description, example.as_deref(), &tag, &vault),
        Command::Info { tag, vault } => cmd_info(&tag, &vault),
        Command::Export { tag, vault } => cmd_export(&tag, &vault),
        Command::Exec {
            tag,
            vault,
            command,
        } => cmd_exec(&command, &tag, &vault),
        Command::Authorize {
            pubkey,
            name,
            vault,
        } => cmd_authorize(&pubkey, name.as_deref(), &vault),
        Command::Revoke { recipient, vault } => cmd_revoke(&recipient, &vault),
        Command::Circle { sub: None, vault } => cmd_recipients(&vault),
        Command::Circle {
            sub:
                Some(CircleCommand::Authorize {
                    pubkey,
                    name,
                    vault,
                }),
            ..
        } => cmd_authorize(&pubkey, name.as_deref(), &vault),
        Command::Circle {
            sub: Some(CircleCommand::Revoke { recipient, vault }),
            ..
        } => cmd_revoke(&recipient, &vault),
        Command::Env { vault } => cmd_env(&vault),
        Command::Diff {
            git_ref,
            show_values,
            vault,
        } => cmd_diff(&git_ref, show_values, &vault),
        Command::MergeDriver { base, ours, theirs } => cmd_merge_driver(&base, &ours, &theirs),
        Command::SetupMergeDriver => cmd_setup_merge_driver(),
    }
}
