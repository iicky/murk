use murk_cli::{DiffKind, EnvrcStatus, MergeDriverSetupStep, MurkIdentity, recovery, types, vault};

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
    eprintln!("{} {msg}", "error:".red().bold());
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
    Restore {
        /// 24-word recovery phrase (prompted if not given)
        phrase: Option<String>,
    },

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
    Authorize {
        /// Public key (age1.../ssh-ed25519.../ssh-rsa...) or github:username
        pubkey: String,
        /// Optional display name (stored in encrypted meta)
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

    /// List all recipients
    Recipients {
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

/// Generate a BIP39 keypair, write to .env, print recovery phrase.
/// Returns (secret_key, pubkey).
fn generate_and_write_key() -> (String, String) {
    eprintln!("{}", "Generating keypair...".dimmed());
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

    // Write MURK_KEY to .env (replaces existing, sets chmod 600).
    eprintln!("{}", "Writing MURK_KEY to .env...".dimmed());
    try_or_die(murk_cli::write_key_to_dotenv(&secret_key));

    // Print recovery phrase.
    eprintln!();
    eprintln!(
        "{}",
        "RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:"
            .yellow()
            .bold()
    );
    eprintln!("{}", phrase.bold());
    eprintln!();
    eprintln!(
        "{} {}",
        "MURK_KEY saved to .env —".yellow().bold(),
        "do not commit this file.".yellow().bold()
    );

    (secret_key, pubkey)
}

fn cmd_init(vault_name: &str) {
    let vault_path = Path::new(vault_name);

    // If vault already exists, handle onboarding flow.
    if vault_path.exists() {
        let vault = try_or_die(vault::read(vault_path));

        eprintln!("{vault_name} already exists");

        // Try to find an existing key: env var first, then .env file.
        let dk = try_or_die(murk_cli::discover_existing_key());
        let (secret_key, pubkey) = match dk {
            Some(dk) => (Some(dk.secret_key), dk.pubkey),
            None => {
                let (_secret_key, pubkey) = generate_and_write_key();
                eprintln!();
                (None, pubkey)
            }
        };

        let status = match secret_key.as_deref() {
            Some(sk) => try_or_die(murk_cli::check_init_status(&vault, sk)),
            None => {
                // No secret key — fall back to simple recipient check.
                if vault.recipients.contains(&pubkey) {
                    eprintln!("{}  {}", "authorized".green(), pubkey.dimmed(),);
                } else {
                    eprintln!(
                        "{}",
                        "not authorized \u{2014} share your public key to get added:".yellow()
                    );
                    eprintln!("{}", pubkey.bold());
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
                "{}  {}{}",
                "authorized".green(),
                status.pubkey.dimmed(),
                name_display
            );
        } else {
            eprintln!(
                "{}",
                "not authorized \u{2014} share your public key to get added:".yellow()
            );
            eprintln!("{}", status.pubkey.bold());
        }
        return;
    }

    // --- New vault flow ---

    // Prompt for display name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        die(&"name is required", 1);
    }

    let (_secret_key, pubkey) = generate_and_write_key();

    let v = try_or_die(murk_cli::create_vault(vault_name, &pubkey, &name));
    try_or_die(vault::write(vault_path, &v));

    eprintln!();
    eprintln!(
        "{} Added {} as recipient.",
        "Vault initialized.".green(),
        name.bold()
    );
    eprintln!("Next: {}", "murk add KEY".bold());
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

    eprintln!("{} {}", "added".green(), key.bold());

    if needs_desc_hint {
        eprintln!(
            "{} no description set. Run: {}",
            "hint:".dimmed(),
            format!("murk describe {key} \"your description\"").bold()
        );
    }

    save_vault(vault_path, &mut vault, &original, &current);
}

fn cmd_import(file: &str, vault_path: &str) {
    let contents = fs::read_to_string(file)
        .unwrap_or_else(|e| die(&format_args!("cannot read {file}: {e}"), 1));

    let pairs = murk_cli::parse_env(&contents);

    if pairs.is_empty() {
        eprintln!("no secrets found in {file}");
        return;
    }

    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let imported = murk_cli::import_secrets(&mut vault, &mut current, &pairs);

    for key in &imported {
        eprintln!("  {} {}", "+".green(), key.bold());
    }

    save_vault(vault_path, &mut vault, &original, &current);
    let count = imported.len();
    eprintln!(
        "{} {count} secret{}",
        "imported".green(),
        if count == 1 { "" } else { "s" }
    );
}

fn cmd_rm(key: &str, vault_path: &str) {
    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();
    let mut current = murk;

    murk_cli::remove_secret(&mut vault, &mut current, key);

    save_vault(vault_path, &mut vault, &original, &current);
    eprintln!("{} {}", "removed".green(), key.bold());
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
            eprintln!(
                "{} .envrc already contains murk export",
                "ok:".green().bold()
            );
        }
        Ok(EnvrcStatus::Appended) => {
            eprintln!(
                "{} appended to .envrc. Run: {}",
                "ok:".green().bold(),
                "direnv allow".bold()
            );
        }
        Ok(EnvrcStatus::Created) => {
            eprintln!(
                "{} created .envrc. Run: {}",
                "ok:".green().bold(),
                "direnv allow".bold()
            );
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
            "{} MURK_KEY not available — meta not regenerated. Run any murk write command to fix.",
            "warning:".yellow().bold()
        );
    }

    // Write merged result to ours path (%A).
    vault::write(Path::new(ours_path), &output.result.vault)
        .unwrap_or_else(|e| die(&format_args!("writing merged vault: {e}"), 2));

    if output.result.conflicts.is_empty() {
        eprintln!("{} vault merged cleanly", "ok:".green().bold());
        process::exit(0);
    } else {
        eprintln!(
            "{} {} conflict{}:",
            "conflict:".red().bold(),
            output.result.conflicts.len(),
            if output.result.conflicts.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for c in &output.result.conflicts {
            eprintln!("  {} {} — {}", "-".red(), c.field.bold(), c.reason);
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
                    "ok:".green().bold()
                );
            }
            MergeDriverSetupStep::GitattributesAppended => {
                eprintln!("{} appended to .gitattributes", "ok:".green().bold());
            }
            MergeDriverSetupStep::GitattributesCreated => {
                eprintln!("{} created .gitattributes", "ok:".green().bold());
            }
            MergeDriverSetupStep::GitConfigured => {
                eprintln!("{} git merge driver configured", "ok:".green().bold());
            }
        }
    }

    eprintln!(
        "{}",
        "Commit .gitattributes so all collaborators use the merge driver.".dimmed()
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
                    if let Ok(old_vault) = vault::parse(&old_contents) {
                        if !old_vault.secrets.is_empty() {
                            eprintln!(
                                "{} cannot decrypt vault at {git_ref} — you may not have been a recipient",
                                "warning:".yellow().bold()
                            );
                        }
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
                        "+".green().bold(),
                        entry.key,
                        entry.new_value.as_deref().unwrap_or("")
                    );
                } else {
                    println!("{} {}", "+".green().bold(), entry.key);
                }
            }
            DiffKind::Removed => {
                if show_values {
                    println!(
                        "{} {} = {}",
                        "-".red().bold(),
                        entry.key,
                        entry.old_value.as_deref().unwrap_or("")
                    );
                } else {
                    println!("{} {}", "-".red().bold(), entry.key);
                }
            }
            DiffKind::Changed => {
                if show_values {
                    println!(
                        "{} {}: {} → {}",
                        "~".yellow().bold(),
                        entry.key,
                        entry.old_value.as_deref().unwrap_or(""),
                        entry.new_value.as_deref().unwrap_or("")
                    );
                } else {
                    println!("{} {}", "~".yellow().bold(), entry.key);
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
                "ok:".green().bold(),
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
            "{} {} ({} key{})",
            "authorized".green(),
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
        eprintln!("{} {}", "authorized".green(), display.bold());
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
        "{} {} from recipients. Vault re-encrypted.",
        "removed".green(),
        display.bold(),
    );

    if !result.exposed_keys.is_empty() {
        eprintln!();
        eprintln!(
            "{} {display} had access to these secrets (rotate them):",
            "warning:".yellow().bold()
        );
        for key in &result.exposed_keys {
            eprintln!("  {} {}", "-".dimmed(), key.bold());
        }
    }
    eprintln!();
    eprintln!(
        "{}",
        "This recipient can still decrypt previous versions from git history.".dimmed()
    );
}

fn cmd_recipients(vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = try_or_die(vault::read(path));

    let secret_key = env::var("MURK_KEY").ok().filter(|k| !k.is_empty());
    let entries = murk_cli::list_recipients(&vault, secret_key.as_deref());
    let has_names = entries.iter().any(|e| e.display_name.is_some());

    for entry in &entries {
        if has_names {
            let name = entry.display_name.as_deref().unwrap_or("");
            let marker = if entry.is_self {
                "  (you)".green().to_string()
            } else {
                String::new()
            };
            println!("{}  {}{}", entry.pubkey.dimmed(), name.bold(), marker);
        } else {
            println!("{}", entry.pubkey);
        }
    }
}

fn cmd_restore(phrase: Option<&str>) {
    let phrase = if let Some(p) = phrase {
        p.to_string()
    } else if io::stdin().is_terminal() {
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

    // Display vault header.
    println!("{}: {}", "vault".dimmed(), info.vault_name.bold());
    println!("{}: {}", "codename".dimmed(), info.codename.bold());
    if !info.repo.is_empty() {
        println!("{}: {}", "repo".dimmed(), info.repo);
    }
    println!("{}: {}", "created".dimmed(), info.created);
    println!(
        "{}: {} recipient{}",
        "recipients".dimmed(),
        info.recipient_count,
        if info.recipient_count == 1 { "" } else { "s" }
    );
    println!();

    if info.entries.is_empty() {
        println!("{}", "no keys in vault".dimmed());
        return;
    }

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

    let tag_width = info
        .entries
        .iter()
        .map(|e| {
            if e.tags.is_empty() {
                0
            } else {
                format!("[{}]", e.tags.join(", ")).len()
            }
        })
        .max()
        .unwrap_or(0);

    let has_meta = secret_key.is_some();

    for entry in &info.entries {
        let example_str = entry
            .example
            .as_ref()
            .map(|ex| format!("(e.g. {ex})"))
            .unwrap_or_default();

        let tag_str = if entry.tags.is_empty() {
            String::new()
        } else {
            format!("[{}]", entry.tags.join(", "))
        };

        // Pad plain strings for alignment, then apply colors.
        let key_padded = format!("{:<key_width$}", entry.key);
        let desc_padded = format!("{:<desc_width$}", entry.description);
        let ex_padded = format!("{example_str:<example_width$}");
        let tag_padded = format!("{tag_str:<tag_width$}");

        if has_meta {
            let scoped_str = if entry.scoped_recipients.is_empty() {
                String::new()
            } else {
                format!("[{}]", entry.scoped_recipients.join(", "))
            };
            println!(
                "{}  {}  {}  {}  {}",
                key_padded.bold(),
                desc_padded,
                ex_padded.dimmed(),
                tag_padded.cyan(),
                scoped_str.dimmed()
            );
        } else {
            println!(
                "{}  {}  {}  {}",
                key_padded.bold(),
                desc_padded,
                ex_padded.dimmed(),
                tag_padded.cyan()
            );
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { vault } => cmd_init(&vault),
        Command::Recover => cmd_recover(),
        Command::Restore { phrase } => cmd_restore(phrase.as_deref()),
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
        Command::Recipients { vault } => cmd_recipients(&vault),
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
