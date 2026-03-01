use murk_cli::{DiffKind, crypto, decrypt_value, encrypt_value, now_utc, recovery, types, vault};

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::process;

use age::secrecy::ExposeSecret;
use clap::{Parser, Subcommand};
use colored::Colorize;

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
        /// Secret value (use "-" or omit to read from stdin)
        value: Option<String>,
        /// Description for this key
        #[arg(long)]
        desc: Option<String>,
        /// Store in personal blob only
        #[arg(long)]
        private: bool,
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

    /// Add a recipient to the vault
    Authorize {
        /// Recipient's age public key
        pubkey: String,
        /// Optional display name (stored in encrypted blob only)
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

fn cmd_init(vault_name: &str) {
    let vault_path = Path::new(vault_name);

    // Don't overwrite an existing vault.
    if vault_path.exists() {
        eprintln!("{} {vault_name} already exists", "error:".red().bold());
        process::exit(1);
    }

    // Prompt for display name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        eprintln!("{} name is required", "error:".red().bold());
        process::exit(1);
    }

    // Generate keypair via BIP39.
    eprintln!("{}", "Generating keypair...".dimmed());
    let (phrase, secret_key, pubkey) = match recovery::generate() {
        Ok(result) => result,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    };

    // Check .env for existing MURK_KEY.
    let env_path = Path::new(".env");
    if env_path.exists() {
        let contents = fs::read_to_string(env_path).unwrap_or_default();
        if contents
            .lines()
            .any(|l| l.starts_with("MURK_KEY=") || l.starts_with("export MURK_KEY="))
        {
            let answer = prompt(
                "MURK_KEY already exists in .env. Overwrite? [y/N]",
                Some("N"),
            );
            if !answer.eq_ignore_ascii_case("y") {
                eprintln!("Aborted.");
                process::exit(1);
            }
            // Remove existing MURK_KEY line(s).
            let filtered: Vec<&str> = contents
                .lines()
                .filter(|l| !l.starts_with("MURK_KEY=") && !l.starts_with("export MURK_KEY="))
                .collect();
            fs::write(env_path, filtered.join("\n") + "\n").unwrap();
        }
    }

    // Append MURK_KEY to .env.
    eprintln!("{}", "Writing MURK_KEY to .env...".dimmed());
    let mut env_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(env_path)
        .unwrap();
    writeln!(env_file, "export MURK_KEY={secret_key}").unwrap();
    drop(env_file);

    // Restrict .env to owner-only (chmod 600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(env_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Build meta with the recipient name mapping.
    let mut recipient_names = HashMap::new();
    recipient_names.insert(pubkey.clone(), name.clone());

    let recipient = crypto::parse_recipient(&pubkey).unwrap();
    let meta = types::Meta {
        recipients: recipient_names,
        mac: String::new(), // Will be computed by vault write.
    };
    let meta_json = serde_json::to_vec(&meta).unwrap();
    let meta_enc = match encrypt_value(&meta_json, &[recipient]) {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    };

    // Build vault.
    let v = types::Vault {
        version: "2.0".into(),
        created: now_utc(),
        vault_name: vault_name.into(),
        recipients: vec![pubkey],
        schema: BTreeMap::new(),
        secrets: BTreeMap::new(),
        meta: meta_enc,
    };

    // Write vault.
    if let Err(e) = vault::write(vault_path, &v) {
        eprintln!("{} {e}", "error:".red().bold());
        process::exit(1);
    }

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
    eprintln!("{}", "Vault initialized. Added as recipient.".green());
    eprintln!("Next: {}", "murk add KEY VALUE".bold());
}

fn resolve_key() -> age::secrecy::SecretString {
    murk_cli::resolve_key().unwrap_or_else(|e| {
        eprintln!("{} {e}", "error:".red().bold());
        process::exit(1);
    })
}

fn load_vault(vault: &str) -> (types::Vault, types::Murk, age::x25519::Identity) {
    murk_cli::warn_env_permissions();
    murk_cli::load_vault(vault).unwrap_or_else(|e| {
        eprintln!("{} {e}", "error:".red().bold());
        process::exit(1);
    })
}

fn save_vault(
    vault_path: &str,
    vault: &mut types::Vault,
    original: &types::Murk,
    current: &types::Murk,
) {
    murk_cli::save_vault(vault_path, vault, original, current).unwrap_or_else(|e| {
        eprintln!("{} {e}", "error:".red().bold());
        process::exit(1);
    });
}

/// Resolve the secret value from a CLI argument, stdin pipe, or interactive prompt.
/// Returns the value or exits with an error.
fn resolve_value(value: Option<String>, key: &str) -> String {
    // Explicit value on the command line (or "-" means read stdin).
    if let Some(v) = value {
        if v != "-" {
            return v;
        }
    }

    let stdin = io::stdin();
    if !stdin.is_terminal() {
        // Piped input: `echo "secret" | murk add KEY`
        let mut buf = String::new();
        stdin.lock().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("{} reading stdin: {e}", "error:".red().bold());
            process::exit(1);
        });
        let trimmed = buf.trim_end_matches('\n').to_string();
        if trimmed.is_empty() {
            eprintln!("{} empty value from stdin", "error:".red().bold());
            process::exit(1);
        }
        return trimmed;
    }

    // Interactive TTY: prompt without echo.
    eprint!("value for {key}: ");
    io::stderr().flush().ok();
    let password = rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("\n{} reading input: {e}", "error:".red().bold());
        process::exit(1);
    });
    if password.is_empty() {
        eprintln!("{} empty value", "error:".red().bold());
        process::exit(1);
    }
    password
}

fn cmd_add(
    key: &str,
    value: &str,
    desc: Option<&str>,
    private: bool,
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
        private,
        tags,
        &identity,
    );

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
    let contents = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} cannot read {file}: {e}", "error:".red().bold());
            process::exit(1);
        }
    };

    let pairs = murk_cli::parse_env(&contents);

    if pairs.is_empty() {
        eprintln!("no secrets found in {file}");
        return;
    }

    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();
    let mut current = murk;

    for (key, value) in &pairs {
        current.values.insert(key.clone(), value.clone());

        if !vault.schema.contains_key(key.as_str()) {
            vault.schema.insert(
                key.clone(),
                types::SchemaEntry {
                    description: String::new(),
                    example: None,
                    tags: vec![],
                },
            );
        }

        eprintln!("  {} {}", "+".green(), key.bold());
    }

    save_vault(vault_path, &mut vault, &original, &current);
    let count = pairs.len();
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
    let pubkey = identity.to_public().to_string();

    if let Some(value) = murk_cli::get_secret(&murk, key, &pubkey) {
        println!("{value}");
    } else {
        eprintln!(
            "{} key not found: {}. Run {} to see available keys",
            "error:".red().bold(),
            key.bold(),
            "murk ls".bold()
        );
        process::exit(1);
    }
}

fn cmd_ls(tags: &[String], vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = match vault::read(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    };

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
    let pubkey = identity.to_public().to_string();

    let exports = murk_cli::export_secrets(&vault, &murk, &pubkey, tags);
    for (k, escaped) in &exports {
        println!("export {k}='{escaped}'");
    }
}

fn cmd_env(vault: &str) {
    let envrc = Path::new(".envrc");
    let murk_line = format!("eval \"$(murk export --vault {vault})\"");

    if envrc.exists() {
        let contents = fs::read_to_string(envrc).unwrap_or_else(|e| {
            eprintln!("{} reading .envrc: {e}", "error:".red().bold());
            process::exit(1);
        });
        if contents.contains("murk export") {
            eprintln!(
                "{} .envrc already contains murk export",
                "ok:".green().bold()
            );
            return;
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(envrc)
            .unwrap_or_else(|e| {
                eprintln!("{} writing .envrc: {e}", "error:".red().bold());
                process::exit(1);
            });
        writeln!(file, "\n{murk_line}").unwrap();
        eprintln!(
            "{} appended to .envrc. Run: {}",
            "ok:".green().bold(),
            "direnv allow".bold()
        );
    } else {
        fs::write(envrc, format!("{murk_line}\n")).unwrap_or_else(|e| {
            eprintln!("{} writing .envrc: {e}", "error:".red().bold());
            process::exit(1);
        });
        eprintln!(
            "{} created .envrc. Run: {}",
            "ok:".green().bold(),
            "direnv allow".bold()
        );
    }
}

fn cmd_diff(git_ref: &str, show_values: bool, vault_path: &str) {
    let (_vault, current_murk, identity) = load_vault(vault_path);

    // Get the old vault contents from git.
    let output = process::Command::new("git")
        .args(["show", &format!("{git_ref}:{vault_path}")])
        .output()
        .unwrap_or_else(|e| {
            eprintln!("{} running git: {e}", "error:".red().bold());
            process::exit(1);
        });

    let old_values: HashMap<String, String> = if output.status.success() {
        let old_contents = String::from_utf8_lossy(&output.stdout);
        match vault::parse(&old_contents) {
            Ok(old_vault) => {
                let mut values = HashMap::new();
                for (key, entry) in &old_vault.secrets {
                    if let Ok(plaintext) = decrypt_value(&entry.shared, &identity) {
                        if let Ok(value) = String::from_utf8(plaintext) {
                            values.insert(key.clone(), value);
                        }
                    }
                }
                if values.is_empty() && !old_vault.secrets.is_empty() {
                    eprintln!(
                        "{} cannot decrypt vault at {git_ref} — you may not have been a recipient",
                        "warning:".yellow().bold()
                    );
                }
                values
            }
            Err(e) => {
                eprintln!("{} parsing vault at {git_ref}: {e}", "error:".red().bold());
                process::exit(1);
            }
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

    if let Err(e) = murk_cli::authorize_recipient(&mut vault, &mut current, pubkey, name) {
        eprintln!("{} {e}", "error:".red().bold());
        process::exit(1);
    }

    save_vault(vault_path, &mut vault, &original, &current);

    let display = name.unwrap_or(pubkey);
    eprintln!("{} {}", "authorized".green(), display.bold());
}

fn cmd_revoke(recipient: &str, vault_path: &str) {
    let (mut vault, murk, _identity) = load_vault(vault_path);
    let original = murk.clone();
    let mut current = murk;

    let result = match murk_cli::revoke_recipient(&mut vault, &mut current, recipient) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    };

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
    let vault = match vault::read(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    };

    // Try to decrypt meta for names and to identify "you".
    let meta_data = env::var("MURK_KEY").ok().and_then(|secret_key| {
        let identity = crypto::parse_identity(&secret_key).ok()?;
        let my_pubkey = identity.to_public().to_string();
        let plaintext = decrypt_value(&vault.meta, &identity).ok()?;
        let meta: types::Meta = serde_json::from_slice(&plaintext).ok()?;
        Some((meta, my_pubkey))
    });

    for pk in &vault.recipients {
        if let Some((ref meta, ref my_pubkey)) = meta_data {
            let name = meta.recipients.get(pk).map_or("", String::as_str);
            let marker = if pk == my_pubkey {
                "  (you)".green().to_string()
            } else {
                String::new()
            };
            println!("{}  {}{}", pk.dimmed(), name.bold(), marker);
        } else {
            println!("{pk}");
        }
    }
}

fn cmd_restore(phrase: Option<&str>) {
    let phrase = if let Some(p) = phrase {
        p.to_string()
    } else {
        eprint!("Enter 24-word recovery phrase: ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).unwrap_or(0);
        line.trim().to_string()
    };

    if phrase.is_empty() {
        eprintln!("{} recovery phrase is required", "error:".red().bold());
        process::exit(1);
    }

    match recovery::recover(&phrase) {
        Ok(key) => println!("{key}"),
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    }
}

fn cmd_recover() {
    let secret_key = resolve_key();

    match recovery::phrase_from_key(secret_key.expose_secret()) {
        Ok(phrase) => println!("{phrase}"),
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    }
}

fn cmd_info(tags: &[String], vault_path: &str) {
    let path = Path::new(vault_path);
    let vault = match vault::read(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            process::exit(1);
        }
    };

    // Filter by tag if specified.
    let entries: Vec<(&String, &types::SchemaEntry)> = if tags.is_empty() {
        vault.schema.iter().collect()
    } else {
        vault
            .schema
            .iter()
            .filter(|(_, e)| e.tags.iter().any(|t| tags.contains(t)))
            .collect()
    };

    if entries.is_empty() {
        println!("{}", "no keys in vault".dimmed());
        return;
    }

    // Try to decrypt meta for recipient names.
    let meta_data = env::var("MURK_KEY").ok().and_then(|secret_key| {
        let identity = crypto::parse_identity(&secret_key).ok()?;
        let plaintext = decrypt_value(&vault.meta, &identity).ok()?;
        let meta: types::Meta = serde_json::from_slice(&plaintext).ok()?;
        Some(meta)
    });

    // Compute column widths for aligned output.
    let key_width = entries.iter().map(|(k, _)| k.len()).max().unwrap();
    let desc_width = entries
        .iter()
        .map(|(_, e)| e.description.len())
        .max()
        .unwrap();

    let example_width = entries
        .iter()
        .map(|(_, e)| {
            e.example
                .as_ref()
                .map_or(0, |ex| format!("(e.g. {ex})").len())
        })
        .max()
        .unwrap();

    let tag_width = entries
        .iter()
        .map(|(_, e)| {
            if e.tags.is_empty() {
                0
            } else {
                format!("[{}]", e.tags.join(", ")).len()
            }
        })
        .max()
        .unwrap();

    for (key, entry) in &entries {
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
        let key_padded = format!("{:<key_width$}", key);
        let desc_padded = format!("{:<desc_width$}", entry.description);
        let ex_padded = format!("{example_str:<example_width$}");
        let tag_padded = format!("{tag_str:<tag_width$}");

        if let Some(ref meta) = meta_data {
            // Show which recipients have scoped overrides for this key.
            let scoped_pks: Vec<String> = vault
                .secrets
                .get(key.as_str())
                .map(|s| {
                    s.scoped
                        .keys()
                        .map(|pk| {
                            meta.recipients
                                .get(pk)
                                .cloned()
                                .unwrap_or_else(|| pk.chars().take(12).collect::<String>() + "…")
                        })
                        .collect()
                })
                .unwrap_or_default();
            let scoped_str = if scoped_pks.is_empty() {
                String::new()
            } else {
                format!("[{}]", scoped_pks.join(", "))
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
            value,
            desc,
            private,
            tag,
            vault,
        } => {
            let resolved = resolve_value(value, &key);
            cmd_add(&key, &resolved, desc.as_deref(), private, &tag, &vault);
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
    }
}
