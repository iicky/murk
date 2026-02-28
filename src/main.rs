mod crypto;
mod integrity;
mod recovery;
mod types;
mod vault;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};

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

    /// Add or update a secret
    Add {
        /// Secret key name
        key: String,
        /// Secret value
        value: String,
        /// Description for this key
        #[arg(long)]
        desc: Option<String>,
        /// Store in personal blob only
        #[arg(long)]
        private: bool,
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
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Show public schema and key info
    Info {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export all secrets as shell export statements
    Export {
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

/// Generate a simple ISO-8601 UTC timestamp (no chrono dependency).
fn now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Convert epoch seconds to date-time components.
    // Good enough for a creation timestamp — not a general-purpose calendar.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 to (year, month, day).
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn cmd_init(vault_name: &str) {
    let vault_path = Path::new(vault_name);

    // Don't overwrite an existing vault.
    if vault_path.exists() {
        eprintln!("error: {vault_name} already exists");
        process::exit(1);
    }

    // Prompt for display name and vault name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        eprintln!("error: name is required");
        process::exit(1);
    }

    // Generate keypair via BIP39.
    eprintln!("Generating keypair...");
    let (phrase, secret_key, pubkey) = match recovery::generate() {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    // Check .env for existing MURK_KEY.
    let env_path = Path::new(".env");
    if env_path.exists() {
        let contents = fs::read_to_string(env_path).unwrap_or_default();
        if contents.lines().any(|l| l.starts_with("MURK_KEY=") || l.starts_with("export MURK_KEY=")) {
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
    eprintln!("Writing MURK_KEY to .env...");
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

    // Build empty shared blob with the recipient name mapping.
    let mut recipient_names = HashMap::new();
    recipient_names.insert(pubkey.clone(), name.clone());

    let murk = types::Murk {
        values: HashMap::new(),
        recipients: recipient_names,
        per_key_access: HashMap::new(),
        motes: HashMap::new(),
    };

    let murk_json = serde_json::to_vec(&murk).unwrap();

    // Encrypt shared blob to this recipient.
    let recipient = crypto::parse_recipient(&pubkey).unwrap();
    let encrypted = match crypto::encrypt(&murk_json, &[recipient]) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    // Build header.
    let murk_hash = integrity::hash(&encrypted);
    let header = types::Header {
        version: "1.0".into(),
        created: now_utc(),
        vault_name: vault_name.into(),
        murk_hash,
        recipients: vec![pubkey],
        schema: vec![],
    };

    // Write vault.
    if let Err(e) = vault::write(vault_path, &header, &encrypted) {
        eprintln!("error: {e}");
        process::exit(1);
    }

    // Print recovery phrase.
    eprintln!();
    eprintln!("WARNING: RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:");
    println!("{phrase}");
    eprintln!();
    eprintln!("Vault initialized. Added as recipient.");
    eprintln!("Next: murk add KEY VALUE");
}

/// Try to decrypt a personal mote for the given pubkey.
/// Returns None if no mote exists or decryption fails.
fn decrypt_mote(
    murk: &types::Murk,
    pubkey: &str,
    identity: &age::x25519::Identity,
) -> Option<types::Mote> {
    let encrypted_mote = murk.motes.get(pubkey)?;
    let mote_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_mote).ok()?;
    let plaintext = crypto::decrypt(&mote_bytes, identity).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Load the vault: read the file, decrypt the shared blob, return all parts.
/// Exits with an error message if anything fails.
fn load_vault(vault: &str) -> (types::Header, types::Murk, age::x25519::Identity, String) {
    let path = Path::new(vault);
    let secret_key = match env::var("MURK_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("error: MURK_KEY not set");
            process::exit(1);
        }
    };

    // Warn if .env has loose permissions.
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
                    "warning: .env is readable by others (mode {:o}). Run: chmod 600 .env",
                    mode & 0o777
                );
            }
        }
    }

    let identity = match crypto::parse_identity(&secret_key) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let (header, encrypted) = match vault::read(path) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let plaintext = match crypto::decrypt(&encrypted, &identity) {
        Ok(pt) => pt,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let murk: types::Murk = match serde_json::from_slice(&plaintext) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: invalid vault data: {e}");
            process::exit(1);
        }
    };

    (header, murk, identity, secret_key)
}

/// Re-encrypt the shared blob and write the vault back to disk.
fn save_vault(vault: &str, header: &mut types::Header, murk: &types::Murk) {
    let murk_json = serde_json::to_vec(murk).unwrap();

    // Build recipient list from the header pubkeys.
    let recipients: Vec<age::x25519::Recipient> = header
        .recipients
        .iter()
        .map(|pk| crypto::parse_recipient(pk).unwrap())
        .collect();

    let encrypted = match crypto::encrypt(&murk_json, &recipients) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    header.murk_hash = integrity::hash(&encrypted);

    if let Err(e) = vault::write(Path::new(vault), header, &encrypted) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn cmd_add(key: &str, value: &str, desc: Option<&str>, private: bool, vault: &str) {
    let (mut header, mut murk, identity, _secret_key) = load_vault(vault);

    if private {
        // Add to personal blob (mote).
        let pubkey = identity.to_public().to_string();

        // Decrypt existing mote or create a new one.
        let mut mote = decrypt_mote(&murk, &pubkey, &identity).unwrap_or(types::Mote {
            values: HashMap::new(),
        });

        mote.values.insert(key.into(), value.into());

        // Re-encrypt mote to self only.
        let mote_json = serde_json::to_vec(&mote).unwrap();
        let recipient = crypto::parse_recipient(&pubkey).unwrap();
        let encrypted_mote = match crypto::encrypt(&mote_json, &[recipient]) {
            Ok(blob) => blob,
            Err(e) => {
                eprintln!("error: {e}");
                process::exit(1);
            }
        };

        let mote_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted_mote);
        murk.motes.insert(pubkey, mote_b64);
    } else {
        // Add to shared blob.
        murk.values.insert(key.into(), value.into());
    }

    // Add schema entry if key is new, or update description if --desc provided.
    if let Some(entry) = header.schema.iter_mut().find(|e| e.key == key) {
        if let Some(d) = desc {
            entry.description = d.into();
        }
    } else {
        header.schema.push(types::SchemaEntry {
            key: key.into(),
            description: desc.unwrap_or("").into(),
            example: None,
        });
        if desc.is_none() {
            eprintln!("hint: no description set. Run: murk describe {key} \"your description\"");
        }
    }

    save_vault(vault, &mut header, &murk);
}

fn cmd_rm(key: &str, vault: &str) {
    let (mut header, mut murk, _identity, _secret_key) = load_vault(vault);

    murk.values.remove(key);
    murk.per_key_access.remove(key);
    header.schema.retain(|e| e.key != key);

    save_vault(vault, &mut header, &murk);
    eprintln!("removed {key}");
}

fn cmd_get(key: &str, vault: &str) {
    let (_header, murk, identity, _secret_key) = load_vault(vault);

    let pubkey = identity.to_public().to_string();

    // Check personal blob first (overrides shared).
    if let Some(mote) = decrypt_mote(&murk, &pubkey, &identity)
        && let Some(value) = mote.values.get(key)
    {
        println!("{value}");
        return;
    }

    // Fall back to shared values.
    match murk.values.get(key) {
        Some(value) => println!("{value}"),
        None => {
            eprintln!("error: key not found: {key}");
            process::exit(1);
        }
    }
}

fn cmd_ls(vault: &str) {
    let path = Path::new(vault);
    let header = match vault::read_header(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    for entry in &header.schema {
        println!("{}", entry.key);
    }
}

fn cmd_describe(key: &str, description: &str, example: Option<&str>, vault: &str) {
    let (mut header, murk, _identity, _secret_key) = load_vault(vault);

    if let Some(entry) = header.schema.iter_mut().find(|e| e.key == key) {
        entry.description = description.into();
        entry.example = example.map(|s| s.into());
    } else {
        header.schema.push(types::SchemaEntry {
            key: key.into(),
            description: description.into(),
            example: example.map(|s| s.into()),
        });
    }

    save_vault(vault, &mut header, &murk);
}

fn cmd_export(vault: &str) {
    let (_header, murk, identity, _secret_key) = load_vault(vault);

    // Start with shared values.
    let mut values = murk.values.clone();

    // Apply personal overrides.
    let pubkey = identity.to_public().to_string();
    if let Some(mote) = decrypt_mote(&murk, &pubkey, &identity) {
        for (k, v) in mote.values {
            values.insert(k, v);
        }
    }

    // Print as shell export statements, sorted for deterministic output.
    let mut keys: Vec<&String> = values.keys().collect();
    keys.sort();
    for k in keys {
        let v = &values[k];
        // Shell-escape: wrap in single quotes, escape embedded single quotes.
        let escaped = v.replace('\'', "'\\''");
        println!("export {k}='{escaped}'");
    }
}

fn cmd_authorize(pubkey: &str, name: Option<&str>, vault: &str) {
    // Validate the pubkey.
    if crypto::parse_recipient(pubkey).is_err() {
        eprintln!("error: invalid public key: {pubkey}");
        process::exit(1);
    }

    let (mut header, mut murk, _identity, _secret_key) = load_vault(vault);

    // Check if already a recipient.
    if header.recipients.contains(&pubkey.to_string()) {
        eprintln!("error: {pubkey} is already a recipient");
        process::exit(1);
    }

    // Add to header recipients list.
    header.recipients.push(pubkey.into());

    // Add name mapping in shared blob (if provided).
    if let Some(n) = name {
        murk.recipients.insert(pubkey.into(), n.into());
    }

    save_vault(vault, &mut header, &murk);

    let display = name.unwrap_or(pubkey);
    eprintln!("authorized {display}");
}

fn cmd_revoke(recipient: &str, vault: &str) {
    let (mut header, mut murk, _identity, _secret_key) = load_vault(vault);

    // Resolve recipient to pubkey — could be a name or a pubkey.
    let pubkey = if header.recipients.contains(&recipient.to_string()) {
        recipient.to_string()
    } else {
        // Try to find by name in the encrypted recipients map.
        murk.recipients
            .iter()
            .find(|(_, name)| name.as_str() == recipient)
            .map(|(pk, _)| pk.clone())
            .unwrap_or_else(|| {
                eprintln!("error: recipient not found: {recipient}");
                process::exit(1);
            })
    };

    // Last-recipient protection.
    if header.recipients.len() == 1 {
        eprintln!(
            "error: cannot revoke last recipient — vault would become permanently inaccessible"
        );
        process::exit(1);
    }

    // Remove from header.
    header.recipients.retain(|pk| pk != &pubkey);

    // Remove from shared blob.
    let display_name = murk.recipients.remove(&pubkey);
    murk.motes.remove(&pubkey);

    // Remove from per_key_access values.
    for access_list in murk.per_key_access.values_mut() {
        access_list.retain(|pk| pk != &pubkey);
    }

    save_vault(vault, &mut header, &murk);

    let display = display_name.as_deref().unwrap_or(&pubkey);
    eprintln!("Removed {display} ({pubkey}) from recipients. Vault re-encrypted.");
    eprintln!("warning: this recipient can still decrypt previous versions from git history.");
    eprintln!("         Rotate any sensitive credentials to complete revocation.");
}

fn cmd_recipients(vault: &str) {
    let path = Path::new(vault);
    let header = match vault::read_header(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    // Try to decrypt for names and to identify "you".
    let murk_data = env::var("MURK_KEY").ok().and_then(|secret_key| {
        let identity = crypto::parse_identity(&secret_key).ok()?;
        let my_pubkey = identity.to_public().to_string();
        let (_, encrypted) = vault::read(path).ok()?;
        let plaintext = crypto::decrypt(&encrypted, &identity).ok()?;
        let murk: types::Murk = serde_json::from_slice(&plaintext).ok()?;
        Some((murk, my_pubkey))
    });

    for pk in &header.recipients {
        if let Some((ref murk, ref my_pubkey)) = murk_data {
            let name = murk.recipients.get(pk).map(|s| s.as_str()).unwrap_or("");
            let marker = if pk == my_pubkey { "  (you)" } else { "" };
            println!("{pk}  {name}{marker}");
        } else {
            println!("{pk}");
        }
    }
}

fn cmd_restore(phrase: Option<&str>) {
    let phrase = match phrase {
        Some(p) => p.to_string(),
        None => {
            eprint!("Enter 24-word recovery phrase: ");
            io::stdout().flush().ok();
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line).unwrap_or(0);
            line.trim().to_string()
        }
    };

    if phrase.is_empty() {
        eprintln!("error: recovery phrase is required");
        process::exit(1);
    }

    match recovery::recover(&phrase) {
        Ok(key) => println!("{key}"),
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_recover() {
    let secret_key = match env::var("MURK_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("error: MURK_KEY not set");
            process::exit(1);
        }
    };

    match recovery::phrase_from_key(&secret_key) {
        Ok(phrase) => println!("{phrase}"),
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_info(vault: &str) {
    let path = Path::new(vault);
    let header = match vault::read_header(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    if header.schema.is_empty() {
        println!("no keys in vault");
        return;
    }

    // Try to decrypt the shared blob for per_key_access and recipient names.
    // This is optional — info works without MURK_KEY.
    let murk_data = env::var("MURK_KEY").ok().and_then(|secret_key| {
        let identity = crypto::parse_identity(&secret_key).ok()?;
        let (_, murk_bytes) = vault::read(path).ok()?;
        let plaintext = crypto::decrypt(&murk_bytes, &identity).ok()?;
        let murk: types::Murk = serde_json::from_slice(&plaintext).ok()?;
        Some(murk)
    });

    // Compute column widths for aligned output.
    let key_width = header.schema.iter().map(|e| e.key.len()).max().unwrap();

    let desc_width = header
        .schema
        .iter()
        .map(|e| e.description.len())
        .max()
        .unwrap();

    let example_width = header
        .schema
        .iter()
        .map(|e| {
            e.example
                .as_ref()
                .map(|ex| format!("(e.g. {ex})").len())
                .unwrap_or(0)
        })
        .max()
        .unwrap();

    for entry in &header.schema {
        let example_str = entry
            .example
            .as_ref()
            .map(|ex| format!("(e.g. {ex})"))
            .unwrap_or_default();

        let line = if let Some(ref murk) = murk_data {
            let recipients = murk
                .per_key_access
                .get(&entry.key)
                .map(|pubkeys| {
                    let names: Vec<&str> = pubkeys
                        .iter()
                        .map(|pk| murk.recipients.get(pk).map(|s| s.as_str()).unwrap_or(pk))
                        .collect();
                    format!("[{}]", names.join(", "))
                })
                .unwrap_or_else(|| "[]".into());
            format!(
                "{:<key_w$}  {:<desc_w$}  {:<ex_w$}  {}",
                entry.key,
                entry.description,
                example_str,
                recipients,
                key_w = key_width,
                desc_w = desc_width,
                ex_w = example_width,
            )
        } else {
            format!(
                "{:<key_w$}  {:<desc_w$}  {}",
                entry.key,
                entry.description,
                example_str,
                key_w = key_width,
                desc_w = desc_width,
            )
        };

        println!("{}", line.trim_end());
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { vault } => cmd_init(&vault),
        Command::Recover => cmd_recover(),
        Command::Restore { phrase } => cmd_restore(phrase.as_deref()),
        Command::Add {
            key,
            value,
            desc,
            private,
            vault,
        } => cmd_add(&key, &value, desc.as_deref(), private, &vault),
        Command::Rm { key, vault } => cmd_rm(&key, &vault),
        Command::Get { key, vault } => cmd_get(&key, &vault),
        Command::Ls { vault } => cmd_ls(&vault),
        Command::Describe {
            key,
            description,
            example,
            vault,
        } => cmd_describe(&key, &description, example.as_deref(), &vault),
        Command::Info { vault } => cmd_info(&vault),
        Command::Export { vault } => cmd_export(&vault),
        Command::Authorize {
            pubkey,
            name,
            vault,
        } => cmd_authorize(&pubkey, name.as_deref(), &vault),
        Command::Revoke { recipient, vault } => cmd_revoke(&recipient, &vault),
        Command::Recipients { vault } => cmd_recipients(&vault),
    }
}
