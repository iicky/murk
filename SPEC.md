# murk — Specification v2.0

> Encrypted secrets manager for developers. One key unlocks everything.

## Motivation

Existing secrets tools are either too complex (SOPS, Vault), tied to a runtime (dotenvx requires Node), or don't support teams cleanly. murk is a minimal Rust binary that:

- Stores encrypted secrets in a single `.murk` file safe to commit to git
- Uses one key (`MURK_KEY`) to unlock everything, stored in `~/.config/murk/keys/`
- Integrates naturally with `direnv`
- Supports multiple users and per-identity scoped secrets
- Documents itself via `murk info` — no key required

---

## Design Philosophy

- **Header is public, values are private.** Anyone with repo access can see what keys exist and what they're for. Only authorized recipients can see values.
- **age does the crypto.** murk handles UX and data structure. No custom crypto.
- **One binary, no runtime dependency.** Wrappable from any language via subprocess.
- **Git is the audit trail.** murk doesn't try to replicate what git already does.
- **Explicit over magic.** murk never silently overwrites or destroys data.

---

## Terminology

- **murk** — the shared layer. Secrets encrypted to all recipients.
- **mote** — a scoped secret. Encrypted to a single recipient's key. Overrides the shared value during export.

---

## Environment Variables

| Variable       | Required | Description                                             |
| -------------- | -------- | ------------------------------------------------------- |
| `MURK_KEY`     | No       | Your age private key. Inline alternative to `MURK_KEY_FILE`. Takes priority if both are set. |
| `MURK_KEY_FILE`| Yes      | Path to a file containing your age private key. Set by `murk init`. |
| `MURK_VAULT`   | No       | Vault filename. Defaults to `.murk`.                    |

Your identity is your key. murk derives your public key from `MURK_KEY` or `MURK_KEY_FILE` to determine which scoped secrets are yours and to identify you in the recipient list.

### Key storage

`murk init` writes the secret key to `~/.config/murk/keys/<vault-hash>` (chmod 600) and writes a `MURK_KEY_FILE` reference to `.env`:

```
export MURK_KEY_FILE=/home/alice/.config/murk/keys/a1b2c3d4e5f6a7b8
MURK_VAULT=prod.murk  # optional
```

The key never appears in the project directory. `.murk` should always be committed.

---

## File Format

A `.murk` file is a single JSON document. All fields except encrypted values and the meta blob are plaintext.

```json
{
  "version": "2.0",
  "created": "2026-02-27T00:00:00Z",
  "vault_name": ".murk",
  "repo": "https://github.com/org/repo",
  "recipients": [
    "age1abc...",
    "age1xyz..."
  ],
  "schema": {
    "DATABASE_URL": {
      "description": "postgres connection string",
      "example": "postgres://user:pass@host/db"
    },
    "OPENAI_KEY": {
      "description": "openai api key"
    }
  },
  "secrets": {
    "DATABASE_URL": {
      "shared": "<base64 age ciphertext>",
      "scoped": {
        "age1xyz...": "<base64 age ciphertext>"
      }
    },
    "OPENAI_KEY": {
      "shared": "<base64 age ciphertext>"
    }
  },
  "meta": "<base64 age ciphertext>"
}
```

### Version

The `version` field uses semver. murk validates the major version on load — a vault with major version other than `2` is rejected. Minor version bumps (e.g. `2.1`) are accepted.

### Recipients

Public keys only — no names or emails. Name-to-pubkey mappings live inside the encrypted meta blob where only authorized recipients can see them.

### Schema

Key metadata stored as a map of key name to entry. Each entry has a `description` and optional `example` and `tags` fields. Schema is public and readable without decryption.

Key names must be valid shell identifiers: `[A-Za-z_][A-Za-z0-9_]*`.

### Secrets

Each secret has a `shared` field containing age ciphertext encrypted to all recipients, and an optional `scoped` map of recipient pubkey to age ciphertext encrypted to only that recipient.

During `murk export`, scoped values override shared values for the current identity.

All age ciphertext is base64-encoded (standard alphabet, with padding).

### Meta

The `meta` field is a single age blob encrypted to all recipients. It contains:

```json
{
  "recipients": {
    "age1abc...": "mickey@example.com",
    "age1xyz...": "alice@example.com"
  },
  "mac": "blake3:abc123...",
  "hmac_key": "0a1b2c3d..."
}
```

`recipients` maps public keys to display names. This is the only place names are stored.

`mac` is a keyed integrity hash over the vault's encrypted content (see Integrity below).

`hmac_key` is a hex-encoded 32-byte random key used for BLAKE3 keyed hashing. Generated fresh on each save.

### Integrity

The MAC is a BLAKE3 keyed hash covering, in order:

1. **Key names** — iterated in sorted order (BTreeMap), each followed by `\x00`
2. **Per-key encrypted values** — for each key (sorted):
   - The shared ciphertext, followed by `\x00`
   - For each scoped entry (sorted by pubkey): the pubkey followed by `\x01`, the scoped ciphertext followed by `\x00`
3. **Recipient pubkeys** — sorted, each followed by `\x00`

The resulting digest is prefixed with `blake3:` and stored as the `mac` field in meta. The 32-byte BLAKE3 key is stored as `hmac_key` in the same encrypted meta blob.

On load, murk verifies the MAC. Legacy prefixes `sha256:` (v1, no scoped coverage) and `sha256v2:` (v2, unkeyed) are accepted for backward compatibility. On save, murk always writes `blake3:` with a fresh key.

Because both the MAC and its key live inside the encrypted meta blob, only authorized recipients can compute or verify the hash. This prevents an attacker from modifying secrets and recomputing a valid MAC.

---

## Commands

### `murk init [--vault NAME]`

Interactive setup. Prompts for a display name. Then:

1. Generates an age keypair via BIP39 (24-word mnemonic encodes the key directly)
2. Writes the secret key to `~/.config/murk/keys/<vault-hash>` with mode 0600
3. Writes `export MURK_KEY_FILE=<path>` to `.env` (creates if missing, warns if key already present)
4. Creates empty `.murk` vault with user's pubkey as first recipient
5. Prints BIP39 24-word recovery phrase to stderr

---

### `murk add KEY [--scoped] [--desc DESC] [--vault NAME]`

Adds or updates a secret. Prompts for the value interactively (hidden input via rpassword) or reads from stdin when piped.

Without `--scoped`, encrypts to all recipients (shared/murk layer). With `--scoped`, encrypts to only your key (scoped/mote layer).

Key names are validated as shell identifiers. Invalid names are rejected.

---

### `murk generate KEY [--length N] [--hex] [--desc DESC] [--tag TAG] [--vault NAME]`

Generates a cryptographically random value and stores it as a shared secret. Default length is 32 bytes, output as URL-safe base64 (no padding). Use `--hex` for hexadecimal output. Uses the same RNG as key generation.

---

### `murk rotate KEY [--generate] [--length N] [--hex] [--vault NAME]`

Replaces a secret value. Prompts for the new value interactively, or generates a random one with `--generate`. Use after revoking a recipient to ensure they can no longer use the old value.

`murk rotate --all` rotates every secret in the vault, prompting for each in sequence. `--generate` is not allowed with `--all` — external credentials (database passwords, API keys from third-party services) require manual rotation at the source.

---

### `murk rm KEY [--vault NAME]`

Removes a key from the vault (shared value, schema entry, and all scoped entries). No confirmation prompt — git is your safety net.

---

### `murk get KEY [--vault NAME]`

Prints a single decrypted value to stdout. Scoped values take priority over shared values. Exits with code 1 if key not found.

---

### `murk ls [--vault NAME]`

Lists key names, one per line.

---

### `murk describe KEY "description" [--vault NAME]`

Sets the description for a key in the plaintext schema. Does not touch encrypted values.

---

### `murk export [--vault NAME]`

Prints all secrets as `export KEY=VALUE` statements to stdout. Scoped values override shared values for the current identity. Errors go to stderr.

Primary usage via direnv:

```bash
# .envrc
eval "$(murk export)"
```

---

### `murk import [FILE] [--vault NAME]`

Imports secrets from a `.env` file. Parses `KEY=VALUE` lines (supports `export` prefix, single/double quotes). Skips `MURK_*` keys with a warning. Invalid key names are skipped with a warning.

---

### `murk info [--vault NAME]`

Prints the public schema. Works without `MURK_KEY`. With a valid key, also shows recipient names and count.

---

### `murk recover`

Prints the BIP39 24-word recovery phrase for the current `MURK_KEY`.

---

### `murk restore`

Recovers `MURK_KEY` from a BIP39 recovery phrase. Prompts for the phrase interactively (hidden input) or reads from stdin when piped.

---

### `murk circle`

Lists all recipients. With `MURK_KEY`, shows display names from the encrypted meta and marks the current user with `*`.

---

### `murk circle authorize PUBKEY [--name NAME] [--vault NAME]`

Adds a new recipient. Re-encrypts all shared secrets to include the new public key. Accepts `age1...`, `ssh-ed25519 ...`, or `github:username` formats.

---

### `murk circle revoke RECIPIENT [--vault NAME]`

Removes a recipient by pubkey or display name. Re-encrypts all shared secrets without their key. Removes their scoped entries.

---

### `murk diff [REF] [--vault NAME]`

Shows which secrets changed between the current vault and a git ref (defaults to `HEAD`).

---

### `murk merge-driver ANCESTOR OURS THEIRS [--vault NAME]`

Git merge driver for `.murk` files. Merges non-conflicting secret changes automatically.

---

### `murk setup-merge-driver`

Configures git to use `murk merge-driver` for `.murk` files via `.gitattributes` and `.git/config`.

---

## Security Model

**What murk protects against:**

- Repo leaks — `.murk` is safe to commit, useless without a private key
- Accidental secret exposure — `.env` is never committed if `.gitignore` is set correctly
- Private overrides — scoped secrets (motes) are encrypted only to their owner

**What murk does not protect against:**

- A compromised machine with `MURK_KEY` present
- Historical access after revocation — old `.murk` versions remain in git history. Always rotate credentials when revoking.
- Fine-grained audit logging — use a secrets server for regulated environments
- Malicious recipients — any authorized recipient can decrypt all shared secrets

**Treat `MURK_KEY` like your SSH private key.** Never commit it. Never share it.

**Revocation is incomplete without credential rotation.** murk always warns about this.

### Scope

murk is appropriate for dev tooling and small teams. It is not designed for regulated environments requiring audit trails, key management infrastructure, or provable access controls.

---

## Crate Dependencies

- `age` / `rage` — encryption
- `bip39` — recovery phrase generation
- `serde` / `serde_json` — serialization
- `clap` — CLI argument parsing
- `blake3` — keyed integrity hashing
- `sha2` — legacy integrity hashing (backward compatibility)
- `chrono` — timestamps
- `colored` — terminal output
- `rpassword` — hidden input prompting
