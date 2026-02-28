# murk — Specification v1.0

> Encrypted secrets manager for developers. One key unlocks everything.

## Motivation

Existing secrets tools are either too complex (SOPS, Vault), tied to a runtime (dotenvx requires Node), or don't support teams cleanly. murk is a minimal Rust binary that:

- Stores encrypted secrets in a single `.murk` file safe to commit to git
- Uses one key (`MURK_KEY`) in `.env` to unlock everything
- Integrates naturally with `direnv`
- Supports multiple users and per-identity private secrets
- Documents itself via `murk info` — no key required

---

## Design Philosophy

- **Header is public, blob is private.** Anyone with repo access can see what keys exist and what they're for. Only authorized recipients can see values.
- **age does the crypto.** murk handles UX and data structure. No custom crypto.
- **One binary, no runtime dependency.** Wrappable from any language via subprocess.
- **Git is the audit trail.** murk doesn't try to replicate what git already does.
- **Explicit over magic.** murk never silently overwrites or destroys data.

---

## Environment Variables

| Variable     | Required | Description                                             |
| ------------ | -------- | ------------------------------------------------------- |
| `MURK_KEY`   | Yes      | Your age private key. Written to `.env` by `murk init`. |
| `MURK_VAULT` | No       | Vault filename. Defaults to `.murk`.                    |

Your identity is your key. murk derives your public key from `MURK_KEY` to determine which personal blob is yours and to identify you in the recipient list. No separate username variable is needed.

### `.env` example

```
MURK_KEY=AGE-SECRET-KEY-1...
MURK_VAULT=prod.murk  # optional
```

`.env` should always be in `.gitignore`. `.murk` should always be committed.

---

## File Format

A `.murk` file has three sections:

```
[plaintext JSON header]
[newline separator]
[shared age blob]
[newline separator]
[anonymous personal blob]
[newline separator]
[anonymous personal blob]
...
```

### Plaintext Header

Public. Readable by anyone. Contains no secret values, identity information, or access metadata.

```json
{
  "version": "1.0",
  "created": "2026-02-27T00:00:00Z",
  "vault_name": ".murk",
  "shared_blob_hash": "sha256:abc123...",
  "recipients": [
    "age1abc...",
    "age1xyz..."
  ],
  "schema": [
    {
      "key": "DATABASE_URL",
      "description": "postgres connection string",
      "example": "postgres://user:pass@host/db"
    },
    {
      "key": "OPENAI_KEY",
      "description": "openai api key",
      "example": "sk-..."
    }
  ]
}
```

**Recipients are public keys only.** No names or emails in the header. Name↔pubkey mappings live inside the encrypted shared blob where only authorized recipients can see them.

**Schema is intentionally minimal.** Key names and descriptions should not themselves be sensitive.

### Shared Age Blob

Encrypted to all recipients. Contains actual secret values, recipient name mappings, per-key access metadata (v2), and the personal blob manifest.

```json
{
  "values": {
    "DATABASE_URL": "postgres://prod:pass@host/db",
    "OPENAI_KEY": "sk-abc123..."
  },
  "recipients": {
    "age1abc...": "mickey@example.com",
    "age1xyz...": "alice@example.com"
  },
  "per_key_access": {
    "DATABASE_URL": ["age1abc...", "age1xyz..."],
    "OPENAI_KEY": ["age1abc..."]
  },
  "personal_blobs": {
    "age1abc...": "sha256:def456...",
    "age1xyz...": "sha256:ghi789..."
  }
}
```

`recipients` maps public keys to display names. This is the only place names are stored — they never appear in the plaintext header.

`per_key_access` is stored in v1 but not enforced until v2. All recipients can decrypt all shared values in v1.

`personal_blobs` maps recipient pubkey to the SHA256 hash of their personal blob for integrity verification.

### Personal Age Blobs

Each personal blob is encrypted only to that recipient's public key. They appear in the file as anonymous age payloads — there is no plaintext label indicating who they belong to. Only someone who can decrypt the shared blob knows the manifest, and only the key owner can decrypt their personal blob.

```json
{
  "values": {
    "DATABASE_URL": "postgres://localhost/dev",
    "MY_PERSONAL_KEY": "abc123"
  }
}
```

Personal values override shared values during `murk export`.

### Integrity Chain

```
plaintext header
  └── shared_blob_hash ──→ shared blob
                              └── personal_blobs[1] ──→ personal blob 1
                              └── personal_blobs[2] ──→ personal blob 2
```

Tampering with any blob is detectable at the appropriate level.

---

## Commands

### `murk init [--vault NAME]`

Interactive setup. Prompts for:

- Name or email (display label, stored inside encrypted blob only)
- Vault filename (defaults to `.murk`)

Then:

1. Generates an age keypair via BIP39 (24-word mnemonic encodes the key directly)
2. Appends `MURK_KEY=...` to `.env` (creates `.env` if missing, alerts and confirms if `MURK_KEY` already present)
3. Creates empty `.murk` vault with user's pubkey as first recipient
4. Prints BIP39 24-word recovery phrase to stdout with a warning

```
$ murk init
Enter your name or email: mickey@example.com
Enter vault name [.murk]:
Generating keypair...
Writing MURK_KEY to .env...

⚠  RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:
witch collapse practice feed shame open despair creek
road again ice least fiction coyote partial album
fury mirror essay cigar approve taxi coral pelican

Vault initialized. Added as recipient.
Next: murk add KEY VALUE
```

---

### `murk add KEY VALUE [--private] [--vault NAME]`

Adds or updates a secret. Without `--private`, writes to the shared blob. With `--private`, writes to your personal blob only.

If no description exists for the key, prints a nudge:

```
⚠  No description set. Run: murk describe DATABASE_URL "your description"
```

---

### `murk rm KEY [--vault NAME]`

Removes a key from the shared blob. Prints `removed KEY` to stderr. No confirmation prompt — git is your safety net.

---

### `murk get KEY [--vault NAME]`

Prints a single decrypted value to stdout. Exits with code 1 and prints to stderr if key not found. Useful for scripting:

```bash
DB=$(murk get DATABASE_URL)
```

---

### `murk ls [--vault NAME]`

Lists key names only. No values. One per line. Useful for scripting and quick reference.

---

### `murk describe KEY "description" [--example "..."] [--vault NAME]`

Adds or updates the description and optional example for a key in the plaintext header. Does not touch the encrypted blob.

```
murk describe DATABASE_URL "postgres connection string" --example "postgres://user:pass@host/db"
```

---

### `murk export [--vault NAME]`

Decrypts the vault and prints all key/value pairs as shell export statements. Personal overrides take precedence over shared values.

Stdout only — clean for `eval`. All errors go to stderr.

**Primary usage via direnv:**

```bash
# .envrc
eval $(murk export)
```

---

### `murk info [--vault NAME]`

Prints the public schema. Works without `MURK_KEY`. Shows key names, descriptions, and examples.

With a valid `MURK_KEY`, also shows per-key recipient access:

```
$ murk info
DATABASE_URL  postgres connection string  (e.g. postgres://user:pass@host/db)  [mickey, alice]
OPENAI_KEY    openai api key              (e.g. sk-...)                         [mickey]
```

Without `MURK_KEY`:

```
DATABASE_URL  postgres connection string  (e.g. postgres://user:pass@host/db)
OPENAI_KEY    openai api key              (e.g. sk-...)
```

---

### `murk recover`

Re-derives and prints the BIP39 24-word recovery phrase from the current `MURK_KEY`. Requires `MURK_KEY` to be set.

Recovery words are a BIP39 encoding of the private key itself — not a separate keypair. Entering the words reconstructs the exact same `MURK_KEY`.

---

### `murk authorize PUBKEY [NAME] [--vault NAME]`

Adds a new recipient to the vault. Re-encrypts the shared blob to include the new public key. Only existing recipients can authorize new ones. The optional name is stored as a display label inside the encrypted shared blob.

```
murk authorize age1xyz... alice@example.com
```

---

### `murk revoke RECIPIENT [--vault NAME]`

Removes a recipient by public key or display name. If a name is given, murk decrypts the shared blob to resolve it to a pubkey. Re-encrypts the shared blob without their key. Removes their personal blob from the file.

```
$ murk revoke alice@example.com
Removed alice@example.com (age1xyz...) from recipients. Vault re-encrypted.
⚠  This recipient can still decrypt previous versions from git history.
   Rotate any sensitive credentials to complete revocation.
```

---

### `murk recipients [--vault NAME]`

Lists all recipient public keys. With `MURK_KEY`, also shows display names from the encrypted blob and marks the current user.

```
age1abc...  mickey@example.com  (you)
age1xyz...  alice@example.com
```

Without `MURK_KEY` (pubkeys are in the plaintext header):

```
age1abc...
age1xyz...
```

---

## Multi-User Workflow

```bash
# Alice initializes
murk init

# Alice adds secrets
murk add DATABASE_URL postgres://prod/db
murk describe DATABASE_URL "production postgres"

# Bob generates a keypair (on his machine)
murk init  # creates his own .env with MURK_KEY

# Bob shares his public key with Alice
# Alice authorizes Bob
murk authorize age1bob... bob@example.com

# Bob adds MURK_KEY to his .env
# Bob can now decrypt
murk export

# Bob adds a personal override
murk add DATABASE_URL postgres://localhost/dev --private

# Bob's export gives him his local DB, shared secrets for everything else
eval $(murk export)
```

---

## Security Model

**What murk protects against:**

- Repo leaks — `.murk` is safe to commit, useless without a private key
- Accidental secret exposure — plaintext `.env` never committed if `.gitignore` is set correctly
- Insider read access — personal blobs are encrypted only to their owner

**What murk does not protect against:**

- A compromised machine with `MURK_KEY` present
- Historical access after revocation — old `.murk` versions remain in git history. Always rotate credentials when revoking.
- Fine-grained audit logging — use a secrets server for regulated environments

**Treat `MURK_KEY` like your SSH private key.** Never commit it. Never share it.

**Revocation is incomplete without credential rotation.** murk will always tell you this.

### Scope

murk is appropriate for dev tooling and small teams. It is not designed for regulated environments handling PII, financial data, or healthcare data where audit trails, key management infrastructure, and provable access controls are required.

Most teams are sharing `.env` files over Slack, email, or shared docs. Encrypted credentials in a repo is a meaningful improvement over that baseline.

---

## Direnv Integration

```bash
# .envrc
eval $(murk export)
```

---

## V1 Scope

- All commands above
- Single shared blob + per-identity personal blobs
- Per-key recipient metadata stored but not enforced
- BIP39 recovery
- direnv integration

## V2 Planned

- Per-key recipient enforcement (multiple blobs per key)
- `murk verify` + `.murk.sha256` integrity checking
- `murk grant KEY NAME` / `murk ungrant KEY NAME`
- `murk rotate` for credential rotation workflow

---

## Crate Dependencies (planned)

- `age` / `rage` — encryption
- `bip39` — recovery phrase
- `serde` / `serde_json` — serialization
- `clap` — CLI
- `sha2` — hashing
