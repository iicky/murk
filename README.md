# murk

[![CI](https://github.com/iicky/murk/actions/workflows/ci.yml/badge.svg)](https://github.com/iicky/murk/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/iicky/murk/graph/badge.svg)](https://codecov.io/gh/iicky/murk)
[![Crates.io](https://img.shields.io/crates/v/murk-cli)](https://crates.io/crates/murk-cli)
[![License](https://img.shields.io/crates/l/murk-cli)](LICENSE-MIT)

Encrypted secrets manager for developers. One key unlocks everything.

murk stores encrypted secrets in a single `.murk` file that's safe to commit to git. It uses [age](https://age-encryption.org/) encryption, works with [direnv](https://direnv.net/), and supports teams — all in one binary with no runtime dependencies.

<p align="center">
  <img src="https://raw.githubusercontent.com/iicky/murk/demo/hero.gif" alt="murk demo" width="900">
</p>

## Why

Most teams share `.env` files over Slack. That's bad. Tools like SOPS and Vault exist but they're complex, require cloud setup, or pull in runtimes you don't want.

murk is simple: one key in your `.env`, one encrypted file in your repo, done.

## Quick start

```bash
cargo install murk-cli

# Initialize — generates your key and recovery phrase
murk init

# Add secrets (prompts for value, hidden input)
murk add DATABASE_URL
murk add OPENAI_KEY

# Use with direnv
echo 'eval $(murk export)' > .envrc
```

## How it works

Your `.murk` file has a plaintext header (key names, descriptions — no values) and encrypted blobs. Anyone can see what secrets exist via `murk info`. Only recipients with a valid `MURK_KEY` can see values.

```bash
murk info           # Public schema — works without a key
murk ls             # List key names
murk get KEY        # Print a single value
murk export         # Shell export statements
```

## Shared secrets vs scoped secrets

murk has two layers of encryption inside the `.murk` file:

**Shared secrets** (the murk) are encrypted to all recipients. When you run `murk add KEY`, every authorized team member can decrypt it. This is where production credentials, API keys, and other team-wide secrets live.

**Scoped secrets** (motes) are encrypted to only your key. When you run `murk add KEY --scoped`, the value is stored in a personal blob that no one else can read. During `murk export`, scoped values override shared ones — so you can use a local database URL while the rest of the team uses production.

```bash
# Shared — everyone sees this
murk add DATABASE_URL

# Scoped — only you see this, overrides the shared value during export
murk add DATABASE_URL --scoped

# Or pipe for scripting
echo "postgres://prod:pass@host/db" | murk add DATABASE_URL
```

## Teams

```bash
# Alice sets up the vault
murk init
echo "postgres://prod/db" | murk add DATABASE_URL

# Bob generates his own key
murk init

# Alice adds Bob as a recipient
murk authorize age1bob... bob@example.com

# Bob can now decrypt
murk export

# Bob overrides a value for local dev
echo "postgres://localhost/dev" | murk add DATABASE_URL --scoped
```

<p align="center">
  <img src="https://raw.githubusercontent.com/iicky/murk/demo/team.gif" alt="murk team demo" width="900">
</p>

## Offboarding

When someone leaves, revoke their access and rotate the secrets:

```bash
murk revoke carol
murk add DATABASE_URL    # re-encrypt with new value
murk add API_KEY
git commit -am "revoke carol, rotate secrets" && git push
```

<p align="center">
  <img src="https://raw.githubusercontent.com/iicky/murk/demo/offboard.gif" alt="murk offboarding demo" width="900">
</p>

## Recovery

Your key is a BIP39 mnemonic. `murk init` prints 24 recovery words — write them down.

```bash
# Lost your key? Recover it from the phrase
murk restore "witch collapse practice feed shame open despair creek ..."
```

## Commands

| Command | Description |
|---------|-------------|
| `murk init` | Generate keypair and create vault |
| `murk add KEY [--scoped]` | Add or update a secret (prompts for value) |
| `murk rm KEY` | Remove a secret |
| `murk get KEY` | Print a single decrypted value |
| `murk ls` | List key names |
| `murk export` | Print all secrets as shell exports |
| `murk import [FILE]` | Import secrets from a .env file |
| `murk describe KEY "..."` | Set description for a key |
| `murk info` | Show public schema (no key required) |
| `murk authorize PUBKEY [NAME]` | Add a recipient |
| `murk revoke RECIPIENT` | Remove a recipient |
| `murk recipients` | List recipients |
| `murk restore [PHRASE]` | Recover key from BIP39 phrase |
| `murk recover` | Show recovery phrase for current key |

## Design

- **age does the crypto** — no custom cryptography
- **Git is the audit trail** — murk doesn't replicate what git does
- **Header is public, blob is private** — key names are visible, values are not
- **Explicit over magic** — never silently overwrites or destroys data

See [SPEC.md](SPEC.md) for the full specification.

## License

MIT OR Apache-2.0
