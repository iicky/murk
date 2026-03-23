# murk

[![CI](https://github.com/iicky/murk/actions/workflows/ci.yml/badge.svg)](https://github.com/iicky/murk/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/iicky/murk/graph/badge.svg)](https://codecov.io/gh/iicky/murk)
[![Crates.io](https://img.shields.io/crates/v/murk-cli)](https://crates.io/crates/murk-cli)
[![License](https://img.shields.io/crates/l/murk-cli)](LICENSE-MIT)

Encrypted secrets manager for developers. One key unlocks everything.

murk stores encrypted secrets in a single `.murk` file that's safe to commit to git. It uses [age](https://age-encryption.org/) encryption, works with [direnv](https://direnv.net/), and supports teams — all in one binary with no runtime dependencies.

> murk is pre-1.0 and has not been independently audited. Use good judgment with production secrets.

<p align="center">
  <img src="https://raw.githubusercontent.com/iicky/murk/demo/hero.gif" alt="murk demo" width="900">
</p>

## Why

Most teams share `.env` files over Slack. That's bad. Tools like SOPS and Vault exist but they're complex, require cloud setup, or pull in runtimes you don't want.

murk is simple: one key in your `.env`, one encrypted file in your repo, done.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/iicky/murk/main/install.sh | sh
```

Or via Homebrew:

```bash
brew tap iicky/murk && brew install murk
```

Or via Cargo (requires [Rust toolchain](https://rustup.rs)):

```bash
cargo install murk-cli
```

Pre-built binaries are available for Linux (x86_64, aarch64, armv7), macOS (x86_64, Apple Silicon), and Windows on the [releases page](https://github.com/iicky/murk/releases). Binary releases are [attested](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) and can be verified with `gh attestation verify murk-* --owner iicky`.

## Quick start

```bash
# Initialize — generates your key and recovery phrase
murk init

# Add secrets (prompts for value, hidden input)
murk add DATABASE_URL
murk add OPENAI_KEY

# Use with direnv
echo 'eval $(murk export)' > .envrc
```

## How it works

Your `.murk` file has a plaintext header (key names, descriptions — no values) and encrypted values. Anyone can see what secrets exist via `murk info`. Only recipients with a valid `MURK_KEY` can see values.

```bash
murk info           # Public schema — works without a key
murk ls             # List key names
murk get KEY        # Print a single value
murk export         # Shell export statements
```

## Shared secrets vs scoped secrets

murk has two layers of encryption inside the `.murk` file:

**Shared secrets** (the murk) are encrypted to all recipients. When you run `murk add KEY`, every authorized team member can decrypt it. This is where production credentials, API keys, and other team-wide secrets live.

**Scoped secrets** (motes) are encrypted to only your key. When you run `murk add KEY --scoped`, the value is encrypted to only your key in the vault. During `murk export`, scoped values override shared ones — so you can use a local database URL while the rest of the team uses production.

```bash
# Shared — everyone sees this (prompts for value, hidden input)
murk add DATABASE_URL

# Scoped — only you see this, overrides the shared value during export
murk add DATABASE_URL --scoped

# Or pipe for scripting (use a command that doesn't leak to shell history)
pbpaste | murk add DATABASE_URL
```

## Teams

```bash
# Alice sets up the vault
murk init
murk add DATABASE_URL

# Bob generates his own key
murk init

# Alice adds Bob as a recipient
murk circle authorize age1bob... --name bob@example.com

# Bob can now decrypt
murk export

# Bob overrides a value for local dev
murk add DATABASE_URL --scoped
```

<p align="center">
  <img src="https://raw.githubusercontent.com/iicky/murk/demo/team.gif" alt="murk team demo" width="900">
</p>

## Offboarding

When someone leaves, revoke their access and rotate the secrets:

```bash
murk circle revoke carol
murk add DATABASE_URL    # prompts for new value
murk add API_KEY
git commit -am "revoke carol, rotate secrets" && git push
```

<p align="center">
  <img src="https://raw.githubusercontent.com/iicky/murk/demo/offboard.gif" alt="murk offboarding demo" width="900">
</p>

## CI/CD

Use [murk-action](https://github.com/iicky/murk-action) to decrypt secrets in GitHub Actions workflows:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: iicky/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # all vault secrets are now in the environment
```

Store your `MURK_KEY` as a GitHub Actions secret. All decrypted values are masked in logs.

## Recovery

Your key is a BIP39 mnemonic. `murk init` prints 24 recovery words — write them down.

```bash
# Lost your key? Recover it (prompts for phrase, hidden input)
murk restore
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
| `murk circle` | List recipients |
| `murk circle authorize PUBKEY [--name NAME]` | Add a recipient |
| `murk circle revoke RECIPIENT` | Remove a recipient |
| `murk restore` | Recover key from BIP39 phrase |
| `murk recover` | Show recovery phrase for current key |

## Design

- **age does the crypto** — no custom cryptography
- **Git is the audit trail** — murk doesn't replicate what git does
- **Header is public, values are private** — key names are visible, values are not
- **Explicit over magic** — never silently overwrites or destroys data

See [SPEC.md](SPEC.md) for the full specification.

## Security notes

**Shell history** — `murk add` and `murk restore` prompt interactively with hidden input. Prefer these over passing secrets as arguments or via `echo`, which can leak to shell history. When piping from scripts, use commands that don't record to history (e.g. `pbpaste | murk add KEY` or reading from a file).

**Key names are plaintext** — the `.murk` header exposes key names (e.g. `STRIPE_SECRET_KEY`, `DATABASE_URL`) so that `murk info` works without a key and git diffs stay readable. Only values are encrypted. If your threat model requires hiding what services you use, this is a trade-off to be aware of.

**Access control is advisory** — any authorized recipient can decrypt all shared secrets. Per-key access metadata in the schema is cosmetic and not enforced cryptographically. If a recipient has `MURK_KEY` and is in the recipient list, they can read everything in the shared layer. Use scoped secrets (motes) for values that should stay private to one recipient.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model.

## License

MIT OR Apache-2.0
