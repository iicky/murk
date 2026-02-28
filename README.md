# murk

Encrypted secrets manager for developers. One key unlocks everything.

murk stores encrypted secrets in a single `.murk` file that's safe to commit to git. It uses [age](https://age-encryption.org/) encryption, works with [direnv](https://direnv.net/), and supports teams — all in one binary with no runtime dependencies.

## Why

Most teams share `.env` files over Slack. That's bad. Tools like SOPS and Vault exist but they're complex, require cloud setup, or pull in runtimes you don't want.

murk is simple: one key in your `.env`, one encrypted file in your repo, done.

## Quick start

```bash
cargo install murk

# Initialize — generates your key and recovery phrase
murk init

# Add secrets
murk add DATABASE_URL postgres://prod:pass@host/db
murk add OPENAI_KEY sk-abc123

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

## Teams

```bash
# Alice sets up the vault
murk init
murk add DATABASE_URL postgres://prod/db

# Bob generates his own key
murk init

# Alice adds Bob as a recipient
murk authorize age1bob... bob@example.com

# Bob can now decrypt
murk export

# Bob overrides a value for local dev
murk add DATABASE_URL postgres://localhost/dev --private
```

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
| `murk add KEY VALUE` | Add or update a secret |
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
