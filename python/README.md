# murk-secrets

[![PyPI](https://img.shields.io/pypi/v/murk-secrets)](https://pypi.org/project/murk-secrets/)

Python bindings for [murk](https://github.com/iicky/murk) — an encrypted secrets manager for developers.

murk stores encrypted secrets in a single `.murk` file safe to commit to git. This package lets Python apps read those secrets at runtime.

## Prerequisites

You need the [murk CLI](https://github.com/iicky/murk) to create and manage vaults. This package only reads them.

```bash
# Install the CLI first
brew tap iicky/murk && brew install murk

# Initialize a vault and add secrets
murk init
murk add DATABASE_URL
murk add API_KEY
```

Then add the Python package to your project:

```bash
pip install murk-secrets
```

## Quick start

```bash
# Load your key (created by murk init)
source .env
```

```python
import murk

# Load the vault (reads MURK_KEY from environment)
vault = murk.load()

# Get a single secret
db_url = vault.get("DATABASE_URL")

# Get all secrets as a dict
secrets = vault.export()

# Dict-style access
api_key = vault["API_KEY"]
```

## API

### `murk.load(vault_path=".murk") -> Vault`

Load and decrypt a murk vault. Reads `MURK_KEY` or `MURK_KEY_FILE` from the environment.

### `murk.get(key, vault_path=".murk") -> str | None`

One-liner: load the vault and get a single value.

### `murk.export_all(vault_path=".murk") -> dict[str, str]`

One-liner: load the vault and export all secrets as a dict.

### `murk.has_key() -> bool`

Check if a `MURK_KEY` is available in the environment.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `str \| None` | Get a single decrypted value |
| `vault.export()` | `dict[str, str]` | All secrets as a dict |
| `vault.keys()` | `list[str]` | List of key names |
| `vault[key]` | `str` | Dict-style access (raises on missing key) |
| `key in vault` | `bool` | Check if a key exists |
| `len(vault)` | `int` | Number of secrets |

Scoped (per-user) overrides are applied automatically — if you have a scoped value for a key, it takes priority over the shared value.

## Environment

Set one of:
- `MURK_KEY` — your age secret key directly
- `MURK_KEY_FILE` — path to your key file (created by `murk init`)

The easiest setup is `source .env` in your project directory after running `murk init`.

## Requirements

- Python >= 3.9
- [murk CLI](https://github.com/iicky/murk) installed (to create and manage vaults)
- A `.murk` vault file in your project (created with `murk init`)
- `MURK_KEY` or `MURK_KEY_FILE` in the environment (created by `murk init`, loaded via `source .env`)

## License

MIT OR Apache-2.0
