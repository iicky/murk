# @iicky/murk-secrets

[![npm](https://img.shields.io/npm/v/@iicky/murk-secrets)](https://www.npmjs.com/package/@iicky/murk-secrets)

Node.js/TypeScript bindings for [murk](https://github.com/iicky/murk) — an encrypted secrets manager for developers.

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

Then add the Node package to your project:

```bash
npm install @iicky/murk-secrets
```

## Quick start

```bash
# Load your key (created by murk init)
source .env
```

```typescript
import { load, get, exportAll } from '@iicky/murk-secrets'

// Load the vault (reads MURK_KEY from environment)
const vault = load()

// Get a single secret
const dbUrl = vault.get('DATABASE_URL')

// Get all secrets as an object
const secrets = vault.export()

// One-liners
get('DATABASE_URL')
exportAll()
```

## API

### `load(vaultPath?: string): Vault`

Load and decrypt a murk vault. Reads `MURK_KEY` or `MURK_KEY_FILE` from the environment.

### `get(key: string, vaultPath?: string): string | null`

One-liner: load the vault and get a single value.

### `exportAll(vaultPath?: string): Record<string, string>`

One-liner: load the vault and export all secrets as an object.

### `hasKey(): boolean`

Check if a `MURK_KEY` is available in the environment.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `string \| null` | Get a single decrypted value |
| `vault.export()` | `Record<string, string>` | All secrets as an object |
| `vault.keys()` | `string[]` | List of key names |
| `vault.has(key)` | `boolean` | Check if a key exists |
| `vault.length` | `number` | Number of secrets |

Scoped (per-user) overrides are applied automatically — if you have a scoped value for a key, it takes priority over the shared value.

## Requirements

- Node.js >= 16
- [murk CLI](https://github.com/iicky/murk) installed (to create and manage vaults)
- A `.murk` vault file in your project (created with `murk init`)
- `MURK_KEY` or `MURK_KEY_FILE` in the environment (created by `murk init`, loaded via `source .env`)

## License

MIT OR Apache-2.0
