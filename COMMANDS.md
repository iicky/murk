# Command Reference

Current output for every murk command. This is a snapshot for UI polish work.

## Setup

### `murk init`

New vault:
```
Generating keypair...
Writing MURK_KEY to .env...

RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:
word1 word2 word3 ... word24

MURK_KEY saved to .env — do not commit this file.

Vault initialized. Added alice as recipient.
Next: murk add KEY
```

Existing vault, already authorized:
```
myproject already exists
authorized  age1abc...xyz  alice
```

Existing vault, not authorized:
```
myproject already exists
not authorized — share your public key to get added:
age1abc...xyz
```

### `murk recover`

```
word1 word2 word3 ... word24
```

Error (SSH key):
```
error: recovery phrases are for age keys only. SSH keys are managed by your SSH agent — back up ~/.ssh instead
```

### `murk restore [PHRASE]`

Interactive prompt:
```
Enter 24-word recovery phrase: ••••
```

Output:
```
AGE-SECRET-KEY-1...
```

## Secrets

### `murk add KEY [--desc DESC] [--scoped] [--tag TAG]`

Interactive prompt:
```
value for DATABASE_URL:
```

Output:
```
added DATABASE_URL
```

With hint:
```
added DATABASE_URL
hint: no description set. Run: murk describe DATABASE_URL "your description"
```

### `murk rm KEY`

```
removed DATABASE_URL
```

### `murk get KEY`

```
postgres://prod:secret@db.example.com/app
```

Error:
```
error: key not found: MISSING_KEY. Run murk ls to see available keys
```

### `murk ls [--tag TAG]`

```
API_KEY
DATABASE_URL
STRIPE_SECRET
```

### `murk import [FILE]`

```
  + API_KEY
  + DATABASE_URL
  + STRIPE_SECRET
imported 3 secrets
```

## Metadata

### `murk describe KEY "description" [--example VALUE] [--tag TAG]`

Silent on success.

### `murk info [--tag TAG]`

```
vault: myproject
codename: silent-ocean
repo: https://github.com/org/repo
created: 2025-01-15
recipients: 2 recipients

DATABASE_URL  Production database  (e.g. postgres://localhost/dev)  [backend]
API_KEY       OpenAI API key
STRIPE_SECRET Stripe secret key    (e.g. sk_test_...)               [billing]
```

No secrets:
```
no keys in vault
```

## Export

### `murk export [--tag TAG]`

```
export API_KEY='sk-proj-abc123def456'
export DATABASE_URL='postgres://prod:secret@db.example.com/app'
export STRIPE_SECRET='sk_live_xyz789'
```

### `murk exec [--tag TAG] -- CMD...`

Replaces process. No murk output — runs the command directly.

### `murk env`

```
ok: created .envrc. Run: direnv allow
```

Or:
```
ok: appended to .envrc. Run: direnv allow
```

Or:
```
ok: .envrc already contains murk export
```

## Recipients

### `murk authorize PUBKEY [NAME]`

Single key:
```
authorized alice
```

GitHub username:
```
authorized iicky@github (2 ssh-ed25519 keys)
```

Already authorized:
```
ok: all 2 SSH keys for iicky@github are already authorized
```

### `murk revoke RECIPIENT`

```
removed carol from recipients. Vault re-encrypted.

warning: carol had access to these secrets (rotate them):
  - API_KEY
  - DATABASE_URL
  - STRIPE_SECRET

This recipient can still decrypt previous versions from git history.
```

### `murk recipients`

Without MURK_KEY:
```
age1abc...fullpubkey...xyz
ssh-ed25519 AAAA...fullkey
```

With MURK_KEY (single key per person):
```
age1abc...fullpubkey...xyz  alice  (you)
age1def...fullpubkey...uvw  bob
```

With MURK_KEY (multi-key GitHub recipient):
```
age1abc...fullpubkey...xyz  alice  (you)
iicky@github  (2 keys)
  ssh-ed25519  ssh-ed25519 AAAA...fullkey1
  ssh-ed25519  ssh-ed25519 AAAA...fullkey2
```

## Git

### `murk diff [GIT_REF] [--show-values]`

Key names only:
```
+ NEW_KEY
- REMOVED_KEY
~ CHANGED_KEY
```

With `--show-values`:
```
+ NEW_KEY = new_value
- REMOVED_KEY = old_value
~ CHANGED_KEY: old_value -> new_value
```

No changes:
```
no changes
```

### `murk setup-merge-driver`

```
ok: created .gitattributes
ok: git merge driver configured
Commit .gitattributes so all collaborators use the merge driver.
```

### `murk merge-driver BASE OURS THEIRS`

Called by git, not directly. Clean merge:
```
ok: vault merged cleanly
```

Conflicts:
```
conflict: 2 conflicts:
  - DATABASE_URL — both sides modified
  - API_KEY — both sides modified
```
