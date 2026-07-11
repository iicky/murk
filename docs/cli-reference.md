<!-- Generated from the clap model by `cargo run --features doc-gen --bin gen-docs`. Do not edit by hand; CI checks it. -->

# murk command reference

This document contains the help content for the `murk` command-line program.

**Command Overview:**

* [`murk`↴](#murk)
* [`murk init`↴](#murk-init)
* [`murk env`↴](#murk-env)
* [`murk restore`↴](#murk-restore)
* [`murk recover`↴](#murk-recover)
* [`murk add`↴](#murk-add)
* [`murk generate`↴](#murk-generate)
* [`murk rotate`↴](#murk-rotate)
* [`murk rm`↴](#murk-rm)
* [`murk get`↴](#murk-get)
* [`murk edit`↴](#murk-edit)
* [`murk ls`↴](#murk-ls)
* [`murk export`↴](#murk-export)
* [`murk import`↴](#murk-import)
* [`murk describe`↴](#murk-describe)
* [`murk info`↴](#murk-info)
* [`murk skeleton`↴](#murk-skeleton)
* [`murk exec`↴](#murk-exec)
* [`murk agent`↴](#murk-agent)
* [`murk agent plan`↴](#murk-agent-plan)
* [`murk agent exec`↴](#murk-agent-exec)
* [`murk agent grant`↴](#murk-agent-grant)
* [`murk agent init`↴](#murk-agent-init)
* [`murk agent ls`↴](#murk-agent-ls)
* [`murk agent revoke`↴](#murk-agent-revoke)
* [`murk mcp`↴](#murk-mcp)
* [`murk policy`↴](#murk-policy)
* [`murk policy show`↴](#murk-policy-show)
* [`murk policy set`↴](#murk-policy-set)
* [`murk policy clear`↴](#murk-policy-clear)
* [`murk circle`↴](#murk-circle)
* [`murk circle authorize`↴](#murk-circle-authorize)
* [`murk circle revoke`↴](#murk-circle-revoke)
* [`murk group`↴](#murk-group)
* [`murk group create`↴](#murk-group-create)
* [`murk group ls`↴](#murk-group-ls)
* [`murk group add`↴](#murk-group-add)
* [`murk group rm`↴](#murk-group-rm)
* [`murk verify`↴](#murk-verify)
* [`murk doctor`↴](#murk-doctor)
* [`murk scan`↴](#murk-scan)
* [`murk diff`↴](#murk-diff)
* [`murk setup-merge-driver`↴](#murk-setup-merge-driver)
* [`murk completion`↴](#murk-completion)
* [`murk completion generate`↴](#murk-completion-generate)
* [`murk completion install`↴](#murk-completion-install)

## `murk`

Encrypted secrets manager for developers — one file, age encryption, git-friendly

**Usage:** `murk <COMMAND>`

###### **Subcommands:**

* `init` — Initialize a new vault and generate a keypair
* `env` — Write a .envrc for direnv integration
* `restore` — Restore MURK_KEY from a BIP39 recovery phrase
* `recover` — Re-derive recovery phrase from current MURK_KEY
* `add` — Add or update a secret
* `generate` — Generate a random secret and store it
* `rotate` — Rotate secrets with new values
* `rm` — Remove a secret
* `get` — Get a single decrypted value
* `edit` — Edit secrets in $EDITOR
* `ls` — List all key names
* `export` — Export all secrets as shell export statements
* `import` — Import secrets from a .env file
* `describe` — Add or update a key description
* `info` — Show public schema and key info
* `skeleton` — Export schema-only vault with no secrets or recipients
* `exec` — Run a command with secrets injected as environment variables
* `agent` — Agent-oriented commands (schema-only output for AI agent prompts)
* `mcp` — Run an MCP (Model Context Protocol) stdio server for AI agents
* `policy` — Manage the agent access policy
* `circle` — Manage recipients
* `group` — Manage recipient groups
* `verify` — Verify vault integrity without exporting secrets
* `doctor` — Check the surrounding repo for hygiene issues
* `scan` — Scan files for leaked secret values
* `diff` — Show secret changes vs a git ref
* `setup-merge-driver` — Configure git to use murk's merge driver for .murk files
* `completion` — Generate or install shell completions



## `murk init`

Initialize a new vault and generate a keypair

**Usage:** `murk init [OPTIONS]`

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk env`

Write a .envrc for direnv integration

**Usage:** `murk env [OPTIONS]`

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk restore`

Restore MURK_KEY from a BIP39 recovery phrase

**Usage:** `murk restore`



## `murk recover`

Re-derive recovery phrase from current MURK_KEY

**Usage:** `murk recover`



## `murk add`

Add or update a secret

**Usage:** `murk add [OPTIONS] <KEY>`

###### **Arguments:**

* `<KEY>` — Secret key name

###### **Options:**

* `--desc <DESC>` — Description for this key
* `--group <GROUP>` — Who can read it: a group name, `everyone` (default), or `me`
* `--tag <TAG>` — Tag for grouping (repeatable)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk generate`

Generate a random secret and store it

**Usage:** `murk generate [OPTIONS] <KEY>`

###### **Arguments:**

* `<KEY>` — Secret key name

###### **Options:**

* `--length <LENGTH>` — Length in bytes (default 32)

  Default value: `32`
* `--hex` — Output as hex instead of base64
* `--desc <DESC>` — Description for this key
* `--group <GROUP>` — Who can read it: a group name, `everyone` (default), or `me`
* `--tag <TAG>` — Tag for grouping (repeatable)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk rotate`

Rotate secrets with new values

**Usage:** `murk rotate [OPTIONS] [KEY]`

###### **Arguments:**

* `<KEY>` — Secret key name (omit for --all)

###### **Options:**

* `--all` — Rotate all secrets in the vault
* `--generate` — Generate random values instead of prompting
* `--length <LENGTH>` — Length in bytes for generated values (default 32)

  Default value: `32`
* `--hex` — Output generated values as hex instead of base64
* `--list` — List keys needing rotation instead of rotating (exits 1 if any)
* `--json` — Output the listing as JSON (with --list; always exits 0)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk rm`

Remove a secret

**Usage:** `murk rm [OPTIONS] <KEY>`

###### **Arguments:**

* `<KEY>` — Secret key name

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk get`

Get a single decrypted value

**Usage:** `murk get [OPTIONS] <KEY>`

###### **Arguments:**

* `<KEY>` — Secret key name

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk edit`

Edit secrets in $EDITOR

**Usage:** `murk edit [OPTIONS] [KEY]`

###### **Arguments:**

* `<KEY>` — Edit a single key (omit to edit all)

###### **Options:**

* `--scoped` — Edit scoped overrides instead of shared secrets
* `--group <GROUP>` — Edit values for this group instead of shared secrets
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk ls`

List all key names

**Usage:** `murk ls [OPTIONS]`

###### **Options:**

* `--tag <TAG>` — Filter by tag (repeatable)
* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk export`

Export all secrets as shell export statements

**Usage:** `murk export [OPTIONS]`

###### **Options:**

* `--tag <TAG>` — Filter by tag (repeatable)
* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk import`

Import secrets from a .env file

**Usage:** `murk import [OPTIONS] [FILE]`

###### **Arguments:**

* `<FILE>` — Path to the .env file to import

  Default value: `.env`

###### **Options:**

* `--force` — Overwrite existing secrets without prompting
* `--group <GROUP>` — Assign imported secrets to this group (default: everyone)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk describe`

Add or update a key description

**Usage:** `murk describe [OPTIONS] <KEY> <DESCRIPTION>`

###### **Arguments:**

* `<KEY>` — Secret key name
* `<DESCRIPTION>` — Description text

###### **Options:**

* `--example <EXAMPLE>` — Example value
* `--tag <TAG>` — Tag for grouping (repeatable, replaces existing tags)
* `--rotate-every <DAYS>` — Rotation interval, e.g. `90d` or `90` (days); `never` clears it
* `--expires <DATE>` — Hard expiry date, e.g. `2026-09-01`; `never` clears it
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk info`

Show public schema and key info

**Usage:** `murk info [OPTIONS]`

###### **Options:**

* `--tag <TAG>` — Filter by tag (repeatable)
* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk skeleton`

Export schema-only vault with no secrets or recipients

**Usage:** `murk skeleton [OPTIONS]`

###### **Options:**

* `-o`, `--output <OUTPUT>` — Output file (prints to stdout if omitted)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk exec`

Run a command with secrets injected as environment variables

**Usage:** `murk exec [OPTIONS] <COMMAND>...`

###### **Arguments:**

* `<COMMAND>` — Command and arguments to execute

###### **Options:**

* `--only <ONLY>` — Only inject these specific keys (repeatable)
* `--tag <TAG>` — Filter by tag (repeatable)
* `--clean-env` — Strip inherited environment (only murk secrets + PATH)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk agent`

Agent-oriented commands (schema-only output for AI agent prompts)

**Usage:** `murk agent <COMMAND>`

###### **Subcommands:**

* `plan` — Emit schema-only context safe to paste into an AI agent prompt
* `exec` — Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)
* `grant` — Mint a short-lived ephemeral key that can read only the named secrets
* `init` — One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely
* `ls` — List active agent grants and their TTLs
* `revoke` — Revoke an agent grant and rotate the keys it could read



## `murk agent plan`

Emit schema-only context safe to paste into an AI agent prompt

**Usage:** `murk agent plan [OPTIONS]`

###### **Options:**

* `--tag <TAG>` — Filter by tag (repeatable)
* `--json` — Output as JSON
* `-o`, `--output <OUTPUT>` — Output file (prints to stdout if omitted)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk agent exec`

Run a command with strict agent-safe defaults (clears the inherited environment, strips MURK_KEY, requires --only)

**Usage:** `murk agent exec [OPTIONS] --only <ONLY> <COMMAND>...`

###### **Arguments:**

* `<COMMAND>` — Command and arguments to execute

###### **Options:**

* `--only <ONLY>` — Inject these specific keys (required — agent mode fails closed)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk agent grant`

Mint a short-lived ephemeral key that can read only the named secrets

**Usage:** `murk agent grant [OPTIONS] --name <NAME> --only <ONLY>`

###### **Options:**

* `--name <NAME>` — Grant name (used to revoke it later)
* `--only <ONLY>` — Keys this grant can read (required — fails closed)
* `--ttl <TTL>` — Time to live, e.g. 30m, 2h, 7d (advisory — see `agent revoke`)

  Default value: `2h`
* `--out <OUT>` — Where to write the agent key: a path, or `-` for stdout
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk agent init`

One-shot onboarding: optionally set the agent allow-list, mint a scoped grant, and print how to run the agent safely

**Usage:** `murk agent init [OPTIONS] --name <NAME> --only <ONLY>`

###### **Options:**

* `--name <NAME>` — Grant name (used to revoke it later)
* `--only <ONLY>` — Keys the agent can read (required — fails closed)
* `--allow-tag <ALLOW_TAG>` — Set the agent allow-list to these tags before granting (repeatable)
* `--ttl <TTL>` — Time to live, e.g. 30m, 2h, 7d (advisory — see `agent revoke`)

  Default value: `2h`
* `--out <OUT>` — Where to write the agent key: a path, or `-` for stdout
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk agent ls`

List active agent grants and their TTLs

**Usage:** `murk agent ls [OPTIONS]`

###### **Options:**

* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk agent revoke`

Revoke an agent grant and rotate the keys it could read

**Usage:** `murk agent revoke [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>` — Grant name

###### **Options:**

* `--rotate` — Rotate the keys it could read in the same session
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk mcp`

Run an MCP (Model Context Protocol) stdio server for AI agents

**Usage:** `murk mcp [OPTIONS]`

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`
* `--allow-exec` — Enable the murk_exec tool (run commands with scoped secrets injected). Off by default: it runs arbitrary commands as this user — the injected secrets are grant-scoped, but the command itself is not sandboxed



## `murk policy`

Manage the agent access policy

**Usage:** `murk policy <COMMAND>`

###### **Subcommands:**

* `show` — Show the agent access policy (works without a key)
* `set` — Set the agent allow-list: agents may only receive secrets carrying one of these tags
* `clear` — Remove the policy — agent mode becomes unrestricted again



## `murk policy show`

Show the agent access policy (works without a key)

**Usage:** `murk policy show [OPTIONS]`

###### **Options:**

* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk policy set`

Set the agent allow-list: agents may only receive secrets carrying one of these tags

**Usage:** `murk policy set [OPTIONS] --allow-tag <ALLOW_TAG>`

###### **Options:**

* `--allow-tag <ALLOW_TAG>` — Tag agents are allowed to receive (repeatable, required)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk policy clear`

Remove the policy — agent mode becomes unrestricted again

**Usage:** `murk policy clear [OPTIONS]`

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk circle`

Manage recipients

**Usage:** `murk circle [OPTIONS] [COMMAND]`

###### **Subcommands:**

* `authorize` — Add a recipient to the vault
* `revoke` — Remove a recipient from the vault

###### **Options:**

* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk circle authorize`

Add a recipient to the vault

**Usage:** `murk circle authorize [OPTIONS] <PUBKEY>`

###### **Arguments:**

* `<PUBKEY>` — Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username

###### **Options:**

* `--name <NAME>` — Display name for this recipient
* `--group <GROUP>` — Also add the new recipient to this group
* `--force` — Accept changed GitHub keys without confirmation
* `--allow-ssh-rsa` — Allow ssh-rsa recipients (rejected by default — use ed25519)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk circle revoke`

Remove a recipient from the vault

**Usage:** `murk circle revoke [OPTIONS] <RECIPIENT>`

###### **Arguments:**

* `<RECIPIENT>` — Recipient pubkey or display name

###### **Options:**

* `--rotate` — Rotate the secrets they had access to in the same session
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk group`

Manage recipient groups

**Usage:** `murk group <COMMAND>`

###### **Subcommands:**

* `create` — Create a new recipient group (you become its first member)
* `ls` — List groups and their members
* `add` — Add a member to a group
* `rm` — Remove a member from a group, or delete the group entirely



## `murk group create`

Create a new recipient group (you become its first member)

**Usage:** `murk group create [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>` — Group name

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk group ls`

List groups and their members

**Usage:** `murk group ls [OPTIONS]`

###### **Options:**

* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk group add`

Add a member to a group

**Usage:** `murk group add [OPTIONS] --member <MEMBER> <NAME>`

###### **Arguments:**

* `<NAME>` — Group name

###### **Options:**

* `--member <MEMBER>` — Recipient pubkey or display name to add
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk group rm`

Remove a member from a group, or delete the group entirely

**Usage:** `murk group rm [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>` — Group name

###### **Options:**

* `--member <MEMBER>` — Recipient pubkey or display name to remove (omit to delete the group)
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk verify`

Verify vault integrity without exporting secrets

**Usage:** `murk verify [OPTIONS]`

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk doctor`

Check the surrounding repo for hygiene issues

**Usage:** `murk doctor [OPTIONS]`

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk scan`

Scan files for leaked secret values

**Usage:** `murk scan [OPTIONS] [PATHS]...`

###### **Arguments:**

* `<PATHS>` — Files or directories to scan (defaults to current directory)

###### **Options:**

* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk diff`

Show secret changes vs a git ref

**Usage:** `murk diff [OPTIONS] [GIT_REF]`

###### **Arguments:**

* `<GIT_REF>` — Git ref to compare against

  Default value: `HEAD`

###### **Options:**

* `--show-values` — Show actual values (not just key names)
* `--json` — Output as JSON
* `--vault <VAULT>` — Vault filename

  Default value: `.murk`



## `murk setup-merge-driver`

Configure git to use murk's merge driver for .murk files

**Usage:** `murk setup-merge-driver`



## `murk completion`

Generate or install shell completions

**Usage:** `murk completion <COMMAND>`

###### **Subcommands:**

* `generate` — Print completions to stdout
* `install` — Install completions to the standard path



## `murk completion generate`

Print completions to stdout

**Usage:** `murk completion generate <SHELL>`

###### **Arguments:**

* `<SHELL>` — Shell to generate completions for

  Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`




## `murk completion install`

Install completions to the standard path

**Usage:** `murk completion install <SHELL>`

###### **Arguments:**

* `<SHELL>` — Shell to install completions for

  Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`




