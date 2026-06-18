# Using murk with AI agents

AI coding agents need secrets — API keys, database URLs, service tokens. The common pattern is pasting them into `.env` files or chat prompts. Both are bad: prompts get logged, `.env` files get committed, and there's no way to revoke access when the session ends.

murk gives agents access to secrets without exposing them in plaintext.

## Rules

1. **Never paste secrets into prompts.** Agent conversations are logged, cached, and sometimes sent to third-party APIs. Once a secret is in a prompt, assume it's leaked.

2. **Never give agents your `MURK_KEY`.** The key is your identity. If an agent has it, it can decrypt everything in the vault — and you can't revoke it without re-keying.

3. **Use `murk exec` to inject secrets.** Instead of exporting secrets to the shell, run agent commands through `murk exec` so secrets exist only in the subprocess environment:
   ```bash
   murk exec -- python deploy.py
   murk exec -- npm run migrate
   ```

   When the agent itself is invoking the command, use `murk agent exec`. It requires explicit `--only` keys, clears the inherited environment, and strips `MURK_KEY` — so the run can only see the secrets you named:
   ```bash
   murk agent exec --only DATABASE_URL -- npm test
   murk agent exec --only DATABASE_URL --only PG_PASSWORD -- ./migrate.sh
   murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
   ```

4. **Use `murk agent plan` for schema prompting.** Agents don't need secret values to understand what's available. `agent plan` emits key names, descriptions, examples, and tags as text or JSON — no decryption, no `MURK_KEY`, no recipient metadata:
   ```bash
   murk agent plan            # human-readable
   murk agent plan --json     # machine-readable
   murk agent plan --tag db   # filter by tag
   ```
   Paste the output into agent system prompts so they know what env vars exist and how to reference them, without ever seeing the values.

   Reach for `murk info` when you want a fuller picture (recipients, your key source, private overrides). Reach for `murk skeleton` when you want a distributable vault file shaped like the real one but with `recipients` / `secrets` / `meta` blanked.

## Short-lived agent grants

`murk agent exec` is the safest pattern: the agent's command gets secret *values* in its environment and never sees a key. Reach for a **grant** when the agent has to run `murk` itself over a session — for example a long-running agent that calls `murk get` as it works.

`murk agent grant` mints a fresh ephemeral age identity and gives it read access to exactly the keys you name — never your `MURK_KEY`:

```bash
murk agent grant --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent grant --name codex --only DATABASE_URL --only PG_PASSWORD --ttl 30m
```

It writes the agent key to `~/.config/murk/agent-keys/<vault-hash>-<name>` (or `--out PATH`, or `--out -` to stream it to stdout) and prints how to use it. Run the agent with that key and `MURK_STRICT=1` so it can't fall back to your stored key:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_STRICT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

The granted key reads only its keys — anything else returns "key not found". It is excluded from the shared layer entirely.

List and revoke grants:

```bash
murk agent ls                       # name, scope, TTL status
murk agent revoke codex --rotate    # remove the grant and rotate its keys
```

Three things to keep in mind:

- **The TTL is advisory.** age keys can't self-destruct, and old vault versions stay readable in git, so a leaked grant key works until you `agent revoke` and rotate. The TTL tells you *when* to revoke; `agent ls` flags expired grants. Revoke + rotate is the real close.
- **The key is a bearer credential.** Whoever holds the key file has the access. Treat it like the secret it unlocks.
- **Real isolation is the OS's job.** An agent running as you, with read access to your home directory, can read `~/.config/murk/keys` directly and bypass murk. `MURK_STRICT` stops murk from *handing over* your key, but for true containment run the agent in a sandbox, container, or under a separate user that can't read your key directory.

## Restricting which secrets agents can touch

Tag your secrets and set an allow-list, and murk will refuse to inject or grant anything outside it in agent mode:

```bash
murk describe DATABASE_URL "..." --tag agents   # tag the agent-usable ones
murk policy set --allow-tag agents              # default-deny everything else
```

Now `agent exec` and `agent grant` only work for keys tagged `agents`; asking for an untagged or production key fails closed with a clear error — there's no override flag, so a misbehaving agent can't talk its way past it. `agents` is just an example tag; use whatever tags fit your vault (`dev`, `ci`, ...). The policy lives in the vault header (MAC-covered, readable with `murk policy show` even without a key) so it travels with the repo and applies in CI. Note this is a guardrail enforced by the murk binary, not access control — see THREAT_MODEL.md.

A granted agent is held to the policy no matter how it reads — `murk get`, `murk agent exec`, or the Python/Node bindings (`murk-secrets`). `get()` and `export()` from the bindings refuse a forbidden key just like the CLI, so the allow-list is enforced from every entry point. Tightening the policy applies retroactively: drop a tag and the agent loses access on its next read, even though its old grant key still exists.

## Auditing agent activity

There's no separate agent log to consult — **git is the record.** Every admin change to a grant or policy is a commit, so:

```bash
git log -p .murk        # who created/revoked grants, changed policy, rotated values
murk diff               # the same changes for the latest revision, decoded
```

Each shows the change attributed to its commit author (and signed, if you use git commit signing). What git *can't* show is secret reads on a developer's machine — murk never sees those — so don't treat the absence of a read trail as proof a secret wasn't used. See THREAT_MODEL.md for the full audit boundary.
