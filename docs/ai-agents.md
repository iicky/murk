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

   Reach for `murk info` when you want a fuller picture (recipients, your key source, scoped overrides). Reach for `murk skeleton` when you want a distributable vault file shaped like the real one but with `recipients` / `secrets` / `meta` blanked.

## What's next

Future versions of murk will support scoped agent keys — short-lived recipient keys you create for an agent session, authorize for specific secrets, and revoke when done. Until then, `murk exec` and `murk info` are the safe path.
