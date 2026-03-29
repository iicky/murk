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

4. **Use `murk info` for schema prompting.** Agents don't need secret values to understand what's available. `murk info` and `murk info --json` show key names, descriptions, and examples — no decryption needed, no `MURK_KEY` required:
   ```bash
   murk info --json
   ```
   Feed this into agent system prompts so they know what secrets exist and how to reference them, without ever seeing the values.

5. **Use `murk skeleton` to share schema.** For distributing vault structure to agents or new team members without any encrypted data:
   ```bash
   murk skeleton -o skeleton.murk
   ```

## What's next

Future versions of murk will support scoped agent keys — short-lived recipient keys you create for an agent session, authorize for specific secrets, and revoke when done. Until then, `murk exec` and `murk info` are the safe path.
