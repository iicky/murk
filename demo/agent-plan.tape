# Agent plan demo — give an AI agent the schema, never the secrets.
# `murk agent plan` emits key names, descriptions, examples, and tags — no
# values, no MURK_KEY — so it's safe to paste into an agent prompt.

Output demo/agent-plan.gif

Require murk

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `cd "$(mktemp -d)"`
Enter
Type `echo "dev" | murk init 2>/dev/null`
Enter
Sleep 1s
Type `source .env`
Enter
Type `echo "postgres://prod:s3cr3t@db.example.com/app" | murk add DATABASE_URL --desc "Primary database" 2>/dev/null`
Enter
Type `echo "sk-proj-abc123def456" | murk add OPENAI_KEY --desc "OpenAI API key" --tag ai 2>/dev/null`
Enter
Type `echo "sk_live_xyz789" | murk add STRIPE_SECRET --desc "Stripe secret key" 2>/dev/null`
Enter
Type `export PS1="\n\[\e[35m\]agent \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# An AI agent needs to know what secrets exist — but must never see values"
Enter
Sleep 1500ms

Type "murk agent plan"
Enter
Sleep 3s

Type "# Names, descriptions, examples, tags. No values, no key required."
Enter
Sleep 2s

Type "# Machine-readable, for wiring into a harness:"
Enter
Sleep 1s

Type "murk agent plan --json"
Enter
Sleep 3s

Type "# Paste this into the agent's prompt — there is nothing secret to leak."
Enter
Sleep 2500ms
