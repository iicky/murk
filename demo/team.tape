# Team demo — scoped overrides, onboarding a new member via git
#
# Shows: murk info, scoped secrets, authorize, git push/pull workflow,
# new member onboarding, and isolation of scoped values.

Output demo/team.gif

Require murk
Require git

Source demo/theme.tape

Set Height 600

# === HIDDEN SETUP ===
Hide

# Put murk on PATH
Type `export PATH="$PWD/target/release:$PATH"`
Enter

# Create dirs
Type `export ALICE_DIR="$(mktemp -d)"`
Enter
Type `export BOB_DIR="$(mktemp -d)"`
Enter
Type `export REMOTE="$(mktemp -d)"`
Enter

# Git config for commits in temp dirs
Type `export GIT_AUTHOR_NAME="demo" GIT_AUTHOR_EMAIL="demo@murk" GIT_COMMITTER_NAME="demo" GIT_COMMITTER_EMAIL="demo@murk"`
Enter

# Create bare git remote
Type `git init --bare "$REMOTE"`
Enter
Sleep 200ms

# Alice: init vault and add secrets
Type `cd "$ALICE_DIR"`
Enter
Type `echo "alice" | murk init 2>/dev/null`
Enter
Sleep 2s
Type `eval $(cat .env)`
Enter
Type `export ALICE_KEY="$MURK_KEY"`
Enter
Type `echo "postgres://prod:secret@db.example.com/app" | murk add DATABASE_URL --desc "Production database" 2>/dev/null`
Enter
Sleep 500ms
Type `echo "sk-proj-abc123def456" | murk add API_KEY --desc "OpenAI API key" 2>/dev/null`
Enter
Sleep 500ms
Type `echo "sk_live_xyz789" | murk add STRIPE_SECRET --desc "Stripe secret key" 2>/dev/null`
Enter
Sleep 500ms

# Git init and push
Type `git init`
Enter
Sleep 200ms
Type `git checkout -b main`
Enter
Type `git add .murk`
Enter
Type `git commit -m "init vault"`
Enter
Sleep 300ms
Type `git remote add origin "$REMOTE"`
Enter
Type `git push -u origin main`
Enter
Sleep 300ms

# Bob: clone the repo (before being authorized)
Type `cd "$BOB_DIR"`
Enter
Type `git clone "$REMOTE" .`
Enter
Sleep 300ms

# Start as Alice (no alias — just inline)
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

# === ALICE: review vault and add scoped override ===

Type "# Check the vault — 1 recipient, 3 secrets"
Enter
Sleep 500ms

Type "murk info"
Enter
Sleep 3s

Type "# Override DATABASE_URL for local dev"
Enter
Sleep 500ms

Type `murk add DATABASE_URL --scoped`
Enter
Sleep 1s
Type "postgres://localhost:5432/alice_dev"
Enter
Sleep 2s

Type "# Alice's export shows her local override"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

# === SWITCH TO BOB ===

Type "# Meanwhile, Bob clones the repo..."
Enter
Sleep 1s

# Switch to Bob — do NOT set MURK_KEY (he doesn't have one yet)
Hide
Type `cd "$BOB_DIR" && unset MURK_KEY`
Enter
Type `export PS1="\n\[\e[33m\]bob \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 200ms
Show

Type "# Bob tries to access the vault"
Enter
Sleep 500ms

# murk init on existing vault: generates keypair, shows "not authorized" + pubkey
# No name prompt — onboarding flow skips it
Type "murk init"
Enter
Sleep 4s

Type "# 1 recipient — Bob isn't on the team yet"
Enter
Sleep 500ms

Type "murk info"
Enter
Sleep 3s

# Capture Bob's key and pubkey, then clear screen for clean transition
Hide
Type `eval $(cat .env)`
Enter
Type `export BOB_KEY="$MURK_KEY"`
Enter
Type `export BOB_PUBKEY=$(murk init 2>&1 | grep "^age1")`
Enter
Sleep 300ms
Type `clear`
Enter
Sleep 200ms
Show

Type "# Send pubkey to Alice..."
Enter
Sleep 2s

# === SWITCH TO ALICE: authorize Bob ===

Hide
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY"`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 200ms
Show

Type "# Alice authorizes Bob"
Enter
Sleep 500ms

Type `murk authorize $BOB_PUBKEY bob`
Enter
Sleep 2s

Type "murk recipients"
Enter
Sleep 2s

Type "# Commit and push"
Enter
Sleep 500ms

Type `git add .murk && git commit -m "add bob"`
Enter
Sleep 1s

Type `git push`
Enter
Sleep 2s

# === SWITCH TO BOB: pull and decrypt ===

Hide
Type `cd "$BOB_DIR" && export MURK_KEY="$BOB_KEY"`
Enter
Type `export PS1="\n\[\e[33m\]bob \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 200ms
Show

Type "# Bob pulls the latest vault"
Enter
Sleep 500ms

Type "git pull"
Enter
Sleep 2s

Type "# 2 recipients now — Bob is on the team"
Enter
Sleep 500ms

Type "murk info"
Enter
Sleep 3s

Type "# Bob can decrypt shared secrets"
Enter
Sleep 500ms

Type "murk get DATABASE_URL"
Enter
Sleep 2s

Type "# Bob sees production, not Alice's local override"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

Sleep 2s
