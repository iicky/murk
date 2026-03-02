# Offboard demo — Bob revokes Carol, rotates secrets, Carol loses access
#
# Shows: revoke, key rotation, git push/pull, and proof that
# revoked users lose access to the new vault.

Output demo/offboard.gif

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
Type `export CAROL_DIR="$(mktemp -d)"`
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

# Alice: init vault, add secrets, push
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
Type `git init && git checkout -b main`
Enter
Sleep 200ms
Type `git add .murk && git commit -m "init vault"`
Enter
Sleep 300ms
Type `git remote add origin "$REMOTE"`
Enter
Type `git push -u origin main`
Enter
Sleep 300ms

# Bob: clone Alice's vault, onboard (generates key, shows pubkey)
Type `cd "$BOB_DIR" && unset MURK_KEY`
Enter
Type `git clone "$REMOTE" .`
Enter
Sleep 300ms
Type `murk init 2>/dev/null`
Enter
Sleep 2s
Type `eval $(cat .env)`
Enter
Type `export BOB_KEY="$MURK_KEY"`
Enter
Type `export BOB_PUBKEY=$(murk init 2>&1 | grep "^age1")`
Enter
Sleep 500ms

# Carol: clone Alice's vault, onboard (generates key, shows pubkey)
Type `cd "$CAROL_DIR" && unset MURK_KEY`
Enter
Type `git clone "$REMOTE" .`
Enter
Sleep 300ms
Type `murk init 2>/dev/null`
Enter
Sleep 2s
Type `eval $(cat .env)`
Enter
Type `export CAROL_KEY="$MURK_KEY"`
Enter
Type `export CAROL_PUBKEY=$(murk init 2>&1 | grep "^age1")`
Enter
Sleep 500ms

# Alice: authorize Bob and Carol, push
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY"`
Enter
Type `murk authorize $BOB_PUBKEY bob 2>/dev/null`
Enter
Sleep 1s
Type `murk authorize $CAROL_PUBKEY carol 2>/dev/null`
Enter
Sleep 1s
Type `git add .murk && git commit -m "add bob and carol"`
Enter
Sleep 300ms
Type `git push`
Enter
Sleep 300ms

# Bob and Carol: pull authorized vault
Type `cd "$BOB_DIR" && export MURK_KEY="$BOB_KEY" && git pull`
Enter
Sleep 300ms
Type `cd "$CAROL_DIR" && export MURK_KEY="$CAROL_KEY" && git pull`
Enter
Sleep 300ms

# Start as Bob
Type `cd "$BOB_DIR" && export MURK_KEY="$BOB_KEY"`
Enter
Type `export PS1="\n\[\e[33m\]bob \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

# === BOB: revoke Carol and rotate secrets ===

Type "# Carol is leaving — check the team"
Enter
Sleep 500ms

Type "murk recipients"
Enter
Sleep 2s

Type "# Revoke Carol's access"
Enter
Sleep 500ms

Type "murk revoke carol"
Enter
Sleep 3s

Type "# Rotate the exposed secrets"
Enter
Sleep 500ms

Type `murk add DATABASE_URL`
Enter
Sleep 1s
Type "postgres://prod:rotated@db.example.com/app"
Enter
Sleep 2s

Type `murk add API_KEY`
Enter
Sleep 1s
Type "sk-proj-rotated789xyz"
Enter
Sleep 2s

Type `murk add STRIPE_SECRET`
Enter
Sleep 1s
Type "sk_live_rotated456"
Enter
Sleep 2s

Type "murk recipients"
Enter
Sleep 2s

Type "# Push the changes"
Enter
Sleep 500ms

Type `git add .murk && git commit -m "revoke carol, rotate secrets"`
Enter
Sleep 1s

Type `git push`
Enter
Sleep 2s

# === SWITCH TO CAROL ===

Hide
Type `cd "$CAROL_DIR" && export MURK_KEY="$CAROL_KEY"`
Enter
Type `export PS1="\n\[\e[35m\]carol \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Carol still has the old vault"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

Type "# Carol pulls the latest..."
Enter
Sleep 500ms

Type "git pull"
Enter
Sleep 2s

Type "# Access revoked"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 3s

Sleep 2s
