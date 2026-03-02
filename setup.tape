# Shared setup for all murk VHS demos.
# Source inside a Hide block. Sets up:
# - murk on PATH
# - Alice's vault with 3 secrets in $ALICE_DIR
# - Bob's keypair in $BOB_DIR, pubkey in $BOB_PUBKEY
# - Carol's keypair in $CAROL_DIR, pubkey in $CAROL_PUBKEY
# - Persona switchers: alice (blue), bob (yellow), carol (magenta), eve (red)
#
# Assumes: run `vhs` from the repo root, and `cargo build --release` first.

Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `export ALICE_DIR="$(mktemp -d)" BOB_DIR="$(mktemp -d)" CAROL_DIR="$(mktemp -d)"`
Enter

# Alice vault + secrets
Type `cd "$ALICE_DIR" && echo "alice" | murk init 2>/dev/null && eval $(cat .env)`
Enter
Sleep 3s
Type `export ALICE_KEY="$MURK_KEY"`
Enter
Type `murk add DATABASE_URL "postgres://prod:secret@db.example.com/app" --desc "Production database" 2>/dev/null`
Enter
Sleep 1s
Type `murk add API_KEY "sk-proj-abc123def456" --desc "OpenAI API key" 2>/dev/null`
Enter
Sleep 1s
Type `murk add STRIPE_SECRET "sk_live_xyz789" --desc "Stripe secret key" 2>/dev/null`
Enter
Sleep 1s

# Bob vault (for keypair only)
Type `cd "$BOB_DIR" && echo "bob" | murk init 2>/dev/null && eval $(cat .env)`
Enter
Sleep 3s
Type `export BOB_KEY="$MURK_KEY"`
Enter
Type `export BOB_PUBKEY=$(python3 -c "import json; print(json.load(open('.murk'))['recipients'][0])")`
Enter

# Carol vault (for keypair only)
Type `cd "$CAROL_DIR" && echo "carol" | murk init 2>/dev/null && eval $(cat .env)`
Enter
Sleep 3s
Type `export CAROL_KEY="$MURK_KEY"`
Enter
Type `export CAROL_PUBKEY=$(python3 -c "import json; print(json.load(open('.murk'))['recipients'][0])")`
Enter

# Persona switchers
Type `alice() { cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY" && export PS1="\n\[\e[94m\]alice \$\[\e[0m\] " && clear; }`
Enter
Type `bob() { cd "$BOB_DIR" && export MURK_KEY="$BOB_KEY" && export PS1="\n\[\e[33m\]bob \$\[\e[0m\] " && clear; }`
Enter
Type `carol() { cd "$CAROL_DIR" && export MURK_KEY="$CAROL_KEY" && export PS1="\n\[\e[35m\]carol \$\[\e[0m\] " && clear; }`
Enter
Type `eve() { cd "$(mktemp -d)" && unset MURK_KEY && export PS1="\n\[\e[31m\]eve \$\[\e[0m\] " && cp "$ALICE_DIR/.murk" . && clear; }`
Enter
