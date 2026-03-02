# Offboarding demo — Alice revokes Carol, rotates exposed secrets

Output demo/offboarding.gif

Require murk

Source demo/theme.tape

Hide
Source demo/setup.tape

# Build up the team: alice adds bob and carol
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY"`
Enter
Type `murk authorize $BOB_PUBKEY bob 2>/dev/null`
Enter
Sleep 2s
Type `murk authorize $CAROL_PUBKEY carol 2>/dev/null`
Enter
Sleep 2s

Type `alice`
Enter
Sleep 500ms
Show

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

Type `echo "postgres://prod:newsecret@db.example.com/app" | murk add DATABASE_URL`
Enter
Sleep 2s

Type `echo "sk-proj-rotated789xyz" | murk add API_KEY`
Enter
Sleep 2s

Type `echo "sk_live_rotated456" | murk add STRIPE_SECRET`
Enter
Sleep 2s

Type "# Verify the team"
Enter
Sleep 500ms

Type "murk recipients"
Enter
Sleep 2s

Sleep 2s
