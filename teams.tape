# Teams demo — Alice adds Bob, Bob adds Carol, private overrides

Output demo/teams.gif

Require murk

Source demo/theme.tape

Hide
Source demo/setup.tape

# Alice authorizes Bob before we start
Type `cd "$ALICE_DIR" && export MURK_KEY="$ALICE_KEY" && murk authorize $BOB_PUBKEY bob 2>/dev/null`
Enter
Sleep 2s

Type `alice`
Enter
Sleep 500ms
Show

# === ALICE ===

Type "# Alice added Bob — check the team"
Enter
Sleep 500ms

Type "murk recipients"
Enter
Sleep 2s

# === SWITCH TO BOB ===
Hide
Type `bob`
Enter
Type `cp $ALICE_DIR/.murk .`
Enter
Sleep 500ms
Show

Type "# Bob can decrypt secrets"
Enter
Sleep 500ms

Type "murk get DATABASE_URL"
Enter
Sleep 2s

Type "# Bob adds Carol to the team"
Enter
Sleep 500ms

Type `murk authorize \`
Enter
Type `  $CAROL_PUBKEY \`
Enter
Type `  carol`
Enter
Sleep 2s

Type "murk recipients"
Enter
Sleep 2s

Type "# Override a secret for local dev"
Enter
Sleep 500ms

Type `echo "postgres://localhost/dev" | murk add DATABASE_URL --private`
Enter
Sleep 2s

Type "# Bob's export shows the override"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 2s

# === SWITCH BACK TO ALICE ===
Hide
Type `alice`
Enter
Sleep 500ms
Show

Type "# Alice still has production values"
Enter
Sleep 500ms

Type "murk export"
Enter
Sleep 2s

Sleep 2s
