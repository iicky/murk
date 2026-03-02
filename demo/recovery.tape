# Recovery demo — back up and restore a key from BIP39 phrase

Output demo/recovery.gif

Require murk

Source demo/theme.tape

Hide
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Type `cd "$(mktemp -d)"`
Enter
Type `echo "alice" | murk init 2>/dev/null`
Enter
Sleep 2s
Type `eval $(cat .env)`
Enter
Type `export PS1="\n\[\e[94m\]alice \$\[\e[0m\] "`
Enter
Type `clear`
Enter
Sleep 300ms
Show

Type "# Your key lives in MURK_KEY"
Enter
Sleep 500ms

Type `echo $MURK_KEY`
Enter
Sleep 2s

Type "# Back it up as a recovery phrase"
Enter
Sleep 500ms

Type "murk recover"
Enter
Sleep 3s

Type "# Save the phrase, then restore from it"
Enter
Sleep 500ms

Type `PHRASE=$(murk recover)`
Enter
Sleep 1s

Type `murk restore "$PHRASE"`
Enter
Sleep 2s

Type "# Same key — round trip confirmed"
Enter
Sleep 2s
