# Quick start for teammates

You've been invited to a project that uses murk for secrets. Here's how to get set up.

## 1. Install murk

```bash
brew tap iicky/murk && brew install murk
```

Or: `cargo install murk-cli`, `pip install murk`, or download from [GitHub Releases](https://github.com/iicky/murk/releases).

## 2. Generate your key

```bash
murk init
```

This creates your keypair and prints 24 recovery words. **Write them down.** If you lose your key, these words are the only way to recover it.

Your key is stored in `~/.config/murk/keys/`, not in the repo.

## 3. Share your public key

```bash
murk recover
```

Wait — that's for recovery. To get your public key for authorization:

```bash
cat ~/.config/murk/keys/*.pub 2>/dev/null || murk info 2>/dev/null
```

Actually, the easiest path: ask the team lead to run:

```bash
murk circle authorize github:YOUR_USERNAME
```

This fetches your SSH public keys from GitHub and adds you to the vault. No manual key exchange needed.

## 4. Pull and use secrets

Once authorized:

```bash
git pull                    # get the updated .murk file
murk ls                     # see what secrets are available
murk get DATABASE_URL       # print one secret
murk export                 # print all as shell exports
murk exec -- ./my-script.sh # run a command with secrets in env
```

## 5. Set up direnv (optional)

```bash
murk env
direnv allow
```

Now secrets are automatically loaded when you `cd` into the project.

## What to know

- **Key names are public.** Anyone with repo access can see what secrets exist (e.g. `STRIPE_KEY`). Only values are encrypted.
- **Your key is your identity.** Don't share it. Don't paste it into chat. Don't commit it.
- **Recovery phrase = your key.** If someone has your 24 words, they have your key.
- **Revocation doesn't erase history.** If you leave the team, your access to old git history remains. The team should rotate secrets after revoking you.
