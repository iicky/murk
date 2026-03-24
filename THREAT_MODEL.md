# Threat Model

This document describes murk's security properties and limitations. It is intended for security leads evaluating murk for team use.

murk is pre-1.0 and has not been independently audited. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## What murk protects

**Secrets at rest in git.** The `.murk` file is safe to commit. Secret values are individually encrypted with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305). An attacker with read access to the repository cannot decrypt values without a recipient's private key.

**Secrets in transit via git.** Since values are encrypted before they enter git, pushing/pulling over any transport (HTTPS, SSH, unencrypted) does not expose secret values.

**Cross-value integrity.** A BLAKE3 keyed MAC inside the encrypted meta blob covers all key names, encrypted values, and recipient public keys. The MAC key is a random 32-byte value stored alongside the MAC in the encrypted meta, so only authorized recipients can compute or verify it. This prevents an attacker from rearranging, adding, or removing ciphertexts — or recomputing a valid MAC after tampering. The MAC is mandatory whenever the vault contains secrets.

**Per-recipient secrets.** Scoped secrets (motes) are encrypted to a single recipient's public key. Other authorized recipients cannot decrypt them.

## What murk does not protect

**Compromised machines.** If an attacker has access to a machine where the secret key is present (`~/.config/murk/keys/`, in memory, or in environment variables), they can decrypt all shared secrets and any scoped secrets belonging to that key.

**Key names are public.** The `.murk` header stores key names, descriptions, and examples in plaintext. An attacker with repo access knows you have `STRIPE_SECRET_KEY`, `DATABASE_URL`, etc. This is a design trade-off that enables `murk info` to work without a key and keeps git diffs readable. If your threat model requires hiding what services you use, murk does not address this.

**In-memory secret exposure.** Decrypted secret values are held as plain `String` in memory during `export`, `exec`, and `get` operations. They are not zeroized on drop. In long-running processes, core dumps, or swap files, decrypted values may be recoverable. The secret key itself uses `SecretString` with zeroize-on-drop, but the values it decrypts do not. This is a known limitation — mitigating it would require threading `SecretString` through all value paths, which is not practical with the current age API.

**Historical access after revocation.** Revoking a recipient re-encrypts the vault going forward, but old `.murk` versions remain in git history. The revoked recipient can still decrypt any version they previously had access to. Always rotate credentials after revocation. murk warns about this at revocation time.

**Fine-grained access control.** All authorized recipients can decrypt all shared secrets. Per-key access metadata is stored but not enforced cryptographically in v1. If a recipient's public key is in the recipient list, they can read everything in the shared layer.

**Audit logging.** murk has no built-in audit trail beyond git history. It does not log who decrypted what or when. For regulated environments requiring provable access controls, use a dedicated secrets server.

## Trust boundaries

```
┌─────────────────────────────────────┐
│         Developer machine           │
│                                     │
│  ~/.config/murk/keys/ ── secret key  │  ← Trust boundary: local machine
│  MURK_KEY in memory ── during ops   │
│                                     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│          Git repository             │
│                                     │
│  .murk file:                        │
│    Header (plaintext) ── key names, │  ← Public: anyone with repo access
│      descriptions, recipient keys   │
│    Values (encrypted) ── per-value  │  ← Protected: requires MURK_KEY
│      age ciphertexts                │
│    Meta (encrypted) ── MAC,         │  ← Protected: requires MURK_KEY
│      recipient names                │
│                                     │
└─────────────────────────────────────┘
```

**What crosses the boundary encrypted:** secret values, recipient display names, integrity MAC.

**What crosses the boundary in plaintext:** key names, key descriptions, example values, recipient public keys, vault metadata (version, creation date, repo URL).

## GitHub SSH key onboarding

`murk authorize github:username` fetches SSH public keys from `https://github.com/username.keys` without authentication. This introduces trust assumptions:

**You trust GitHub as a key directory.** The keys returned by GitHub are whatever the user has uploaded to their GitHub account. If an attacker compromises a GitHub account and adds their own SSH key, `murk authorize github:attacker` would grant them access to vault secrets.

**You trust that the GitHub username belongs to who you think it does.** There is no out-of-band verification. If you authorize `github:alice` you are trusting that the GitHub user "alice" is your teammate Alice. For most teams this is reasonable — you already trust teammates' GitHub accounts for code review and merge access.

**No TOFU (Trust On First Use) pinning.** murk does not remember which keys were previously fetched for a username. If a user rotates their SSH keys on GitHub, a subsequent `authorize` would add the new keys. Revocation of old keys must be done manually via `murk revoke`.

**SSH keys in the vault are just longer pubkey strings.** The vault format is unchanged — `vault.recipients` stores `ssh-ed25519 AAAA...` strings alongside `age1...` strings. All existing integrity protections (MAC, per-value encryption) apply equally to SSH recipients.

**Acceptable risk profile:** For a team secrets tool, trusting GitHub as a key directory is a reasonable trade-off. You are already trusting your teammates with code access, CI credentials, and production deployments through the same GitHub accounts. The alternative (manual key exchange) has worse security properties in practice because teams resort to sharing keys over Slack or email.

## Key compromise scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| `MURK_KEY` leaked | Attacker can decrypt all shared secrets and the owner's scoped secrets | Revoke the compromised key, rotate all secrets, re-authorize with a new key |
| `.env` committed to git | Same as key leak, but the key is now in git history | Remove from history (`git filter-repo`), revoke, rotate |
| Recovery phrase exposed | Attacker can derive the secret key | Same as key leak |
| Repository made public | Key names and encrypted values exposed; values remain safe if keys are secure | Rotate secrets as a precaution if key names alone are sensitive |
| Recipient revoked | Revoked user retains access to historical versions in git | Rotate all secrets that the revoked user had access to |
| GitHub account compromised | Attacker could be authorized via `github:username` if the vault owner runs authorize after compromise | Verify teammate identity before authorizing; revoke and rotate if compromise is suspected |
| SSH private key leaked | Attacker can decrypt all secrets the SSH key was a recipient for | Revoke the compromised SSH key from the vault, rotate secrets |

## Cryptographic properties

murk delegates all cryptography to age. It does not implement any custom cryptographic primitives.

- **Encryption:** age v1 (X25519 key agreement, ChaCha20-Poly1305 payload encryption)
- **Per-value encryption:** each secret value is encrypted independently with a fresh age file key
- **Recipient types:** age x25519 keys (`age1...`) and SSH keys (`ssh-ed25519`, `ssh-rsa`) — age handles both natively
- **Integrity:** BLAKE3 keyed MAC over sorted key names + encrypted shared values + sorted recipient public keys, stored inside an age-encrypted meta blob (legacy SHA-256 accepted on load)
- **Key derivation:** BIP39 mnemonic (256 bits of entropy) → SHA-256 → age identity (age keys only; SSH keys use their native format)

The MAC binds independent age ciphertexts together. Without it, an attacker could swap ciphertexts between key names (age authenticates individual ciphertexts but has no cross-value binding).

## Scope

murk is appropriate for dev teams and small organizations. It replaces sharing `.env` files over Slack, email, or shared documents — a meaningful improvement over that baseline.

murk is not designed for regulated environments handling PII, financial data, or healthcare data where audit trails, key management infrastructure, and provable access controls are required.
