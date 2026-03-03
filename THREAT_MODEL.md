# Threat Model

This document describes murk's security properties and limitations. It is intended for security leads evaluating murk for team use.

murk is pre-1.0 and has not been independently audited. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## What murk protects

**Secrets at rest in git.** The `.murk` file is safe to commit. Secret values are individually encrypted with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305). An attacker with read access to the repository cannot decrypt values without a recipient's private key.

**Secrets in transit via git.** Since values are encrypted before they enter git, pushing/pulling over any transport (HTTPS, SSH, unencrypted) does not expose secret values.

**Cross-value integrity.** A SHA-256 MAC inside the encrypted meta blob covers all key names, encrypted values, and recipient public keys. This prevents an attacker from rearranging, adding, or removing ciphertexts between key names without detection. The MAC is mandatory whenever the vault contains secrets.

**Per-recipient secrets.** Scoped secrets (motes) are encrypted to a single recipient's public key. Other authorized recipients cannot decrypt them.

## What murk does not protect

**Compromised machines.** If an attacker has access to a machine where `MURK_KEY` is present (in `.env`, in memory, or in environment variables), they can decrypt all shared secrets and any scoped secrets belonging to that key.

**Key names are public.** The `.murk` header stores key names, descriptions, and examples in plaintext. An attacker with repo access knows you have `STRIPE_SECRET_KEY`, `DATABASE_URL`, etc. This is a design trade-off that enables `murk info` to work without a key and keeps git diffs readable. If your threat model requires hiding what services you use, murk does not address this.

**Historical access after revocation.** Revoking a recipient re-encrypts the vault going forward, but old `.murk` versions remain in git history. The revoked recipient can still decrypt any version they previously had access to. Always rotate credentials after revocation. murk warns about this at revocation time.

**Fine-grained access control.** All authorized recipients can decrypt all shared secrets. Per-key access metadata is stored but not enforced cryptographically in v1. If a recipient's public key is in the recipient list, they can read everything in the shared layer.

**Audit logging.** murk has no built-in audit trail beyond git history. It does not log who decrypted what or when. For regulated environments requiring provable access controls, use a dedicated secrets server.

## Trust boundaries

```
┌─────────────────────────────────────┐
│         Developer machine           │
│                                     │
│  .env (MURK_KEY) ── secret key      │  ← Trust boundary: local machine
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

## Key compromise scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| `MURK_KEY` leaked | Attacker can decrypt all shared secrets and the owner's scoped secrets | Revoke the compromised key, rotate all secrets, re-authorize with a new key |
| `.env` committed to git | Same as key leak, but the key is now in git history | Remove from history (`git filter-repo`), revoke, rotate |
| Recovery phrase exposed | Attacker can derive the secret key | Same as key leak |
| Repository made public | Key names and encrypted values exposed; values remain safe if keys are secure | Rotate secrets as a precaution if key names alone are sensitive |
| Recipient revoked | Revoked user retains access to historical versions in git | Rotate all secrets that the revoked user had access to |

## Cryptographic properties

murk delegates all cryptography to age. It does not implement any custom cryptographic primitives.

- **Encryption:** age v1 (X25519 key agreement, ChaCha20-Poly1305 payload encryption)
- **Per-value encryption:** each secret value is encrypted independently with a fresh age file key
- **Integrity:** SHA-256 MAC over sorted key names + encrypted shared values + sorted recipient public keys, stored inside an age-encrypted meta blob
- **Key derivation:** BIP39 mnemonic (256 bits of entropy) → SHA-256 → age identity

The MAC binds independent age ciphertexts together. Without it, an attacker could swap ciphertexts between key names (age authenticates individual ciphertexts but has no cross-value binding).

## Scope

murk is appropriate for dev teams and small organizations. It replaces sharing `.env` files over Slack, email, or shared documents — a meaningful improvement over that baseline.

murk is not designed for regulated environments handling PII, financial data, or healthcare data where audit trails, key management infrastructure, and provable access controls are required.
