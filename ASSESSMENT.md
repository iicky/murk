# murk — Security Assessment

_What HN and security folks would say._

---

## TL;DR

murk is a git-native encrypted secrets manager built on `age`. The crypto
delegation is the right call — no hand-rolled primitives. But several areas
would draw fire from HN commenters and security reviewers, especially for a
tool whose entire value proposition is _"trust me with your secrets."_

---

## The Good

- **No custom crypto.** Core encrypt/decrypt delegates entirely to the `age`
  crate (X25519 + HKDF-SHA256 + ChaCha20-Poly1305). The Rust `age` crate is
  authored by str4d (zcash). HN would approve.
- **Per-value encryption.** Each secret is a separate age message — no
  all-or-nothing decryption. Fresh random file key per encrypt call, no nonce
  reuse risk.
- **`SecretString` for key material.** `MURK_KEY` is wrapped in
  `secrecy::SecretString` with zeroize-on-drop. `.env` gets `chmod 0600` on
  Unix. Permission warnings if too loose.
- **BIP39 recovery.** Clean design — 32 bytes entropy → X25519 key + 24-word
  mnemonic. Same bytes, no derivation step. Simple and correct.
- **`cargo-deny` in CI.** License allowlist, advisory DB checks, source
  restrictions. Dependabot for both cargo and actions.
- **Ciphertext stability.** Unchanged values keep their ciphertext across
  saves — good for git diffs, doesn't compromise security.

---

## The "MAC" That Isn't a MAC

**The single biggest thing a cryptographer would flag.**

`compute_mac()` in `lib.rs` computes a plain SHA-256 hash over key names,
shared ciphertext, and recipient pubkeys. It calls this a "MAC" but there is
**no secret key** — it's just a hash of public data. Any current recipient who
can re-encrypt the meta blob can recompute a valid "hash" after tampering.

The saving grace: the hash is stored _inside_ the encrypted meta blob, so an
external attacker can't update it. But calling it a MAC is misleading and the
protection is entirely parasitic on meta blob encryption.

**Worse:**
- Empty MAC string → integrity check silently skipped (`lib.rs:119`)
- Meta decryption failure → falls through to `HashMap::new()`, no MAC check at
  all (`lib.rs:109-132`)
- **Scoped entries are not covered by the MAC.** An attacker can modify, add,
  or remove scoped ciphertext without detection.

**HN comment:** _"They called it a MAC but it's just SHA256 with no key. The
integrity check can be bypassed by clearing the mac field or corrupting the
meta blob. This is not how you do authenticated encryption."_

---

## The Merge Driver Is a Data Loss Vector

The custom git merge driver (`merge.rs`) silently drops secrets and recipients
in several scenarios:

1. **One side removes a secret, other side doesn't touch it → silently
   deleted.** No conflict raised. User never warned.
2. **One side removes a recipient → silently removed.** Set-difference
   operation, no conflict. Alice removes Bob on branch A, Carol makes
   unrelated changes on branch B, merge silently revokes Bob.
3. **Malicious recipient injection.** The merge driver unions recipients from
   both sides. An attacker with commit access can add their own pubkey as a
   recipient — the merge incorporates it without conflict, no authorization
   check.
4. **Without `MURK_KEY`, meta regeneration falls back to stale "ours" meta.**
   Integrity MAC is stale after merge. Next load fails validation.

**HN comment:** _"A merge driver for a secrets manager that can silently delete
secrets and silently add unauthorized recipients? This needs to be a hard
conflict, not a set operation."_

---

## Supply Chain: Every Action Pinned to Mutable Tags

**Every** GitHub Actions reference uses mutable version tags (`@v6`, `@v2`,
`@stable`) instead of commit SHA pins. For a secrets manager, this is the
most significant supply chain risk.

| What | Tag Used |
|------|----------|
| `actions/checkout` | `@v6` |
| `dtolnay/rust-toolchain` | `@stable` (a _branch name_) |
| `Swatinem/rust-cache` | `@v2` |
| `codecov/codecov-action` | `@v5` |
| `softprops/action-gh-release` | `@v2` |
| ... and 10+ more | all mutable tags |

A compromised upstream action gets arbitrary code execution in the build
pipeline. `dtolnay/rust-toolchain@stable` is especially concerning — it's not
even a version tag.

**Also:**
- **No code signing** on release binaries or SHA256SUMS
- **No SLSA provenance** or build attestation
- **`cargo build --release` missing `--locked`** in the release workflow
- **Dependabot auto-merge is unconditional** — no patch-only filter, no CI
  gate requirement
- **`cargo publish` runs independently** without `needs:` gate on build/release
  jobs
- **`publish` job passes registry token via CLI argument** instead of env var

**HN comment:** _"You're building a secrets manager and your CI actions aren't
pinned to SHAs? The release binaries are unsigned? Anyone who compromises one
upstream action owns every murk user's secrets pipeline."_

---

## Secret Handling at Runtime

### What's done well
- Secrets injected via `Command::envs()` in `murk exec` — environment
  variables, not CLI args. Not visible in `/proc/cmdline` or `ps`.
- On Unix, `exec()` replaces the process (no parent holding secrets).
- `MURK_KEY` uses `SecretString` with zeroize-on-drop.
- Interactive secret input uses `rpassword` for echo suppression.
- No temp files — secrets never written to disk unencrypted (beyond `.env`).
- No logging framework — all secret output is intentional (`get`, `export`).

### What's not
- **Decrypted secret values live as `String` in `HashMap`** — no zeroize. In
  long-running processes (or core dumps), secret values are readable from
  memory.
- **Recovery phrase printed to stderr at init** (`main.rs:304-311`). Terminal
  scrollback, CI logs, screen recordings → key compromise. No confirmation
  prompt that user saved the phrase.
- **`murk restore` accepts phrase as a CLI argument** (`main.rs:36-38`) —
  visible in shell history, `/proc/cmdline`, `ps`. (It does prompt if omitted,
  which is the intended path.)
- **`eval $(murk export)` pattern** — key names are not validated for shell
  safety. A malicious key name could theoretically inject shell commands.
- **No vault file locking** — concurrent read-modify-write cycles can
  silently lose changes. No atomic writes (write to temp + rename).
- **`MURK_KEY` visible in `/proc/<pid>/environ`** to same-user processes.
- **`env::var("MURK_KEY")` creates a plain `String` before wrapping in
  `SecretString`** — the pre-wrap copy is not zeroized.
- **`murk restore` interactive path uses plain `read_line()`** — recovery
  phrase echoed to terminal (unlike `murk add` which uses `rpassword`).

---

## Metadata Leakage (By Design, But Worth Noting)

Key names (`DATABASE_URL`, `STRIPE_SECRET_KEY`), descriptions, examples, tags,
recipient pubkeys, and secret count are all plaintext in the `.murk` JSON.

**HN comment:** _"The existence of STRIPE_SECRET_KEY or
AWS_ROOT_CREDENTIALS tells me plenty about your infrastructure without
needing to decrypt anything."_

---

## Spec vs. Implementation Drift

SPEC.md describes a v1 multi-section format. The code implements v2 (single
JSON doc, per-value encryption). Anyone building a compatible parser from the
spec would produce something incompatible. The `version` field is never
validated on load — a vault claiming `"version": "99.0"` is happily parsed.

---

## Smaller Issues

- **Name collision in `revoke_recipient`** — resolves display names via
  `HashMap::find()`, non-deterministic if two recipients share a name. Could
  revoke the wrong person.
- **No key rotation** (`murk rotate` listed as V2 planned feature).
- **No forward secrecy** — inherent to age's static X25519, acceptable for
  file-based threat model.
- **Scoped secrets encrypted to single recipient** — lost forever if that
  user loses their key. No recovery path even for admins.
- **No self-revocation guard** — user can accidentally revoke themselves.

---

## What I'd Fix First

1. **Pin all Actions to commit SHAs.** Non-negotiable for a security tool.
2. **Sign release binaries.** At minimum, GPG-sign SHA256SUMS. Better: SLSA
   provenance.
3. **Fix the "MAC"** — either use HMAC-SHA256 with a key derived from the
   encryption context, or rename it to "integrity hash" and document that
   integrity depends on meta blob encryption. Cover scoped entries. Hard-fail
   on empty MAC for new vaults.
4. **Make the merge driver conflict-heavy, not conflict-light.** Recipient
   removal and secret deletion should always produce a conflict that requires
   human review.
5. **Add `--locked` to all cargo build commands** in the release workflow.
6. **Add file locking** (flock/advisory) around vault read-modify-write
   cycles.
7. **Gate dependabot auto-merge** on patch-only updates and CI passing.
8. **Don't accept recovery phrase as a CLI argument.**

---

_Assessment generated 2026-03-02 against commit `85026e0`._
