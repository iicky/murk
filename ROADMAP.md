# Roadmap

murk is pre-1.0. This roadmap covers planned directions, not commitments. Priorities shift based on real usage.

## Near-term (2026)

- Hardening pass: race-safe file opens, permission enforcement, adversarial tests
- GitHub key pinning (TOFU) for `github:username` authorization
- Lower-exposure execution modes for `murk exec` (`--only`, `--clean-env`)
- Fuzz testing via OSS-Fuzz
- SLSA Level 3 provenance

## Someday

- Secret versioning (`murk history`, `murk rollback`)
- Per-key timestamps and access logging
- First-class environment separation (dev/staging/prod)
- Scoped agent keys for AI coding agents and CI
- Nix flake, Debian packages
- External security review

## Non-goals

- Centralized secrets server (use HashiCorp Vault)
- Custom cryptographic primitives (murk uses age)
- Fine-grained cryptographic access control (all recipients can read shared secrets by design)
- Regulated/compliance environments (no audit trail beyond git, no provable access controls)
- Algorithm agility (age uses a fixed suite by design)
