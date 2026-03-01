# Security Policy

## Cryptography

murk does not implement any cryptography. All encryption and decryption is performed by [age](https://age-encryption.org/) via the [rage](https://github.com/str4d/rage) Rust implementation. Key generation uses BIP39 mnemonics over cryptographically random bytes.

If you find a vulnerability in the underlying cryptographic primitives, please report it to the [age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage) projects directly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Latest release only |

murk is pre-1.0 software. Only the latest release receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://github.com/iicky/murk/security/advisories/new) to submit a report. You'll get a response within 7 days.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

## Scope

In scope:
- Secret values leaking into plaintext (logs, error messages, temp files)
- Bypassing recipient-based access control
- Key material exposure beyond `.env`
- Integrity check bypass (MAC validation)

Out of scope:
- Vulnerabilities in age/rage cryptographic primitives (report upstream)
- Attacks requiring local access to `.env` or `MURK_KEY` (these contain the secret key by design)
- Denial of service against the CLI
