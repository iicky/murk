---
title: Install & verify
description: Install murk and verify the release you downloaded.
sidebar:
  order: 1
---

murk ships as a single binary with no runtime dependencies. Pick whichever
install method fits your setup.

## Homebrew

```bash
brew tap iicky/murk && brew install murk
```

## Cargo

Requires the [Rust toolchain](https://rustup.rs):

```bash
cargo install murk-cli
```

## install.sh

Downloads a pre-built binary for your platform:

```bash
curl -fsSL https://raw.githubusercontent.com/iicky/murk/main/install.sh | sh
```

## GitHub Releases

Pre-built binaries are available for Linux (x86_64, aarch64, armhf), macOS
(x86_64, Apple Silicon), and Windows on the
[releases page](https://github.com/iicky/murk/releases).

murk is also published to npm as
[`@iicky/murk-secrets`](https://www.npmjs.com/package/@iicky/murk-secrets) and
to PyPI as [`murk-secrets`](https://pypi.org/project/murk-secrets/), if either
fits your project's toolchain better than a system-wide binary.

## Verify your download

Binary releases carry signed build provenance
([`actions/attest-build-provenance`](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds),
backed by Sigstore/Fulcio). Verify a downloaded artifact with the GitHub CLI:

```bash
gh attestation verify murk-<version>-<target>.tar.gz --owner iicky
```

This confirms the artifact was produced by this repository's release
workflow — a builder you can inspect, with a signing identity an attacker
cannot forge.

npm, PyPI, and crates.io releases each have their own verification path (npm
provenance, PEP 740 attestations, and signed release tags respectively). See
[Verifying releases](/security/verifying/) for the full walkthrough across
every distribution channel.

## Next steps

Once murk is installed, run through the [quick start](/quick-start/) to
generate a key and create your first vault.
