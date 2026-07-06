# VHS recorder image for CI: upstream vhs plus the git and direnv binaries the
# demo tapes call. Built in each vhs-record matrix job with a shared GitHub
# Actions layer cache, so only the first run after an upstream change pays for
# the apt install.
FROM ghcr.io/charmbracelet/vhs
RUN apt-get update --allow-releaseinfo-change \
    && apt-get install -y --no-install-recommends git direnv \
    && rm -rf /var/lib/apt/lists/*
