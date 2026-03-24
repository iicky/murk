#!/bin/sh
# Install murk — https://github.com/iicky/murk
# Usage: curl -fsSL https://raw.githubusercontent.com/iicky/murk/main/install.sh | sh
set -e

REPO="iicky/murk"
INSTALL_DIR="${MURK_INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux)
        case "$arch" in
            x86_64)  target="x86_64-unknown-linux-gnu" ;;
            aarch64) target="aarch64-unknown-linux-gnu" ;;
            armv7*)  target="arm-unknown-linux-gnueabihf" ;;
            *)       echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$arch" in
            x86_64)  target="x86_64-apple-darwin" ;;
            arm64)   target="aarch64-apple-darwin" ;;
            *)       echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "error: unsupported OS: $os (try cargo install murk-cli)" >&2
        exit 1
        ;;
esac

# Get latest release tag.
tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$tag" ]; then
    echo "error: could not determine latest release" >&2
    exit 1
fi

archive="murk-${tag}-${target}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$archive"

echo "installing murk $tag ($target)"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

curl -fsSL "$url" -o "$tmpdir/$archive"
tar xzf "$tmpdir/$archive" -C "$tmpdir"

if [ -w "$INSTALL_DIR" ]; then
    mv "$tmpdir/murk" "$INSTALL_DIR/murk"
else
    sudo mv "$tmpdir/murk" "$INSTALL_DIR/murk"
fi

echo "installed murk to $INSTALL_DIR/murk"
