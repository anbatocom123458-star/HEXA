#!/bin/sh
# HEXA toolchain installer.
#
# Installs the `hexa` binary into $PREFIX/bin (default: $HOME/.local, i.e.
# ~/.local/bin — already on most user PATHs). Set PREFIX to relocate, e.g.
#   PREFIX=/usr/local ./tools/install.sh
#
# Uninstall later with:
#   ./tools/install.sh --uninstall
#
# Options:
#   --prefix DIR   short for PREFIX=DIR
#   --uninstall    remove the installed hexa binary
#   --force        overwrite an existing hexa at the destination
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
UNINSTALL=0
FORCE=0
REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=1 ;;
        --force) FORCE=1 ;;
        --prefix) echo "install.sh: use PREFIX=DIR instead of --prefix" >&2; exit 2 ;;
        --prefix=*) PREFIX="${arg#--prefix=}" ;;
        -h|--help)
            sed -n '2,14p' "$0"
            exit 0
            ;;
        *)
            echo "install.sh: unknown argument '$arg' (see header)" >&2
            exit 2
            ;;
    esac
done

BIN_DIR="$PREFIX/bin"
DEST="$BIN_DIR/hexa"

if [ "$UNINSTALL" -eq 1 ]; then
    if [ -f "$DEST" ]; then
        rm -f "$DEST"
        echo "uninstalled $DEST"
    else
        echo "install.sh: $DEST not present; nothing to do"
    fi
    exit 0
fi

# Build a release binary (fast when nothing changed).
if ! command -v cargo >/dev/null 2>&1; then
    echo "install.sh: cargo is required (install Rust: https://rustup.rs)" >&2
    exit 1
fi
printf 'install.sh: building hexa (release)…\n'
( cd "$REPO_DIR" && cargo build --release -p hexa ) >&2 || {
    echo "install.sh: build failed" >&2
    exit 1
}

mkdir -p "$BIN_DIR"
if [ -e "$DEST" ] && [ "$FORCE" -ne 1 ]; then
    echo "install.sh: $DEST already exists (use --force to overwrite)" >&2
    exit 1
fi

install -m 0755 "$REPO_DIR/target/release/hexa" "$DEST"
echo "installed: $DEST"
echo
echo "  HEXA_HOME (packages) defaults to ~/.hexa; set HEXA_HOME to relocate."
echo "  Try: hexa version  |  hexa build examples/hello.he && ./hello"
echo "  Package manager:  hexa package [dir] && hexa install <file.hxpkg>"