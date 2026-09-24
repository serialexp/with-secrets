#!/usr/bin/env bash
#
# Install the `ws` (with-secrets) binary from GitHub Releases.
#
# The binary dynamically links libfido2, so this script also makes sure
# libfido2 is installed via Homebrew (asking first when run interactively).
#
#   curl -fsSL https://raw.githubusercontent.com/serialexp/with-secrets/main/install.sh | bash
#
# Environment overrides:
#   WS_VERSION       release tag to install (default: latest)
#   WS_INSTALL_DIR   where to put the binary  (default: $HOME/.local/bin)
#   WS_ASSUME_YES=1  answer yes to all prompts (installs libfido2 without asking)
#   WS_SKIP_DEPS=1   don't touch Homebrew / libfido2 at all

set -euo pipefail

REPO="serialexp/with-secrets"
ASSET="ws-darwin-arm64"
VERSION="${WS_VERSION:-latest}"
INSTALL_DIR="${WS_INSTALL_DIR:-$HOME/.local/bin}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# prompt_yes_no MESSAGE [default Y|N] — reads from the terminal even when the
# script itself is piped from curl. Falls back to the default when there is no
# terminal (fully non-interactive), and honours WS_ASSUME_YES.
prompt_yes_no() {
  local msg="$1" default="${2:-Y}" reply hint
  if [ "${WS_ASSUME_YES:-0}" = "1" ]; then return 0; fi
  if [ -e /dev/tty ] && [ -r /dev/tty ]; then
    [ "$default" = "Y" ] && hint="[Y/n]" || hint="[y/N]"
    printf '%s %s ' "$msg" "$hint" > /dev/tty
    read -r reply < /dev/tty || reply=""
    [ -z "$reply" ] && reply="$default"
    case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
  fi
  [ "$default" = "Y" ]
}

download() { # URL DEST
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    err "need curl or wget to download"
  fi
}

# --- platform check -------------------------------------------------------

os="$(uname -s)"
arch="$(uname -m)"
if [ "$os" != "Darwin" ] || [ "$arch" != "arm64" ]; then
  err "prebuilt binaries are only published for macOS arm64 (Apple Silicon).
       You're on $os/$arch — build from source instead: go build ./cmd/ws"
fi

# --- dependency: libfido2 via Homebrew ------------------------------------

if [ "${WS_SKIP_DEPS:-0}" = "1" ]; then
  info "skipping dependency check (WS_SKIP_DEPS=1)"
elif command -v brew >/dev/null 2>&1; then
  if brew list --formula libfido2 >/dev/null 2>&1; then
    info "libfido2 already installed"
  else
    if prompt_yes_no "libfido2 is required to run ws. Install it now with 'brew install libfido2'?"; then
      info "installing libfido2..."
      brew install libfido2
    else
      warn "libfido2 not installed — ws will fail to run until you 'brew install libfido2'."
    fi
  fi
else
  warn "Homebrew not found. ws needs libfido2 at runtime."
  warn "Install Homebrew (https://brew.sh) then run 'brew install libfido2', or"
  warn "install libfido2 by other means before running ws."
  prompt_yes_no "Continue installing the ws binary anyway?" || err "aborted"
fi

# --- download binary + checksum -------------------------------------------

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "downloading $ASSET ($VERSION)..."
download "$base/$ASSET" "$tmp/$ASSET"
download "$base/$ASSET.sha256" "$tmp/$ASSET.sha256"

info "verifying checksum..."
( cd "$tmp" && shasum -a 256 -c "$ASSET.sha256" ) || err "checksum verification failed"

# curl/wget don't normally set the macOS quarantine flag, but strip it if present
# so Gatekeeper doesn't block the first run.
xattr -d com.apple.quarantine "$tmp/$ASSET" 2>/dev/null || true

# --- install --------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/$ASSET" "$INSTALL_DIR/ws"
info "installed ws -> $INSTALL_DIR/ws"

if ! printf '%s' ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
  warn "$INSTALL_DIR is not on your PATH. Add it, e.g.:"
  printf '\n    echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc && exec zsh\n\n' "$INSTALL_DIR"
fi

"$INSTALL_DIR/ws" version || true
info "done. Run 'ws init' to create your store."
