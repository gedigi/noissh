#!/bin/sh
# noissh installer — https://github.com/gedigi/noissh
#
#   curl -fsSL https://raw.githubusercontent.com/gedigi/noissh/main/install.sh | sh
#
# Installs the `noissh` (client) and `noisshd` (server) binaries. Tries a
# prebuilt release for your platform first, then falls back to building from
# source with cargo (offering to install Rust via rustup if needed).
#
# Environment / flags:
#   NOISSH_BIN_DIR=DIR   install location (default: ~/.local/bin, or /usr/local/bin if writable)
#   NOISSH_VERSION=vX     release tag to install (default: latest)
#   --yes / -y            non-interactive (assume yes to prompts)
#   --build               force building from source
#   --uninstall           remove installed binaries

set -eu

REPO="gedigi/noissh"
RAW_REPO="https://github.com/${REPO}"
BINS="noissh noisshd"
ASSUME_YES="${NOISSH_ASSUME_YES:-0}"
FORCE_BUILD=0
DO_UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --build) FORCE_BUILD=1 ;;
    --uninstall) DO_UNINSTALL=1 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

# ---------- pretty output ----------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
  GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m'); BLU=$(printf '\033[36m')
  RST=$(printf '\033[0m')
else
  BOLD=; DIM=; RED=; GRN=; YEL=; BLU=; RST=
fi
step() { printf '%s==>%s %s\n' "$BLU$BOLD" "$RST$BOLD" "$1$RST"; }
info() { printf '    %s\n' "$1"; }
warn() { printf '%swarning:%s %s\n' "$YEL" "$RST" "$1" >&2; }
err()  { printf '%serror:%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }
ok()   { printf '%s✓%s %s\n' "$GRN" "$RST" "$1"; }

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  printf '%s [Y/n] ' "$1"
  read -r reply </dev/tty 2>/dev/null || return 0
  case "$reply" in n*|N*) return 1 ;; *) return 0 ;; esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------- choose an install directory ----------
choose_bindir() {
  if [ -n "${NOISSH_BIN_DIR:-}" ]; then printf '%s' "$NOISSH_BIN_DIR"; return; fi
  if [ -w /usr/local/bin ] 2>/dev/null; then printf '/usr/local/bin'; return; fi
  printf '%s/.local/bin' "$HOME"
}
BIN_DIR=$(choose_bindir)

# ---------- uninstall ----------
if [ "$DO_UNINSTALL" = 1 ]; then
  step "Uninstalling noissh from ${BIN_DIR}"
  for b in $BINS; do
    if [ -e "${BIN_DIR}/${b}" ]; then rm -f "${BIN_DIR}/${b}" && ok "removed ${BIN_DIR}/${b}"; fi
  done
  info "Config in ~/.config/noissh was left untouched."
  exit 0
fi

# ---------- detect platform ----------
detect_target() {
  os=$(uname -s); arch=$(uname -m)
  case "$os" in
    Linux)  os_t=unknown-linux-gnu ;;
    Darwin) os_t=apple-darwin ;;
    *) printf ''; return ;;
  esac
  case "$arch" in
    x86_64|amd64) arch_t=x86_64 ;;
    aarch64|arm64) arch_t=aarch64 ;;
    *) printf ''; return ;;
  esac
  printf '%s-%s' "$arch_t" "$os_t"
}
TARGET=$(detect_target)

printf '%s\n' "${BOLD}noissh installer${RST}"
info "${DIM}resilient remote shell over the Noise protocol${RST}"
echo

# ---------- try a prebuilt release ----------
install_prebuilt() {
  [ -n "$TARGET" ] || return 1
  have curl || have wget || return 1
  ver="${NOISSH_VERSION:-latest}"
  if [ "$ver" = latest ]; then
    base="${RAW_REPO}/releases/latest/download"
  else
    base="${RAW_REPO}/releases/download/${ver}"
  fi
  asset="noissh-${TARGET}.tar.gz"
  url="${base}/${asset}"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  step "Looking for a prebuilt release (${TARGET})"
  if have curl; then
    curl -fsSL "$url" -o "$tmp/$asset" 2>/dev/null || return 1
  else
    wget -qO "$tmp/$asset" "$url" 2>/dev/null || return 1
  fi
  tar -xzf "$tmp/$asset" -C "$tmp" 2>/dev/null || return 1
  mkdir -p "$BIN_DIR"
  for b in $BINS; do
    f=$(find "$tmp" -type f -name "$b" | head -1)
    [ -n "$f" ] || return 1
    install -m 0755 "$f" "${BIN_DIR}/${b}"
  done
  ok "Installed prebuilt binaries to ${BIN_DIR}"
  return 0
}

# ---------- build from source ----------
ensure_rust() {
  have cargo && return 0
  warn "Rust (cargo) was not found."
  if confirm "Install the Rust toolchain via rustup now?"; then
    if have curl; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
    elif have wget; then
      wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal
    else
      err "Need curl or wget to install Rust."
    fi
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env" 2>/dev/null || true
  fi
  have cargo || err "cargo is still unavailable; install Rust and re-run."
}

install_from_source() {
  step "Building from source with cargo"
  ensure_rust
  ver="${NOISSH_VERSION:-}"
  if [ -n "$ver" ]; then tagopt="--tag $ver"; else tagopt=""; fi
  info "This compiles noissh and noisshd (a minute or two)…"
  # shellcheck disable=SC2086
  CARGO_INSTALL_ROOT="$tmproot" cargo install --git "${RAW_REPO}" $tagopt --bins --quiet
  mkdir -p "$BIN_DIR"
  for b in $BINS; do
    install -m 0755 "$tmproot/bin/$b" "${BIN_DIR}/${b}"
  done
  ok "Built and installed to ${BIN_DIR}"
}

tmproot=$(mktemp -d)
trap 'rm -rf "$tmproot"' EXIT

if [ "$FORCE_BUILD" = 1 ]; then
  install_from_source
elif ! install_prebuilt; then
  info "No prebuilt release available; falling back to a source build."
  install_from_source
fi

# ---------- PATH hint + next steps ----------
echo
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *)
    warn "${BIN_DIR} is not on your PATH."
    shellrc="$HOME/.profile"
    case "${SHELL:-}" in *zsh) shellrc="$HOME/.zshrc" ;; *bash) shellrc="$HOME/.bashrc" ;; esac
    info "Add it with:"
    info "  ${BOLD}echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ${shellrc}${RST}"
    ;;
esac

echo
ok "noissh installed."
printf '\n%sGet started%s\n' "$BOLD" "$RST"
info "Connect to a host you can already SSH into (recommended):"
info "  ${BOLD}noissh --ssh user@host${RST}"
info "  ${DIM}(requires noisshd installed on the remote host)${RST}"
echo
info "Or run a standalone server, then connect directly:"
info "  ${BOLD}noisshd --listen 0.0.0.0:51820${RST}    ${DIM}# on the server${RST}"
info "  ${BOLD}noissh user@host${RST}                   ${DIM}# from your machine${RST}"
echo
info "Your client key is generated on first run at ~/.config/noissh/id"
info "Docs: ${RAW_REPO}#documentation"
