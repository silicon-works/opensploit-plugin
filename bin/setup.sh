#!/bin/bash
# OpenSploit Setup
#
# Installs the opensploit-hosts helper script and configures passwordless sudo.
# Run once after installing the plugin. Safe to run multiple times.
#
# Usage:
#   ./bin/setup.sh          # Interactive — prompts for sudo password once
#   sudo ./bin/setup.sh     # If already root

set -euo pipefail

HELPER_NAME="opensploit-hosts"
HELPER_SRC="$(cd "$(dirname "$0")" && pwd)/${HELPER_NAME}"
HELPER_DEST="/usr/local/bin/${HELPER_NAME}"
SUDOERS_FILE="/etc/sudoers.d/opensploit"

# Colors (if terminal supports them)
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' NC=''
fi

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1" >&2; }

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

if [[ ! -f "$HELPER_SRC" ]]; then
  error "Helper script not found at: $HELPER_SRC"
  error "Run this script from the opensploit-plugin directory."
  exit 1
fi

# ---------------------------------------------------------------------------
# Install helper script
# ---------------------------------------------------------------------------

install_helper() {
  local needs_install=0

  if [[ -f "$HELPER_DEST" ]]; then
    # Check if it needs updating
    if cmp -s "$HELPER_SRC" "$HELPER_DEST"; then
      info "Helper script already installed and up to date."
    else
      warn "Helper script exists but differs — updating."
      needs_install=1
    fi
  else
    needs_install=1
  fi

  if [[ $needs_install -eq 1 ]]; then
    cp "$HELPER_SRC" "$HELPER_DEST"
    chown root:root "$HELPER_DEST"
    chmod 755 "$HELPER_DEST"
    info "Installed helper script to $HELPER_DEST"
  fi
}

# ---------------------------------------------------------------------------
# Configure sudoers
# ---------------------------------------------------------------------------

configure_sudoers() {
  local target_user="${SUDO_USER:-$USER}"

  if [[ -z "$target_user" || "$target_user" == "root" ]]; then
    # If run directly as root without sudo, ask for the username
    if [[ -n "${1:-}" ]]; then
      target_user="$1"
    else
      error "Could not determine target user. Run with: sudo ./bin/setup.sh"
      error "Or specify user: sudo ./bin/setup.sh --user USERNAME"
      exit 1
    fi
  fi

  local sudoers_line="${target_user} ALL=(ALL) NOPASSWD: ${HELPER_DEST}"

  if [[ -f "$SUDOERS_FILE" ]]; then
    if grep -qF "$sudoers_line" "$SUDOERS_FILE" 2>/dev/null; then
      info "Sudoers entry already configured for $target_user."
      return
    else
      warn "Sudoers file exists but has different content — updating."
    fi
  fi

  # Validate the sudoers line before writing
  echo "$sudoers_line" > "$SUDOERS_FILE"
  chmod 440 "$SUDOERS_FILE"

  # Verify sudoers syntax
  if visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
    info "Configured passwordless sudo for $target_user → $HELPER_DEST"
  else
    error "Sudoers syntax check failed — removing invalid entry."
    rm -f "$SUDOERS_FILE"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Purge stale entries
# ---------------------------------------------------------------------------

purge_stale() {
  if grep -q "^# opensploit-session:" /etc/hosts 2>/dev/null; then
    local count
    count=$(grep -c "^# opensploit-session:" /etc/hosts 2>/dev/null || true)
    warn "Found $count stale opensploit blocks in /etc/hosts."
    "$HELPER_DEST" purge
    info "Purged stale entries from /etc/hosts."
  fi
}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

verify() {
  local target_user="${SUDO_USER:-$USER}"

  # Test as the target user
  if sudo -u "$target_user" sudo -n "$HELPER_DEST" check >/dev/null 2>&1; then
    info "Verification passed — $target_user can run $HELPER_NAME without password."
  else
    warn "Verification inconclusive — you may need to log out and back in."
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ""
echo "  OpenSploit Setup"
echo "  ================"
echo ""

# Parse --user flag
TARGET_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) TARGET_USER="$2"; shift 2 ;;
    *) error "Unknown option: $1"; exit 1 ;;
  esac
done

# Need root for installation
if [[ $EUID -ne 0 ]]; then
  info "This script needs root access. You'll be prompted for your password once."
  echo ""
  exec sudo "$0" ${TARGET_USER:+--user "$TARGET_USER"}
fi

install_helper
configure_sudoers "$TARGET_USER"
purge_stale
verify

echo ""
info "Setup complete. No more password prompts during engagements."
echo ""
