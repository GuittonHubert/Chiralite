#!/usr/bin/env bash
# Install chiralite on macOS (Homebrew required).
#
# What this script does:
#   1. Locates or installs a compatible Python interpreter (>= 3.10)
#   2. Installs system dependencies via Homebrew (ClamAV, build tools)
#   3. Builds xdelta3 from the required fork
#   4. Installs chiralite via pip
#   5. Configures ClamAV (freshclam + clamd socket)
#   6. Optionally installs a launchd agent for the chiralite daemon
#
# macOS role note:
#   macOS is the typical *client* side of a chiralite pair.  The server-side
#   sandbox (tmpfs mount + clamd) is a Linux-only feature; on macOS the sandbox
#   falls back to a standard temp directory and ClamAV is optional.
#
# Usage:
#   bash scripts/install-macos.sh [--no-daemon] [--dev]
#
#   --no-daemon   Skip launchd agent installation
#   --dev         Install in editable mode (pip install -e .)

set -euo pipefail

INSTALL_DAEMON=true
EDITABLE=false
for arg in "$@"; do
    case "$arg" in
        --no-daemon) INSTALL_DAEMON=false ;;
        --dev)       EDITABLE=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
MIN_PYTHON_MINOR=10  # requires Python >= 3.10

log() { echo "[chiralite] $*"; }
die() { echo "[chiralite] ERROR: $*" >&2; exit 1; }

# ── Homebrew ───────────────────────────────────────────────────────────────────

if ! command -v brew >/dev/null 2>&1; then
    die "Homebrew is required but not installed.
Install it from https://brew.sh, then re-run this script."
fi

# ── locate a compatible Python ─────────────────────────────────────────────────
# Discovers every python3.X binary in PATH via regex, sorts them highest-minor
# first, then falls back to bare python3.  Stops at the first candidate that
# satisfies Python >= 3.$MIN_PYTHON_MINOR.  Sets PYTHON and PIP globals.
#
# Common locations searched (all on PATH when Homebrew / pyenv are set up):
#   /opt/homebrew/bin/python3.X   (Apple Silicon)
#   /usr/local/bin/python3.X      (Intel)
#   ~/.pyenv/shims/python3.X      (pyenv)

find_python() {
    local candidates
    mapfile -t candidates < <(
        {
            compgen -c | grep -E '^python3\.[0-9]+$' | sort -t. -k2 -rn
            echo python3
        } | uniq
    )
    for cmd in "${candidates[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            local minor major
            minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
            major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
            if [[ "$major" -eq 3 && "$minor" -ge "$MIN_PYTHON_MINOR" ]]; then
                PYTHON="$cmd"
                PIP="$cmd -m pip"
                log "Using Python: $($PYTHON --version)"
                return 0
            fi
        fi
    done
    return 1
}

# ── system dependencies ────────────────────────────────────────────────────────

if find_python; then
    log "Compatible Python already present — skipping Homebrew Python install"
    BREW_PYTHON_PKG=()
else
    log "No compatible Python (>= 3.10) found — will install via Homebrew"
    BREW_PYTHON_PKG=(python3)
fi

log "Installing system dependencies via Homebrew"
brew update --quiet
brew install --quiet "${BREW_PYTHON_PKG[@]}" git clamav

# Re-probe after potential Homebrew install
find_python || die "Python >= 3.10 not available even after Homebrew install"

# ── ClamAV ─────────────────────────────────────────────────────────────────────

log "Configuring ClamAV"
BREW_PREFIX="$(brew --prefix)"
CLAMD_CONF="$BREW_PREFIX/etc/clamav/clamd.conf"
FRESHCLAM_CONF="$BREW_PREFIX/etc/clamav/freshclam.conf"

# Homebrew ships example configs; activate them if not already done
if [[ ! -f "$CLAMD_CONF" && -f "${CLAMD_CONF}.sample" ]]; then
    cp "${CLAMD_CONF}.sample" "$CLAMD_CONF"
    # Switch from Foreground to background mode and set socket path
    sed -i '' 's|^#LocalSocket .*|LocalSocket /tmp/clamd.socket|' "$CLAMD_CONF"
    sed -i '' 's|^Example|#Example|'                               "$CLAMD_CONF"
    log "  created $CLAMD_CONF"
fi
if [[ ! -f "$FRESHCLAM_CONF" && -f "${FRESHCLAM_CONF}.sample" ]]; then
    cp "${FRESHCLAM_CONF}.sample" "$FRESHCLAM_CONF"
    sed -i '' 's|^Example|#Example|' "$FRESHCLAM_CONF"
    log "  created $FRESHCLAM_CONF"
fi

if command -v freshclam >/dev/null 2>&1; then
    freshclam --quiet 2>/dev/null || log "  freshclam: could not update (offline?), continuing"
fi

# ── xdelta3 ────────────────────────────────────────────────────────────────────

log "Building xdelta3 from fork"
PYTHON="$PYTHON" PIP="$PIP" bash "$SCRIPT_DIR/build-xdelta3.sh"

# ── chiralite ─────────────────────────────────────────────────────────────────

log "Installing chiralite"
if $EDITABLE; then
    $PIP install -e "$REPO_ROOT"
else
    $PIP install "$REPO_ROOT"
fi

$PYTHON -c "import chiralite.hash" 2>/dev/null || {
    log "  compiling rapidhash CFFI extension"
    $PYTHON -m chiralite._rapidhash_build
}

# ── launchd agent ─────────────────────────────────────────────────────────────

if $INSTALL_DAEMON; then
    CHIRALITE_BIN="$($PYTHON -c "import shutil; print(shutil.which('chiralite') or '')")"
    [[ -n "$CHIRALITE_BIN" ]] || CHIRALITE_BIN="$(brew --prefix)/bin/chiralite"
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.chiralite.daemon.plist"
    CONFIG_FILE="$HOME/.config/chiralite/config.yaml"

    log "Installing launchd agent: $PLIST_FILE"
    mkdir -p "$PLIST_DIR"
    cat > "$PLIST_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.chiralite.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>$CHIRALITE_BIN</string>
        <string>start</string>
        <string>--config</string>
        <string>$CONFIG_FILE</string>
    </array>
    <key>RunAtLoad</key>         <false/>
    <key>KeepAlive</key>         <false/>
    <key>StandardOutPath</key>   <string>$HOME/.local/share/chiralite/daemon.log</string>
    <key>StandardErrorPath</key> <string>$HOME/.local/share/chiralite/daemon.log</string>
</dict>
</plist>
PLIST

    mkdir -p "$HOME/.local/share/chiralite"
    log "  run 'launchctl load $PLIST_FILE' to start the daemon"
fi

# ── verify ─────────────────────────────────────────────────────────────────────

log "Verifying installation"
chiralite --version && log "chiralite is ready."
log ""
log "Next steps:"
log "  1. Generate keys:  chiralite keygen --out-dir ~/.config/chiralite"
log "  2. Edit config:    ~/.config/chiralite/config.yaml  (see docs/install.md)"
log "  3. Start daemon:   chiralite start"
