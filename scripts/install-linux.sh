#!/usr/bin/env bash
# Install chiralite on Linux (Debian/Ubuntu, RHEL/Fedora, or Arch).
#
# What this script does:
#   1. Locates or installs a compatible Python interpreter (>= 3.10)
#   2. Installs system dependencies (ClamAV, build tools)
#   3. Builds xdelta3 from the required fork
#   4. Installs chiralite via pip
#   5. Mounts the sandbox tmpfs at /run/chiralite/sandbox
#   6. Configures ClamAV (freshclam + clamd socket)
#   7. Optionally installs a systemd unit for the chiralite daemon
#
# Requires: root (sudo) for system packages and mount.
#
# Usage:
#   sudo bash scripts/install-linux.sh [--no-service] [--dev]
#
#   --no-service   Skip systemd unit installation
#   --dev          Install in editable mode (pip install -e .)

set -euo pipefail

INSTALL_SERVICE=true
EDITABLE=false
for arg in "$@"; do
    case "$arg" in
        --no-service) INSTALL_SERVICE=false ;;
        --dev)        EDITABLE=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SANDBOX_MOUNT="/run/chiralite/sandbox"
MIN_PYTHON_MINOR=10  # requires Python >= 3.10

log()      { echo "[chiralite] $*"; }
die()      { echo "[chiralite] ERROR: $*" >&2; exit 1; }
need_root(){ [[ "$EUID" -eq 0 ]] || die "Run as root or with sudo: sudo $0 $*"; }

# ── locate a compatible Python ─────────────────────────────────────────────────
# Discovers every python3.X binary in PATH via regex, sorts them highest-minor
# first, then falls back to bare python3.  Stops at the first candidate that
# satisfies Python >= 3.$MIN_PYTHON_MINOR.  Sets PYTHON and PIP globals.

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

# ── detect package manager ─────────────────────────────────────────────────────

if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
else
    die "Unsupported Linux distribution — install dependencies manually (see docs/install.md)"
fi

# ── system dependencies ────────────────────────────────────────────────────────

need_root

# Try to find a compatible Python before installing anything
if find_python; then
    log "Compatible Python already present — skipping Python package install"
    PY_PKGS=()
else
    log "No compatible Python (>= 3.10) found — will install system Python"
    case "$PKG_MGR" in
        apt)    PY_PKGS=(python3 python3-dev python3-pip python3-venv) ;;
        dnf)    PY_PKGS=(python3 python3-devel python3-pip) ;;
        pacman) PY_PKGS=(python python-pip) ;;
    esac
fi

log "Installing system dependencies (package manager: $PKG_MGR)"
case "$PKG_MGR" in
    apt)
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            "${PY_PKGS[@]}" \
            gcc make git \
            clamav clamav-daemon
        ;;
    dnf)
        dnf install -y \
            "${PY_PKGS[@]}" \
            gcc make git \
            clamav clamav-update clamd
        ;;
    pacman)
        pacman -Sy --noconfirm \
            "${PY_PKGS[@]}" \
            gcc make git \
            clamav
        ;;
esac

# Re-probe after potential install
find_python || die "Python >= 3.10 not available even after install — check your distro's Python packages"

# ── sandbox tmpfs ──────────────────────────────────────────────────────────────

log "Setting up sandbox tmpfs at $SANDBOX_MOUNT"
mkdir -p "$SANDBOX_MOUNT"
if ! mountpoint -q "$SANDBOX_MOUNT"; then
    mount -t tmpfs -o size=256m,mode=0700,uid=0,gid=0 tmpfs "$SANDBOX_MOUNT"
    log "  tmpfs mounted (256 MiB)"
else
    log "  tmpfs already mounted — skipping"
fi

FSTAB_ENTRY="tmpfs  $SANDBOX_MOUNT  tmpfs  size=256m,mode=0700  0  0"
if ! grep -qF "$SANDBOX_MOUNT" /etc/fstab; then
    echo "$FSTAB_ENTRY" >> /etc/fstab
    log "  added fstab entry"
fi

# ── ClamAV ─────────────────────────────────────────────────────────────────────

log "Configuring ClamAV"
if command -v freshclam >/dev/null 2>&1; then
    freshclam --quiet || log "  freshclam: could not update (offline?), continuing"
fi

CLAMD_CONF="/etc/clamav/clamd.conf"
[[ -f "$CLAMD_CONF" ]] || CLAMD_CONF="/etc/clamd.d/scan.conf"
if [[ -f "$CLAMD_CONF" ]]; then
    SOCKET_PATH="/run/clamav/clamd.ctl"
    if ! grep -q "^LocalSocket " "$CLAMD_CONF"; then
        echo "LocalSocket $SOCKET_PATH" >> "$CLAMD_CONF"
        log "  set LocalSocket $SOCKET_PATH"
    fi
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

# ── systemd unit ───────────────────────────────────────────────────────────────

if $INSTALL_SERVICE; then
    CHIRALITE_BIN="$($PYTHON -c "import shutil; print(shutil.which('chiralite') or '')")"
    [[ -n "$CHIRALITE_BIN" ]] || CHIRALITE_BIN="/usr/local/bin/chiralite"

    log "Installing systemd unit: chiralite.service"
    cat > /etc/systemd/system/chiralite.service <<UNIT
[Unit]
Description=chiralite file synchronisation daemon
After=network-online.target clamav-daemon.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$CHIRALITE_BIN start --config /etc/chiralite/config.yaml
Restart=on-failure
RestartSec=5
User=chiralite
Group=chiralite
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/var/log/chiralite /var/lib/chiralite

[Install]
WantedBy=multi-user.target
UNIT

    id chiralite >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false chiralite
    mkdir -p /etc/chiralite /var/log/chiralite /var/lib/chiralite
    chown -R chiralite:chiralite /var/log/chiralite /var/lib/chiralite
    systemctl daemon-reload
    log "  run 'systemctl enable --now chiralite' to start the daemon"
fi

# ── verify ─────────────────────────────────────────────────────────────────────

log "Verifying installation"
chiralite --version && log "chiralite is ready."
log ""
log "Next steps:"
log "  1. Generate keys:  chiralite keygen --out-dir ~/.config/chiralite"
log "  2. Edit config:    /etc/chiralite/config.yaml  (see docs/install.md)"
log "  3. Start daemon:   chiralite start  (or: systemctl start chiralite)"
