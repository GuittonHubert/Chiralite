#!/usr/bin/env bash
# Build and install xdelta3 from the jmacd release3_1_apl fork.
#
# The PyPI package (0.0.5) links against xdelta 3.0 and is not compatible
# with this project. This script builds from the fork that ships xdelta 3.1
# (APL licence) with the Python 3.10 fix applied.
#
# Usage:
#   bash scripts/build-xdelta3.sh          # build into a temp dir, pip install
#   bash scripts/build-xdelta3.sh --check  # verify the installed version only

set -euo pipefail

REPO_URL="https://github.com/samuelcolvin/xdelta3-python.git"
BRANCH="master"
BUILD_DIR="${TMPDIR:-/tmp}/xdelta3-python-build"

# Honour PYTHON/PIP set by a parent installer; fall back to bare python3/pip3.
PYTHON="${PYTHON:-python3}"
PIP="${PIP:-$PYTHON -m pip}"

# ── helpers ────────────────────────────────────────────────────────────────────

log()  { echo "[xdelta3] $*"; }
die()  { echo "[xdelta3] ERROR: $*" >&2; exit 1; }

check_cmd() { command -v "$1" >/dev/null 2>&1 || die "$1 not found — install it first"; }

# ── --check mode ───────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--check" ]]; then
    $PYTHON -c "
import xdelta3, importlib.metadata
v = importlib.metadata.version('xdelta3')
print(f'xdelta3 {v} — OK')
" && exit 0
    die "xdelta3 not importable"
fi

# ── prerequisites ──────────────────────────────────────────────────────────────

check_cmd "$PYTHON"
check_cmd git

# C build tools
if [[ "$(uname)" == "Darwin" ]]; then
    check_cmd clang
else
    check_cmd gcc
fi

log "Cloning $REPO_URL@$BRANCH into $BUILD_DIR"
rm -rf "$BUILD_DIR"
git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$BUILD_DIR"

# Patch: add missing assert.h include and force gnu11 for inline compatibility
log "Applying patches to xdelta3 C sources"
XDELTA_C="$BUILD_DIR/xdelta3/xdelta3.c"
if [[ -f "$XDELTA_C" ]]; then
    if ! grep -q "#include <assert.h>" "$XDELTA_C"; then
        sed -i.bak '1s|^|#include <assert.h>\n|' "$XDELTA_C"
        log "  added #include <assert.h>"
    fi
fi

log "Building and installing xdelta3"
CFLAGS="${CFLAGS:+$CFLAGS }-std=gnu11" $PIP install --no-build-isolation "$BUILD_DIR"

log "Verifying install"
PYTHON="$PYTHON" PIP="$PIP" bash "$0" --check

log "Done — xdelta3 is ready."
