#!/usr/bin/env bash
# VaultTerm -- install.sh
# Creates .venv and installs the hash-pinned runtime dependencies.
# Only prebuilt wheels are accepted (no setup.py code runs during install).
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "$APP_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERR] VaultTerm v4 supports Linux only." >&2
  exit 1
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERR] $PYTHON_BIN not found. Install Python 3.10 or newer first." >&2
  exit 1
fi
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "[ERR] Python 3.10 or newer is required." >&2
  exit 1
fi

if [[ -f SOURCE-SHA256SUMS ]]; then
  echo "[SYS] verifying source files against SOURCE-SHA256SUMS..."
  ./verify.sh --source
fi

umask 077
"$PYTHON_BIN" -m venv "$VENV_DIR"
# pip itself is NOT upgraded from the network: an unpinned upgrade would be
# the one unverified download in the whole install.
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-input \
    --require-hashes --only-binary=:all: -r requirements.txt

"$VENV_DIR/bin/python" "$APP_DIR/vaultterm.py" --selftest

chmod 700 "$APP_DIR" "$VENV_DIR" || true
chmod +x "$APP_DIR/start.sh" "$APP_DIR/compile.sh" "$APP_DIR/verify.sh" || true

echo "[OK] VaultTerm environment installed. Start with: ./start.sh"
