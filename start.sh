#!/usr/bin/env bash
# VaultTerm -- start.sh  (runs from source; arguments are passed through,
# e.g. ./start.sh --restore FILE.vtbak  or  ./start.sh --recover)
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/.venv"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[ERR] virtual environment not found. Run ./install.sh first." >&2
  exit 1
fi

# Catches accidental or naive modification of the source files. A real
# attacker who can edit these files can also edit this script: authenticity
# comes from checking the GPG signature with ./verify.sh --source BEFORE you
# run anything (see README, "Verifying a release").
if [[ -f "$APP_DIR/SOURCE-B2SUMS" ]]; then
  if ! (cd "$APP_DIR" && b2sum --quiet --strict -c SOURCE-B2SUMS); then
    echo "[ERR] source files do not match SOURCE-B2SUMS. refusing to start." >&2
    exit 1
  fi
fi

umask 077
# -I: isolated mode (ignores PYTHON* env vars and the user site-packages dir)
exec "$VENV_DIR/bin/python" -I "$APP_DIR/vaultterm.py" "$@"
