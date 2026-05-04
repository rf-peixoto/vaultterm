#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/.venv"
SCRIPT="$APP_DIR/vaultterm.py"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[ERR] virtual environment not found. Run ./install.sh first."
  exit 1
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
exec python "$SCRIPT"
