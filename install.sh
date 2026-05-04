#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "$APP_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERR] python3 not found. Install Python 3 first."
  exit 1
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
pip install -r requirements.txt
chmod 700 "$APP_DIR" || true
chmod 700 "$VENV_DIR" || true
chmod +x "$APP_DIR/start.sh" || true

echo "[OK] VaultTerm environment installed. Start with: ./start.sh"
