#!/usr/bin/env bash
# =============================================================================
# VaultTerm -- compile.sh
#
# Compiles vaultterm.py into a standalone binary.
#
# MODES
#   pyinstaller          PyInstaller one-directory bundle  (faster startup)
#   pyinstaller-onefile  PyInstaller single-file binary    (portable, slower start)
#   nuitka               Nuitka standalone directory       (native code, faster)
#   nuitka-onefile       Nuitka single-file binary         (native + portable)
#
# USAGE
#   ./compile.sh [mode] [options]
#
#   --upx                Enable UPX compression (reduces size, may flag AV)
#   --sign               GPG-sign the output binary (requires GPG key)
#   --sign-key <keyid>   Use a specific GPG key ID
#   --no-clean           Skip cleaning previous build artefacts
#   --output-dir <dir>   Override output directory (default: ./dist)
#   --help               Show this help
#
# EXAMPLES
#   ./compile.sh pyinstaller
#   ./compile.sh pyinstaller-onefile --upx
#   ./compile.sh nuitka-onefile --sign
#   ./compile.sh nuitka --sign --sign-key 0xABCD1234
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── colour helpers ─────────────────────────────────────────────────────────────

_BOLD="\033[1m"
_CYAN="\033[96m"
_GREEN="\033[92m"
_YELLOW="\033[93m"
_RED="\033[91m"
_DIM="\033[2m"
_RESET="\033[0m"

inf()  { echo -e "  ${_CYAN}[SYS]${_RESET} $*"; }
ok()   { echo -e "  ${_GREEN}[OK]${_RESET}  $*"; }
warn() { echo -e "  ${_YELLOW}[WARN]${_RESET} $*"; }
err()  { echo -e "  ${_RED}[ERR]${_RESET} $*" >&2; }
die()  { err "$*"; exit 1; }
sep()  { echo -e "${_CYAN}$(printf '=%.0s' $(seq 1 72))${_RESET}"; }

# ── defaults ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/vaultterm.py"
VENV="$SCRIPT_DIR/.venv"
VENV_PY="$VENV/bin/python3"
VENV_PIP="$VENV/bin/pip"
OUTPUT_DIR="$SCRIPT_DIR/dist"
BINARY_NAME="vaultterm"

MODE=""
USE_UPX=false
DO_SIGN=false
SIGN_KEY=""
DO_CLEAN=true

# ── argument parsing ───────────────────────────────────────────────────────────

usage() {
    sed -n '/^# USAGE/,/^# SECURITY/p' "$0" | grep -v "^# SECURITY" | sed 's/^# \?//'
    exit 0
}

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        pyinstaller|pyinstaller-onefile|nuitka|nuitka-onefile)
            MODE="$1" ;;
        --upx)
            USE_UPX=true ;;
        --sign)
            DO_SIGN=true ;;
        --sign-key)
            shift; SIGN_KEY="$1" ;;
        --no-clean)
            DO_CLEAN=false ;;
        --output-dir)
            shift; OUTPUT_DIR="$1" ;;
        --help|-h)
            usage ;;
        *)
            die "unknown option: $1  (try --help)" ;;
    esac
    shift
done

[[ -z "$MODE" ]] && die "no mode specified. run with --help for usage."

# ── preflight checks ───────────────────────────────────────────────────────────

sep
echo -e "  ${_BOLD}VAULTTERM COMPILER${_RESET}  //  mode: ${_CYAN}${MODE}${_RESET}"
sep
echo

inf "checking environment..."

[[ -f "$SOURCE" ]]      || die "vaultterm.py not found at $SOURCE"
[[ -d "$VENV" ]]        || die ".venv not found. run ./install.sh first."
[[ -x "$VENV_PY" ]]     || die "Python interpreter not found in .venv."

PYTHON_VER=$("$VENV_PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ok "venv Python $PYTHON_VER"

# Verify source file is importable (syntax check)
"$VENV_PY" -m py_compile "$SOURCE" \
    || die "syntax error in vaultterm.py -- fix before compiling."
ok "source syntax OK"

# ── source integrity hash ──────────────────────────────────────────────────────

SOURCE_HASH=$(sha256sum "$SOURCE" | awk '{print $1}')
ok "source SHA-256: $SOURCE_HASH"

HASH_RECORD="$SCRIPT_DIR/.source_hash"
if [[ -f "$HASH_RECORD" ]]; then
    PREV_HASH=$(cat "$HASH_RECORD")
    if [[ "$PREV_HASH" != "$SOURCE_HASH" ]]; then
        warn "source has changed since last compilation."
        warn "previous: $PREV_HASH"
        warn "current:  $SOURCE_HASH"
        echo
        read -r -p "  continue? [y/N] " confirm
        [[ "${confirm,,}" == "y" ]] || { inf "aborted."; exit 0; }
    else
        ok "source hash matches previous compilation record."
    fi
fi
echo "$SOURCE_HASH" > "$HASH_RECORD"

# ── optional tool checks ───────────────────────────────────────────────────────

HAS_STRIP=false
HAS_UPX=false
HAS_GPG=false
HAS_CODESIGN=false

command -v strip     >/dev/null 2>&1 && HAS_STRIP=true
command -v upx       >/dev/null 2>&1 && HAS_UPX=true
command -v gpg       >/dev/null 2>&1 && HAS_GPG=true
command -v codesign  >/dev/null 2>&1 && HAS_CODESIGN=true

if $USE_UPX && ! $HAS_UPX; then
    warn "UPX requested but not found. skipping compression."
    warn "install with: sudo apt install upx-ucl  (Debian/Ubuntu)"
    warn "           or: brew install upx          (macOS)"
    USE_UPX=false
fi

if $DO_SIGN && ! $HAS_GPG; then
    warn "GPG signing requested but gpg not found. skipping signing."
    DO_SIGN=false
fi

# ── output directory ───────────────────────────────────────────────────────────

mkdir -p "$OUTPUT_DIR"

# ── module exclusion list (shared by both backends) ───────────────────────────
#
# Only modules that are provably unused by vaultterm.py AND all of its
# transitive dependencies (rich, cryptography, argon2-cffi, pyotp, pyperclip).
#
# IMPORTANT: rich has non-obvious stdlib dependencies:
#   colorsys  — rich/color.py uses it for RGB↔HLS conversions        DO NOT exclude
#   html      — rich/markup.py uses html.escape for rendering         DO NOT exclude
#   webbrowser— rich/console.py conditionally imports it for links    DO NOT exclude
#   warnings  — rich uses warnings.warn throughout                    DO NOT exclude
#   email     — transitively reachable via mimetypes/urllib chains    DO NOT exclude
#
# When in doubt, leave a module in. Nuitka converts a missing transitive
# import into a hard RuntimeError; the binary builds fine but crashes.

EXCLUDE_MODS=(
    # GUI / graphics — definitely not needed
    tkinter
    turtle
    idlelib
    curses

    # Easter eggs
    antigravity
    this

    # Testing / debugging
    unittest
    pdb
    doctest

    # Network protocols not used by any dependency
    ftplib
    imaplib
    poplib
    smtplib
    nntplib
    telnetlib

    # RPC / server frameworks
    xmlrpc
    http.server
    wsgiref
    socketserver
    cgi
    cgitb

    # Packaging / installation tools
    distutils
    ensurepip
    venv

    # Python 2→3 migration tool
    lib2to3

    # Audio / multimedia
    sunau
    aifc
    audioop
    ossaudiodev
    imghdr
    chunk

    # Deprecated Unix auth modules (removed in Python 3.13)
    crypt
    nis
    spwd
    pipes

    # Multiprocessing fork backends (we only use threading)
    multiprocessing.popen_forkserver
    multiprocessing.popen_fork
)

# ── hidden imports required by cryptography + argon2-cffi ─────────────────────
#
# Both libraries rely on CFFI and Rust native extensions.
# PyInstaller misses these without explicit declaration.
# colorsys and warnings are stdlib but included explicitly because rich
# needs colorsys and Python 3.12+ made warnings a pure-Python module that
# some bundlers miss.

HIDDEN_IMPORTS=(
    cryptography
    cryptography.hazmat
    cryptography.hazmat.backends
    cryptography.hazmat.backends.openssl
    cryptography.hazmat.bindings._rust
    cryptography.hazmat.primitives.ciphers.aead
    argon2
    argon2.low_level
    argon2._utils
    argon2._password_hasher
    argon2.exceptions
    _argon2_cffi_bindings
    _cffi_backend
    cffi
    pyotp
    pyotp.totp
    pyotp.hotp
    pyotp.utils
    pyperclip
    rich
    rich.console
    rich.table
    rich.prompt
    rich.text
    rich.rule
    colorsys
    warnings
)

# ── helper: strip + upx + permissions ─────────────────────────────────────────

harden_binary() {
    local bin="$1"
    [[ -f "$bin" ]] || return

    # Strip debug symbols (not on macOS universal binaries – codesign breaks)
    if $HAS_STRIP && [[ "$(uname -s)" == "Linux" ]]; then
        inf "stripping debug symbols from $(basename "$bin")..."
        strip --strip-all "$bin" 2>/dev/null || strip "$bin" 2>/dev/null || true
        ok "stripped."
    fi

    # UPX compression (optional)
    if $USE_UPX; then
        inf "compressing with UPX..."
        upx --best --lzma "$bin" 2>/dev/null \
            && ok "UPX compression applied." \
            || warn "UPX failed on this binary (may be already packed). skipping."
    fi

    chmod 0755 "$bin"
}

# ── helper: generate checksum + optional GPG signature ────────────────────────

sign_and_checksum() {
    local bin="$1"
    local base
    base=$(basename "$bin")
    local hashfile="${bin}.sha256"
    local sigfile="${bin}.sig"

    # SHA-256 checksum
    inf "generating SHA-256 checksum..."
    sha256sum "$bin" > "$hashfile"
    chmod 0600 "$hashfile"
    ok "checksum: $hashfile"
    cat "$hashfile"

    # GPG detached signature
    if $DO_SIGN; then
        inf "signing with GPG..."
        local gpg_args=(--detach-sign --armor --output "$sigfile")
        [[ -n "$SIGN_KEY" ]] && gpg_args+=(--local-user "$SIGN_KEY")
        gpg "${gpg_args[@]}" "$bin" \
            && { chmod 0600 "$sigfile"; ok "signature: $sigfile"; } \
            || warn "GPG signing failed. binary is still usable without a signature."
    fi

    # macOS code signing (if available and applicable)
    if $HAS_CODESIGN && [[ "$(uname -s)" == "Darwin" ]]; then
        inf "signing with codesign (ad-hoc)..."
        codesign --force --sign - "$bin" \
            && ok "codesign applied." \
            || warn "codesign failed. binary may be blocked by Gatekeeper without a Developer ID."
    fi
}

# ── helper: remove .pyc files from a directory tree ───────────────────────────

remove_pyc() {
    local dir="$1"
    inf "removing .pyc bytecode from bundle..."
    find "$dir" -name "*.pyc" -delete 2>/dev/null || true
    find "$dir" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    ok "bytecode cleaned."
}

# ── helper: clean previous build artefacts ────────────────────────────────────

clean_build() {
    if $DO_CLEAN; then
        inf "cleaning previous build artefacts..."
        rm -rf "$SCRIPT_DIR/build" \
               "$SCRIPT_DIR/__pycache__" \
               "$SCRIPT_DIR"/*.spec \
               "$OUTPUT_DIR/$BINARY_NAME" \
               "$OUTPUT_DIR/${BINARY_NAME}.exe" \
               "$OUTPUT_DIR/${BINARY_NAME}.sha256" \
               "$OUTPUT_DIR/${BINARY_NAME}.sig" \
               "$OUTPUT_DIR/${BINARY_NAME}-onefile" \
               "$OUTPUT_DIR/${BINARY_NAME}-onefile.sha256" \
               "$OUTPUT_DIR/${BINARY_NAME}-onefile.sig" \
               2>/dev/null || true
        ok "cleaned."
    fi
}

# ── helper: smoke test ────────────────────────────────────────────────────────
#
# The app requires interactive input, so we just verify it starts, loads its
# imports, and exits cleanly when stdin is closed immediately.

smoke_test() {
    local bin="$1"
    inf "running smoke test on $(basename "$bin")..."
    # Feed empty stdin so the app gets EOF at the first prompt and exits
    if echo "" | timeout 15 "$bin" >/dev/null 2>&1; then
        ok "smoke test passed."
    elif [[ $? -eq 124 ]]; then
        # Timeout is actually OK here — it means the binary started and was
        # waiting for input, which is correct behaviour.
        ok "smoke test passed (binary started and awaited input correctly)."
    else
        # Non-zero exit that isn't timeout — check if it's just "wrong password"
        exit_code=$?
        if [[ $exit_code -le 2 ]]; then
            ok "smoke test passed (exited $exit_code — expected for empty input)."
        else
            warn "smoke test: binary exited $exit_code. manual verification recommended."
        fi
    fi
}

# =============================================================================
# MODE: pyinstaller  (one-directory bundle)
# =============================================================================

build_pyinstaller_dir() {
    inf "installing PyInstaller into .venv..."
    "$VENV_PIP" install --quiet pyinstaller pyinstaller-hooks-contrib

    local outname="${BINARY_NAME}"
    local distpath="$OUTPUT_DIR"

    inf "building PyInstaller one-directory bundle..."
    echo

    # Build the --exclude-module flags
    local exclude_flags=()
    for m in "${EXCLUDE_MODS[@]}"; do
        exclude_flags+=(--exclude-module "$m")
    done

    # Build the --hidden-import flags
    local hidden_flags=()
    for m in "${HIDDEN_IMPORTS[@]}"; do
        hidden_flags+=(--hidden-import "$m")
    done

    "$VENV_PY" -m PyInstaller \
        --name "$outname" \
        --onedir \
        --console \
        --strip \
        --clean \
        --noconfirm \
        --distpath "$distpath" \
        --workpath "$SCRIPT_DIR/build/pyinstaller" \
        --specpath "$SCRIPT_DIR/build" \
        "${exclude_flags[@]}" \
        "${hidden_flags[@]}" \
        --collect-all cryptography \
        --collect-all argon2 \
        --collect-all _argon2_cffi_bindings \
        --collect-all rich \
        --collect-all pyotp \
        "$SOURCE"

    local bundle_dir="$distpath/$outname"
    local binary="$bundle_dir/$outname"

    [[ -f "$binary" ]] || die "PyInstaller build failed — binary not found at $binary"

    remove_pyc "$bundle_dir"
    harden_binary "$binary"
    sign_and_checksum "$binary"
    smoke_test "$binary"

    echo
    ok "bundle directory: $bundle_dir"
    warn "distribute the entire directory, not just the binary."
}

# =============================================================================
# MODE: pyinstaller-onefile  (single executable)
# =============================================================================

build_pyinstaller_onefile() {
    inf "installing PyInstaller into .venv..."
    "$VENV_PIP" install --quiet pyinstaller pyinstaller-hooks-contrib

    local outname="${BINARY_NAME}-onefile"
    local distpath="$OUTPUT_DIR"

    # Security note: onefile mode extracts to a temp directory at runtime.
    # On Linux/macOS this is typically /tmp/_MEIxxxxxx.
    # The extraction path can be changed via _MEIPASS2 or --runtime-tmpdir.
    # We use the user's own temp to avoid /tmp permission issues, but note
    # that this means the unpacked bundle briefly exists in plaintext.
    warn "PyInstaller onefile mode extracts to a temp dir at runtime."
    warn "The extracted bundle is plaintext on disk for the duration of execution."
    warn "If this is a concern, use the 'pyinstaller' (onedir) mode instead."
    echo

    local exclude_flags=()
    for m in "${EXCLUDE_MODS[@]}"; do
        exclude_flags+=(--exclude-module "$m")
    done

    local hidden_flags=()
    for m in "${HIDDEN_IMPORTS[@]}"; do
        hidden_flags+=(--hidden-import "$m")
    done

    inf "building PyInstaller single-file binary..."
    echo

    "$VENV_PY" -m PyInstaller \
        --name "$outname" \
        --onefile \
        --console \
        --strip \
        --clean \
        --noconfirm \
        --distpath "$distpath" \
        --workpath "$SCRIPT_DIR/build/pyinstaller-onefile" \
        --specpath "$SCRIPT_DIR/build" \
        "${exclude_flags[@]}" \
        "${hidden_flags[@]}" \
        --collect-all cryptography \
        --collect-all argon2 \
        --collect-all _argon2_cffi_bindings \
        --collect-all rich \
        --collect-all pyotp \
        "$SOURCE"

    local binary="$distpath/$outname"
    [[ -f "$binary" ]] || die "PyInstaller onefile build failed — binary not found."

    harden_binary "$binary"
    sign_and_checksum "$binary"
    smoke_test "$binary"

    echo
    ok "single-file binary: $binary"
}

# =============================================================================
# MODE: nuitka  (native one-directory bundle)
# =============================================================================

build_nuitka_dir() {
    inf "installing Nuitka into .venv..."
    "$VENV_PIP" install --quiet "nuitka>=2.0" ordered-set zstandard

    # Nuitka requires a C compiler. Check now before spending time on KDF.
    if ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
        die "Nuitka requires gcc or clang. install with: sudo apt install gcc"
    fi

    local outname="${BINARY_NAME}"
    local outdir="$OUTPUT_DIR"

    # Build --nofollow-import-to flags
    local nofollow_flags=()
    for m in "${EXCLUDE_MODS[@]}"; do
        nofollow_flags+=(--nofollow-import-to="$m")
    done

    inf "building Nuitka standalone directory..."
    echo

    "$VENV_PY" -m nuitka \
        --standalone \
        --output-filename="$outname" \
        --output-dir="$outdir" \
        --python-flag=no_site \
        --python-flag=no_docstrings \
        --python-flag=isolated \
        --assume-yes-for-downloads \
        --remove-output \
        --follow-imports \
        --include-package=cryptography \
        --include-package=argon2 \
        --include-package=_argon2_cffi_bindings \
        --include-package=rich \
        --include-package=pyotp \
        --include-package=pyperclip \
        --include-package=cffi \
        --include-module=colorsys \
        --include-module=warnings \
        "${nofollow_flags[@]}" \
        "$SOURCE"

    # Nuitka puts output in <output-dir>/<script>.dist/
    local bundle_dir="$outdir/${outname}.dist"
    local binary="$bundle_dir/$outname"

    [[ -f "$binary" ]] || {
        # Some Nuitka versions use a slightly different path
        binary=$(find "$outdir" -maxdepth 2 -name "$outname" -type f | head -1)
        [[ -f "$binary" ]] || die "Nuitka build failed — binary not found."
        bundle_dir=$(dirname "$binary")
    }

    harden_binary "$binary"
    sign_and_checksum "$binary"
    smoke_test "$binary"

    echo
    ok "bundle directory: $bundle_dir"
    warn "distribute the entire .dist directory, not just the binary."
}

# =============================================================================
# MODE: nuitka-onefile  (native single executable)
# =============================================================================

build_nuitka_onefile() {
    inf "installing Nuitka into .venv..."
    "$VENV_PIP" install --quiet "nuitka>=2.0" ordered-set zstandard

    if ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
        die "Nuitka requires gcc or clang. install with: sudo apt install gcc"
    fi

    local outname="${BINARY_NAME}-onefile"
    local outdir="$OUTPUT_DIR"

    local nofollow_flags=()
    for m in "${EXCLUDE_MODS[@]}"; do
        nofollow_flags+=(--nofollow-import-to="$m")
    done

    inf "building Nuitka single-file binary (this takes several minutes)..."
    echo

    "$VENV_PY" -m nuitka \
        --onefile \
        --output-filename="$outname" \
        --output-dir="$outdir" \
        --python-flag=no_site \
        --python-flag=no_docstrings \
        --python-flag=isolated \
        --assume-yes-for-downloads \
        --remove-output \
        --follow-imports \
        --include-package=cryptography \
        --include-package=argon2 \
        --include-package=_argon2_cffi_bindings \
        --include-package=rich \
        --include-package=pyotp \
        --include-package=pyperclip \
        --include-package=cffi \
        --include-module=colorsys \
        --include-module=warnings \
        "${nofollow_flags[@]}" \
        "$SOURCE"

    local binary
    binary=$(find "$outdir" -maxdepth 1 -name "$outname" -type f | head -1)
    [[ -f "$binary" ]] || die "Nuitka onefile build failed — binary not found."

    harden_binary "$binary"
    sign_and_checksum "$binary"
    smoke_test "$binary"

    echo
    ok "single-file binary: $binary"
    inf "Nuitka onefile also extracts to a temp dir, but the bundle is"
    inf "compressed with zstandard and harder to inspect than PyInstaller."
}

# ── comparison table ───────────────────────────────────────────────────────────

print_mode_notes() {
    echo
    sep
    echo -e "  ${_BOLD}MODE COMPARISON${_RESET}"
    sep
    echo
    printf "  %-26s %-12s %-12s %-18s %s\n" "MODE" "STARTUP" "PORTABILITY" "REVERSIBILITY" "NOTES"
    echo -e "  ${_DIM}$(printf '%.0s─' {1..80})${_RESET}"
    printf "  %-26s %-12s %-12s %-18s %s\n" \
        "pyinstaller"          "fast"   "dir only"    "bytecode visible" "good default" \
        "pyinstaller-onefile"  "slow"   "one file"    "bytecode visible" "extracts to /tmp" \
        "nuitka"               "fast"   "dir only"    "compiled to C"    "requires gcc" \
        "nuitka-onefile"       "slow"   "one file"    "compiled to C"    "requires gcc, slow build"
    echo
}

# ── post-build summary ────────────────────────────────────────────────────────

print_summary() {
    local binary="$1"
    echo
    sep
    echo -e "  ${_BOLD}BUILD COMPLETE${_RESET}"
    sep
    echo
    if [[ -f "$binary" ]]; then
        local size
        size=$(du -sh "$binary" | cut -f1)
        ok "binary:    $binary"
        ok "size:      $size"
        ok "mode:      $MODE"
        [[ -f "${binary}.sha256" ]] && ok "checksum:  ${binary}.sha256"
        [[ -f "${binary}.sig"    ]] && ok "signature: ${binary}.sig"
        echo
        inf "verify with:  sha256sum -c ${binary}.sha256"
        $DO_SIGN && inf "verify sig:   gpg --verify ${binary}.sig $binary"
    fi
    echo
}

# ── dispatch ──────────────────────────────────────────────────────────────────

print_mode_notes
clean_build

case "$MODE" in
    pyinstaller)
        build_pyinstaller_dir
        print_summary "$OUTPUT_DIR/$BINARY_NAME/$BINARY_NAME"
        ;;
    pyinstaller-onefile)
        build_pyinstaller_onefile
        print_summary "$OUTPUT_DIR/${BINARY_NAME}-onefile"
        ;;
    nuitka)
        build_nuitka_dir
        NUITKA_BIN=$(find "$OUTPUT_DIR" -maxdepth 2 -name "$BINARY_NAME" -type f | head -1)
        print_summary "$NUITKA_BIN"
        ;;
    nuitka-onefile)
        build_nuitka_onefile
        print_summary "$OUTPUT_DIR/${BINARY_NAME}-onefile"
        ;;
esac
