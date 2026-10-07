#!/usr/bin/env bash
# =============================================================================
# VaultTerm -- compile.sh
#
# Builds a standalone Linux ELF binary with PyInstaller and produces files that
# let anyone verify it:
#
#   dist/vaultterm                  the binary (one file)
#   dist/B2SUMS                     BLAKE2b-512 of the binary            (b2sum -c)
#   dist/SOURCE-B2SUMS              BLAKE2b-512 of the exact source files
#   dist/BUILDINFO                  toolchain, dependency pins, SOURCE_DATE_EPOCH
#   dist/*.asc                      GPG signatures                       (--sign)
#   dist/*.mldsa                    ML-DSA-87 post-quantum signatures    (--pq-sign)
#
# The build is pinned end-to-end (requirements*.txt with hashes, wheels only)
# and uses SOURCE_DATE_EPOCH + PYTHONHASHSEED=0, so rebuilding the same source
# with the same Python on the same distro gives the same binary.
#
# USAGE
#   ./compile.sh [options]
#     --onedir              one-directory bundle instead of a single file
#     --sign                GPG-sign B2SUMS and SOURCE-B2SUMS (classical)
#     --sign-key <keyid>    use a specific GPG key
#     --pq-sign <file.key>  ML-DSA-87-sign them too (create a key with:
#                           python3 pqsign.py keygen --out vaultterm-release)
#     --output-dir <dir>    default: ./dist
#     --keep-build          keep build/ and the build venv for inspection
#     --help
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

C="\033[96m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; X="\033[0m"
inf()  { echo -e "  ${C}[SYS]${X} $*"; }
ok()   { echo -e "  ${G}[OK]${X}  $*"; }
warn() { echo -e "  ${Y}[WARN]${X} $*"; }
die()  { echo -e "  ${R}[ERR]${X} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ONEDIR=false; SIGN=false; SIGN_KEY=""; PQ_KEY=""; OUTPUT_DIR="$SCRIPT_DIR/dist"; KEEP=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --onedir) ONEDIR=true ;;
        --sign) SIGN=true ;;
        --sign-key) SIGN=true; SIGN_KEY="${2:?--sign-key needs a key id}"; shift ;;
        --pq-sign) PQ_KEY="$(realpath "${2:?--pq-sign needs a key file}")"; shift ;;
        --output-dir) OUTPUT_DIR="$(realpath -m "${2:?--output-dir needs a path}")"; shift ;;
        --keep-build) KEEP=true ;;
        --help|-h) sed -n '2,34p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

cd "$SCRIPT_DIR"   # after argument parsing, so relative paths are taken from the caller's directory

[[ "$(uname -s)" == "Linux" ]] || die "VaultTerm builds for Linux only."
PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null || die "$PYTHON_BIN not found."
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10+ required."
command -v b2sum >/dev/null || die "b2sum (coreutils) not found."
if $SIGN; then command -v gpg >/dev/null || die "--sign requested but gpg is not installed."; fi
if [[ -n "$PQ_KEY" ]]; then [[ -f "$PQ_KEY" ]] || die "ML-DSA key not found: $PQ_KEY"; fi

SOURCES=(vaultterm.py vaultterm_wordlist.py pqsign.py requirements.txt requirements-build.txt
         install.sh start.sh compile.sh verify.sh README.md LICENSE tests/test_vaultterm.py tests/e2e_pty.py)
for f in "${SOURCES[@]}"; do [[ -f "$f" ]] || die "missing source file: $f"; done

# Reproducibility: fixed timestamps and hash seed.
if git -C "$SCRIPT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git -C "$SCRIPT_DIR" log -1 --format=%ct)"
else
    SOURCE_DATE_EPOCH="$(stat -c %Y vaultterm.py)"
fi
export SOURCE_DATE_EPOCH PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 TZ=UTC LC_ALL=C.UTF-8
umask 022

BUILD_VENV="$SCRIPT_DIR/.build-venv"
WORK="$SCRIPT_DIR/build"
NAME="vaultterm"

echo
inf "VaultTerm build  (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"

# ── 1. isolated, hash-verified toolchain ─────────────────────────────────────
rm -rf "$BUILD_VENV" "$WORK"
"$PYTHON_BIN" -m venv "$BUILD_VENV"
inf "installing pinned runtime + build dependencies (hash-checked, wheels only)..."
"$BUILD_VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-input \
    --require-hashes --only-binary=:all: -r requirements.txt -r requirements-build.txt
ok "toolchain ready."

# ── 2. tests on the source before building ───────────────────────────────────
inf "running test suite..."
"$BUILD_VENV/bin/python" -m unittest discover -s tests -q 2>&1 | tail -3
"$BUILD_VENV/bin/python" vaultterm.py --selftest >/dev/null || die "source selftest failed."
ok "tests passed."

# ── 3. build ─────────────────────────────────────────────────────────────────
EXCLUDES=(tkinter turtle idlelib curses unittest pdb doctest pydoc xmlrpc http.server
          wsgiref socketserver ftplib imaplib poplib smtplib lib2to3 ensurepip venv)
EXCLUDE_FLAGS=(); for m in "${EXCLUDES[@]}"; do EXCLUDE_FLAGS+=(--exclude-module "$m"); done
MODE_FLAG="--onefile"; $ONEDIR && MODE_FLAG="--onedir"

inf "building with PyInstaller ($MODE_FLAG)..."
"$BUILD_VENV/bin/python" -m PyInstaller --noconfirm --clean --log-level WARN \
    "$MODE_FLAG" --name "$NAME" \
    --distpath "$WORK/dist" --workpath "$WORK/work" --specpath "$WORK" \
    --hidden-import vaultterm_wordlist --collect-submodules qrcode \
    "${EXCLUDE_FLAGS[@]}" vaultterm.py

if $ONEDIR; then
    BIN="$WORK/dist/$NAME/$NAME"
else
    BIN="$WORK/dist/$NAME"
fi
[[ -x "$BIN" ]] || die "build produced no binary."
file "$BIN" 2>/dev/null | grep -q ELF || warn "output does not look like an ELF file."
ok "built $(du -h "$BIN" | cut -f1) binary."

# ── 4. smoke test in a throw-away HOME (never touches your real vault) ───────
inf "smoke test..."
SMOKE_HOME="$(mktemp -d)"
trap 'rm -rf "$SMOKE_HOME"' EXIT
if ! env -i HOME="$SMOKE_HOME" VAULTTERM_DIR="$SMOKE_HOME/v" PATH=/usr/bin:/bin "$BIN" --version; then
    die "binary failed to start."
fi
SELFTEST_RC=0
env -i HOME="$SMOKE_HOME" VAULTTERM_DIR="$SMOKE_HOME/v" PATH=/usr/bin:/bin "$BIN" --selftest || SELFTEST_RC=$?
[[ $SELFTEST_RC -eq 0 ]] || die "binary selftest failed (exit $SELFTEST_RC)."
[[ ! -e "$SMOKE_HOME/v" && ! -e "$SMOKE_HOME/.config/vaultterm" ]] || warn "selftest left files behind."
ok "binary selftest passed."

# ── 5. publish to the output directory + checksums + signatures ──────────────
mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR/$NAME" "$OUTPUT_DIR/B2SUMS"* "$OUTPUT_DIR/SOURCE-B2SUMS"* "$OUTPUT_DIR/BUILDINFO"
if $ONEDIR; then
    cp -a "$WORK/dist/$NAME" "$OUTPUT_DIR/$NAME"
    (cd "$OUTPUT_DIR" && find "$NAME" -type f -print0 | sort -z | xargs -0 b2sum > B2SUMS)
else
    install -m 0755 "$BIN" "$OUTPUT_DIR/$NAME"
    (cd "$OUTPUT_DIR" && b2sum "$NAME" > B2SUMS)
fi
b2sum "${SOURCES[@]}" > "$OUTPUT_DIR/SOURCE-B2SUMS"

{
    echo "vaultterm_version: $("$BUILD_VENV/bin/python" vaultterm.py --version)"
    echo "build_mode: $MODE_FLAG"
    echo "source_date_epoch: $SOURCE_DATE_EPOCH"
    echo "python: $("$BUILD_VENV/bin/python" -c 'import sys; print(sys.version.split()[0])')"
    echo "platform: $(uname -m) $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
    echo "glibc: $(ldd --version 2>/dev/null | head -1 | awk '{print $NF}')"
    echo "checksums: BLAKE2b-512 (b2sum)"
    echo "packages:"
    "$BUILD_VENV/bin/python" -m pip freeze --disable-pip-version-check | sed 's/^/  /'
} > "$OUTPUT_DIR/BUILDINFO"

if $SIGN; then
    inf "signing checksums with GPG (classical)..."
    GPG_ARGS=(--batch --yes --armor --detach-sign --digest-algo SHA512)
    [[ -n "$SIGN_KEY" ]] && GPG_ARGS+=(--local-user "$SIGN_KEY")
    gpg "${GPG_ARGS[@]}" --output "$OUTPUT_DIR/B2SUMS.asc" "$OUTPUT_DIR/B2SUMS"
    gpg "${GPG_ARGS[@]}" --output "$OUTPUT_DIR/SOURCE-B2SUMS.asc" "$OUTPUT_DIR/SOURCE-B2SUMS"
    ok "GPG signatures written."
fi
if [[ -n "$PQ_KEY" ]]; then
    inf "signing checksums with ML-DSA-87 (post-quantum)..."
    "$BUILD_VENV/bin/python" -I pqsign.py sign --key "$PQ_KEY" "$OUTPUT_DIR/B2SUMS" "$OUTPUT_DIR/SOURCE-B2SUMS"
    PUB="${PQ_KEY%.key}.pub"
    if [[ -f "$PUB" ]]; then
        cp "$PUB" "$OUTPUT_DIR/"
        "$BUILD_VENV/bin/python" -I pqsign.py verify --pub "$PUB" "$OUTPUT_DIR/B2SUMS" "$OUTPUT_DIR/SOURCE-B2SUMS" >/dev/null \
            || die "fresh ML-DSA signatures failed verification."
    fi
    ok "ML-DSA-87 signatures written."
fi

if ! $KEEP; then rm -rf "$BUILD_VENV" "$WORK"; fi

echo
ok "release files in $OUTPUT_DIR:"
ls -l "$OUTPUT_DIR" | sed 's/^/      /'
echo
echo "      $(head -1 "$OUTPUT_DIR/B2SUMS" | cut -c1-64)…  $NAME"
echo
inf "publish B2SUMS (+ .asc/.mldsa) and your key fingerprints through a channel separate from the binary."
inf "users check it with:  ./verify.sh dist/vaultterm [--pq-pub vaultterm-release.pub]"
