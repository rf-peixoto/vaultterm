#!/usr/bin/env bash
# =============================================================================
# VaultTerm -- verify.sh
#
# Verify a release BEFORE running it. Run this with a copy of verify.sh you
# trust (or the b2sum / gpg / pqsign.py commands below by hand) -- a tampered
# download could ship a tampered verify.sh too.
#
#   ./verify.sh [path/to/vaultterm]          binary vs B2SUMS next to it
#   ./verify.sh --source [dir]               source tree vs SOURCE-B2SUMS
#   ./verify.sh --b2 <expected-blake2b-512> [path/to/vaultterm]
#
#   --pq-pub <file.pub>        also REQUIRE a valid ML-DSA-87 (post-quantum)
#                              signature (*.mldsa) made with this key
#   --pq-fingerprint "<fpr>"   and require the key to have this fingerprint
#
# Signatures checked when present: *.asc (GPG, classical) and *.mldsa
# (ML-DSA-87, needs Python + cryptography >= 50; set VAULTTERM_PY to choose
# the interpreter). Exit code 0 only if every requested check passes.
# =============================================================================
set -euo pipefail

G="\033[92m"; R="\033[91m"; Y="\033[93m"; X="\033[0m"
pass() { echo -e "  ${G}[PASS]${X} $*"; }
fail() { echo -e "  ${R}[FAIL]${X} $*" >&2; exit 1; }
note() { echo -e "  ${Y}[NOTE]${X} $*"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v b2sum >/dev/null || fail "b2sum (GNU coreutils) is required."

find_py() {
    local c
    for c in "${VAULTTERM_PY:-}" "$HERE/.venv/bin/python" "$HERE/.build-venv/bin/python" python3; do
        [[ -n "$c" ]] || continue
        if command -v "$c" >/dev/null 2>&1 && "$c" -c 'from cryptography.hazmat.primitives.asymmetric import mldsa' 2>/dev/null; then
            echo "$c"; return 0
        fi
    done
    return 1
}

check_gpg() {   # $1 = file with a detached .asc next to it
    local f="$1" log
    if [[ -f "$f.asc" ]]; then
        command -v gpg >/dev/null || fail "$f.asc present but gpg is not installed."
        log="$(mktemp)"
        if gpg --batch --verify "$f.asc" "$f" 2>"$log"; then
            pass "GPG signature on $(basename "$f") is valid:"
            grep -E 'Good signature|using|Primary key' "$log" | sed 's/^/         /' || true
            note "make sure that key fingerprint is the one the author published."
        else
            cat "$log" >&2; rm -f "$log"
            fail "GPG signature on $(basename "$f") is NOT valid."
        fi
        rm -f "$log"
    fi
}

check_pq() {    # $1 = file with a .mldsa next to it
    local f="$1" py
    if [[ -n "$PQ_PUB" ]]; then
        [[ -f "$f.mldsa" ]] || fail "--pq-pub given but $(basename "$f").mldsa is missing."
        py="$(find_py)" || fail "no Python with cryptography >= 50 found (set VAULTTERM_PY)."
        local args=(verify --pub "$PQ_PUB")
        [[ -n "$PQ_FPR" ]] && args+=(--fingerprint "$PQ_FPR")
        "$py" -I "$HERE/pqsign.py" "${args[@]}" "$f" | sed 's/^/  /' || fail "ML-DSA-87 signature check failed."
    elif [[ -f "$f.mldsa" ]]; then
        note "$(basename "$f").mldsa present: pass --pq-pub <key.pub> to check the post-quantum signature."
    fi
    if [[ ! -f "$f.asc" && ! -f "$f.mldsa" ]]; then
        note "no signatures: hashes prove integrity, not authorship. compare with the author's published hash."
    fi
}

MODE="binary"; EXPECTED=""; TARGET=""; PQ_PUB=""; PQ_FPR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source) MODE="source" ;;
        --b2) EXPECTED="${2:?--b2 needs a value}"; shift ;;
        --pq-pub) PQ_PUB="$(realpath "${2:?--pq-pub needs a file}")"; shift ;;
        --pq-fingerprint) PQ_FPR="${2:?--pq-fingerprint needs a value}"; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) TARGET="$1" ;;
    esac
    shift
done

if [[ "$MODE" == "source" ]]; then
    DIR="${TARGET:-$HERE}"
    [[ -f "$DIR/SOURCE-B2SUMS" ]] || fail "no SOURCE-B2SUMS in $DIR"
    check_gpg "$DIR/SOURCE-B2SUMS"
    check_pq "$DIR/SOURCE-B2SUMS"
    (cd "$DIR" && b2sum --strict -c SOURCE-B2SUMS) || fail "source files do not match."
    pass "all source files match SOURCE-B2SUMS (BLAKE2b-512)."
    exit 0
fi

TARGET="${TARGET:-dist/vaultterm}"
[[ -f "$TARGET" ]] || fail "binary not found: $TARGET"
ACTUAL="$(b2sum "$TARGET" | awk '{print $1}')"
echo "  blake2b-512  ${ACTUAL:0:64}"
echo "               ${ACTUAL:64}"

if [[ -n "$EXPECTED" ]]; then
    [[ "${EXPECTED,,}" == "$ACTUAL" ]] || fail "hash does not match the expected value."
    pass "hash matches the expected value."
    exit 0
fi

SUMS="$(dirname "$TARGET")/B2SUMS"
[[ -f "$SUMS" ]] || fail "no B2SUMS next to $TARGET (use --b2 <value> instead)."
check_gpg "$SUMS"
check_pq "$SUMS"
LISTED="$(awk -v n="$(basename "$TARGET")" '$2==n || $2=="*"n {print $1}' "$SUMS")"
[[ -n "$LISTED" ]] || fail "$(basename "$TARGET") is not listed in B2SUMS."
[[ "$LISTED" == "$ACTUAL" ]] || fail "hash does not match B2SUMS."
pass "binary matches B2SUMS (BLAKE2b-512)."
