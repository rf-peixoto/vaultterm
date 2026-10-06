#!/usr/bin/env bash
# =============================================================================
# VaultTerm -- verify.sh
#
# Verify a release BEFORE running it. Run this with a copy of verify.sh you
# trust (or simply run the sha256sum / gpg commands below by hand) -- a
# tampered download could ship a tampered verify.sh too.
#
#   ./verify.sh [path/to/vaultterm]    check the binary against SHA256SUMS
#                                      (+ SHA256SUMS.asc if present) next to it
#   ./verify.sh --source               check the source tree against
#                                      SOURCE-SHA256SUMS (+ .asc if present)
#   ./verify.sh --hash <expected-sha256> [path/to/vaultterm]
#                                      compare against a hash you got elsewhere
#
# Exit code 0 only if every available check passes.
# =============================================================================
set -euo pipefail

G="\033[92m"; R="\033[91m"; Y="\033[93m"; X="\033[0m"
pass() { echo -e "  ${G}[PASS]${X} $*"; }
fail() { echo -e "  ${R}[FAIL]${X} $*" >&2; exit 1; }
note() { echo -e "  ${Y}[NOTE]${X} $*"; }

check_sig() {   # $1 = file that has a detached .asc next to it
    local f="$1"
    if [[ -f "$f.asc" ]]; then
        command -v gpg >/dev/null || fail "$f.asc present but gpg is not installed."
        if gpg --batch --verify "$f.asc" "$f" 2>/tmp/vaultterm-gpg.$$; then
            pass "GPG signature on $(basename "$f") is valid:"
            grep -E 'Good signature|using|Primary key' /tmp/vaultterm-gpg.$$ | sed 's/^/         /' || true
            note "make sure the key fingerprint above is the one the author published."
        else
            cat /tmp/vaultterm-gpg.$$ >&2
            rm -f /tmp/vaultterm-gpg.$$
            fail "GPG signature on $(basename "$f") is NOT valid."
        fi
        rm -f /tmp/vaultterm-gpg.$$
    else
        note "no $(basename "$f").asc: hashes prove integrity, not authorship."
        note "compare the hash with the one published by the author through another channel."
    fi
}

MODE="binary"; EXPECTED=""; TARGET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source) MODE="source" ;;
        --hash) EXPECTED="${2:?--hash needs a value}"; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) TARGET="$1" ;;
    esac
    shift
done

if [[ "$MODE" == "source" ]]; then
    DIR="${TARGET:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    [[ -f "$DIR/SOURCE-SHA256SUMS" ]] || fail "no SOURCE-SHA256SUMS in $DIR"
    check_sig "$DIR/SOURCE-SHA256SUMS"
    (cd "$DIR" && sha256sum --strict -c SOURCE-SHA256SUMS) || fail "source files do not match."
    pass "all source files match SOURCE-SHA256SUMS."
    exit 0
fi

TARGET="${TARGET:-dist/vaultterm}"
[[ -f "$TARGET" ]] || fail "binary not found: $TARGET"
ACTUAL="$(sha256sum "$TARGET" | awk '{print $1}')"
echo "  sha256  $ACTUAL  $TARGET"

if [[ -n "$EXPECTED" ]]; then
    [[ "${EXPECTED,,}" == "$ACTUAL" ]] || fail "hash does not match the expected value."
    pass "hash matches the expected value."
    exit 0
fi

SUMS="$(dirname "$TARGET")/SHA256SUMS"
[[ -f "$SUMS" ]] || fail "no SHA256SUMS next to $TARGET (use --hash <value> instead)."
check_sig "$SUMS"
LISTED="$(awk -v n="$(basename "$TARGET")" '$2==n || $2=="*"n {print $1}' "$SUMS")"
[[ -n "$LISTED" ]] || fail "$(basename "$TARGET") is not listed in SHA256SUMS."
[[ "$LISTED" == "$ACTUAL" ]] || fail "hash does not match SHA256SUMS."
pass "binary matches SHA256SUMS."
