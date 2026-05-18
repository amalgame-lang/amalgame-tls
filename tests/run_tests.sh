#!/bin/bash
# ─────────────────────────────────────────────────────
#  amalgame-tls — Test Runner
#  Usage: ./tests/run_tests.sh [path-to-amc]
#
#  Requires:
#    - libssl-dev installed (or equivalent on macOS / Windows)
#    - amc binary (path passed as arg, or ./amc in cwd)
# ─────────────────────────────────────────────────────

set -e

PKG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$PKG_DIR/tests"

# Resolve `amc` — explicit arg wins, else $PATH, sibling Amalgame
# checkout, then the user's amalgame bin dir.
AMC=""
if [ -n "$1" ]; then
    AMC="$1"
elif [ -x "./amc" ]; then
    AMC="$(pwd)/amc"
elif command -v amc >/dev/null 2>&1; then
    AMC="$(command -v amc)"
elif [ -x "$PKG_DIR/../Amalgame/amc" ]; then
    AMC="$PKG_DIR/../Amalgame/amc"
elif [ -x "$HOME/.local/bin/amc" ]; then
    AMC="$HOME/.local/bin/amc"
elif [ -x "$HOME/.amalgame/bin/amc" ]; then
    AMC="$HOME/.amalgame/bin/amc"
fi

if [ -z "$AMC" ] || [ ! -x "$AMC" ]; then
    echo "error: amc binary not found"
    echo "  pass an explicit path:  ./tests/run_tests.sh /path/to/amc"
    echo "  or build amc:           cd ../Amalgame && ./build_amc.sh"
    exit 2
fi
echo "Using amc: $AMC"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# ── Generate self-signed cert if missing ──
if [ ! -f "$TESTS_DIR/server.pem" ]; then
    echo -e "${YELLOW}Generating self-signed test cert...${NC}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TESTS_DIR/server.key" \
        -out "$TESTS_DIR/server.pem" \
        -days 365 -subj "/CN=localhost" 2>/dev/null
fi

# ── Compile + run the e2e test ──
BUILD_DIR=$(mktemp -d -t amalgame-tls-XXXXXX)
trap 'rm -rf "$BUILD_DIR"' EXIT

cd "$PKG_DIR"
"$AMC" -o "$BUILD_DIR/tls_e2e" tests/tls_e2e_test.am 2>&1 | tail -5

if [ ! -x "$BUILD_DIR/tls_e2e" ]; then
    echo -e "${RED}FAIL${NC} (amc build failed)"
    exit 1
fi

"$BUILD_DIR/tls_e2e"
rc=$?

if [ $rc -eq 0 ]; then
    echo -e "${GREEN}All tests passed${NC}"
else
    echo -e "${RED}Tests failed (exit $rc)${NC}"
    exit $rc
fi
