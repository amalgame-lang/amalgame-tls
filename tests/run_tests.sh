#!/bin/bash
# ─────────────────────────────────────────────────────
#  amalgame-tls — Test Runner
#  Usage: ./tests/run_tests.sh [path-to-amc]
#
#  Requires:
#    - libssl-dev installed (or equivalent on macOS / Windows)
#    - amc binary (path passed as arg, or autodetected)
# ─────────────────────────────────────────────────────
set -e

PKG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$PKG_DIR/tests"

# Resolve `amc`.
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
    exit 2
fi

# Resolve the Amalgame runtime headers dir. AMC_RUNTIME env wins
# (set by the CI workflow); else fall back to sibling Amalgame
# checkout or user install.
RUNTIME_DIR=""
if [ -n "$AMC_RUNTIME" ] && [ -d "$AMC_RUNTIME" ]; then
    RUNTIME_DIR="$AMC_RUNTIME"
elif [ -d "$PKG_DIR/../Amalgame/runtime" ]; then
    RUNTIME_DIR="$PKG_DIR/../Amalgame/runtime"
elif [ -d "$HOME/.amalgame/runtime" ]; then
    RUNTIME_DIR="$HOME/.amalgame/runtime"
fi
if [ -z "$RUNTIME_DIR" ]; then
    echo "error: Amalgame runtime headers not found"
    exit 2
fi

BUILD_DIR=$(mktemp -d -t amalgame-tls-XXXXXX)
trap 'rm -rf "$BUILD_DIR"' EXIT

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

echo "Using amc: $AMC"
echo "Using runtime: $RUNTIME_DIR"
cd "$PKG_DIR"

# ── 1) Smoke test — header compiles standalone with OpenSSL ──────
# Validates Amalgame_Tls.h's __has_include detection + that all
# public symbols link against system OpenSSL. No AM code involved.
echo ""
echo "── Smoke test (header + OpenSSL link) ──"
cat > "$BUILD_DIR/smoke.c" <<'EOF'
#include "Amalgame_Tls.h"
#include <stdio.h>
int main(void) {
    AmalgameTlsConfig* cfg = Amalgame_Tls_TlsConfig_Default();
    cfg = Amalgame_Tls_TlsConfig_WithMinVersion(cfg, 13);
    cfg = Amalgame_Tls_TlsConfig_WithAlpn(cfg, "h2,http/1.1");
    AmalgameTlsContext* tc = Amalgame_Tls_TlsContext_Client(cfg);
    AmalgameTlsStream* s = Amalgame_Tls_TlsStream_Wrap(0, tc, 0);
    (void) Amalgame_Tls_TlsStream_LastError(s);
    Amalgame_Tls_TlsStream_Close(s);
    printf("AMALGAME_HAS_OPENSSL: %d\n",
#ifdef AMALGAME_HAS_OPENSSL
        1
#else
        0
#endif
    );
    return 0;
}
EOF
gcc -O2 -I"$RUNTIME_DIR" -I"$PKG_DIR/runtime" \
    "$BUILD_DIR/smoke.c" \
    -lssl -lcrypto -lgc \
    -o "$BUILD_DIR/smoke" 2>&1 | head -5
if [ ! -x "$BUILD_DIR/smoke" ]; then
    echo -e "${RED}FAIL${NC} (smoke build)"
    exit 1
fi
SMOKE_OUT=$("$BUILD_DIR/smoke")
echo "$SMOKE_OUT"
if echo "$SMOKE_OUT" | grep -q "AMALGAME_HAS_OPENSSL: 1"; then
    echo -e "${GREEN}smoke test passed (OpenSSL detected + linked)${NC}"
else
    echo -e "${RED}FAIL${NC} (OpenSSL not detected at compile time)"
    exit 1
fi

# ── 2) e2e test (server + client over TLS) ──────────────────────
# DISABLED for CI v0.1.x: requires amalgame-threading (not yet
# packaged) + the package-loader to resolve cross-package
# imports for Amalgame.Tls / Amalgame.Net at compile time.
# The smoke test above already proves the C runtime side.
# When the test infrastructure catches up, re-enable by removing
# the early-exit below + ensuring tests/server.pem exists.
echo ""
echo "── E2E test (server + client) ──"
echo -e "${GREEN}skipped${NC} (requires amalgame-threading + cross-pkg import resolver)"
exit 0
