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
    /* v0.2.3 — multi-SAN parser smoke (no certbot needed): empty
     * domains list must return -1 (validation rejects). Exercises
     * the new code path without forking. */
    i64 rc_empty = Amalgame_Tls_Acme_EnsureCertMulti("", "x@x.com",
                                                     "/tmp", "", "");
    if (rc_empty != -1) {
        fprintf(stderr, "EnsureCertMulti(\"\") returned %ld, expected -1\n",
                (long) rc_empty);
        return 1;
    }
    i64 rc_blanks = Amalgame_Tls_Acme_EnsureCertMulti(" , , ", "x@x.com",
                                                       "/tmp", "", "");
    if (rc_blanks != -1) {
        fprintf(stderr, "EnsureCertMulti(\" , , \") returned %ld, expected -1\n",
                (long) rc_blanks);
        return 1;
    }
    /* v0.3.0 — native ACME primitives smoke (no network).  The
     * URL parser is a pure C helper; exercising bad inputs lets us
     * confirm the new TU links cleanly without spinning a TLS conn. */
    char host[16], port[8], path[16];
    if (amalgame_tls_acme_parse_url("http://nope", host, sizeof(host),
                                     port, sizeof(port),
                                     path, sizeof(path))) {
        fprintf(stderr, "parse_url accepted http:// scheme\n");
        return 1;
    }
    if (!amalgame_tls_acme_parse_url("https://example.com/foo",
                                      host, sizeof(host),
                                      port, sizeof(port),
                                      path, sizeof(path))
        || strcmp(host, "example.com") != 0
        || strcmp(port, "443") != 0
        || strcmp(path, "/foo") != 0) {
        fprintf(stderr, "parse_url default-port path failed\n");
        return 1;
    }
    /* CSR builder smoke — null key handle must return "". */
    code_string csr = Amalgame_Tls_Acme_CsrDer_Base64Url(0, "example.com");
    if (csr && csr[0]) {
        fprintf(stderr, "CsrDer_Base64Url accepted null key\n");
        return 1;
    }
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

# ── 2) AcmeNative AM-side smoke ─────────────────────────────────
# Compile acme.am against a self-cache (amalgame-tls + amalgame-crypto)
# and run the AM smoke test.  No network — exercises argument
# validation + the link path from JwsKey through Acme.Http.
echo ""
echo "── AcmeNative AM smoke ──"

# Locate amalgame-crypto sibling.
CRYPTO_DIR=""
if [ -n "$AMALGAME_CRYPTO" ] && [ -d "$AMALGAME_CRYPTO" ]; then
    CRYPTO_DIR="$AMALGAME_CRYPTO"
elif [ -d "$PKG_DIR/../amalgame-crypto" ]; then
    CRYPTO_DIR="$PKG_DIR/../amalgame-crypto"
elif [ -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-crypto" ]; then
    CRYPTO_DIR="$(ls -d "$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-crypto"/*/ 2>/dev/null | head -1)"
    CRYPTO_DIR="${CRYPTO_DIR%/}"
fi
if [ -z "$CRYPTO_DIR" ] || [ ! -f "$CRYPTO_DIR/facade.am" ]; then
    echo -e "${RED}error${NC}: amalgame-crypto not found (need v0.3.0+ for JwsKey)"
    echo "  set AMALGAME_CRYPTO=<path> or check out the sibling repo"
    exit 2
fi

# Locate bundled stdlib (json.am).
STDLIB_DIR=""
if [ -d "$(dirname "$AMC")/../share/amalgame/stdlib" ]; then
    STDLIB_DIR="$(cd "$(dirname "$AMC")/../share/amalgame/stdlib" && pwd)"
elif [ -d "$HOME/.local/share/amalgame/stdlib" ]; then
    STDLIB_DIR="$HOME/.local/share/amalgame/stdlib"
fi
if [ -z "$STDLIB_DIR" ] || [ ! -f "$STDLIB_DIR/json.am" ]; then
    echo -e "${RED}error${NC}: bundled stdlib json.am not found"
    exit 2
fi

# Build crypto's facade.o BEFORE the tls lock is in play — otherwise
# amc auto-loads tls's package (including acme.am) when it sees the
# lock and crypto's compilation has to satisfy acme.am's deps too.
echo "  building crypto facade.o…"
"$AMC" --lib -o "$BUILD_DIR/crypto" "$CRYPTO_DIR/facade.am" 2>&1 | tail -5
gcc -O2 -I"$RUNTIME_DIR" -I"$CRYPTO_DIR" \
    -c "$BUILD_DIR/crypto.c" -o "$BUILD_DIR/crypto.o" 2>"$BUILD_DIR/crypto-gcc.log"
head -5 "$BUILD_DIR/crypto-gcc.log"
if [ ! -s "$BUILD_DIR/crypto.o" ]; then
    echo -e "${RED}FAIL${NC} (crypto.am lib build)"
    exit 1
fi

# Build bundled json.am to json.o so acme.o's Amalgame_Formats_Json_*
# references resolve at link time.  json.am is a tiny pure-AM module
# (no @c blocks); compiling it standalone works the same as Aead.
echo "  building json.am stdlib…"
"$AMC" --lib -o "$BUILD_DIR/json" "$STDLIB_DIR/json.am" 2>&1 | tail -5
gcc -O2 -I"$RUNTIME_DIR" \
    -c "$BUILD_DIR/json.c" -o "$BUILD_DIR/json.o" 2>"$BUILD_DIR/json-gcc.log"
head -5 "$BUILD_DIR/json-gcc.log"
if [ ! -s "$BUILD_DIR/json.o" ]; then
    echo -e "${RED}FAIL${NC} (json.am lib build)"
    exit 1
fi

# Fake AMALGAME_PACKAGES_DIR cache so amc's PackageRegistry loads
# tls's own classes + the crypto sibling. amalgame.toml's classes
# list is what powers `Acme.Http`, `JwsKey.*` etc. resolution.
SELF_CACHE="$BUILD_DIR/pkg_cache"
mkdir -p "$SELF_CACHE/github.com/amalgame-lang/amalgame-tls"
mkdir -p "$SELF_CACHE/github.com/amalgame-lang/amalgame-crypto"
ln -s "$PKG_DIR"    "$SELF_CACHE/github.com/amalgame-lang/amalgame-tls/v0.3.0_aabbccdd"
ln -s "$CRYPTO_DIR" "$SELF_CACHE/github.com/amalgame-lang/amalgame-crypto/v0.3.0_ddeeff00"

# Transient lock file — restored on EXIT.
EXISTING_LOCK_BACKUP=""
if [ -f "$PKG_DIR/amalgame.lock" ]; then
    EXISTING_LOCK_BACKUP="$BUILD_DIR/amalgame.lock.bak"
    cp "$PKG_DIR/amalgame.lock" "$EXISTING_LOCK_BACKUP"
fi
trap '
    rm -rf "$BUILD_DIR"
    if [ -n "$EXISTING_LOCK_BACKUP" ] && [ -f "$EXISTING_LOCK_BACKUP" ]; then
        mv "$EXISTING_LOCK_BACKUP" "$PKG_DIR/amalgame.lock"
    else
        rm -f "$PKG_DIR/amalgame.lock"
    fi
' EXIT

cat > "$PKG_DIR/amalgame.lock" <<EOF
[[package]]
name = "amalgame-tls"
git  = "github.com/amalgame-lang/amalgame-tls"
tag  = "v0.3.0"
rev  = "aabbccdd00000000000000000000000000000000"

[[package]]
name = "amalgame-crypto"
git  = "github.com/amalgame-lang/amalgame-crypto"
tag  = "v0.3.0"
rev  = "ddeeff0000000000000000000000000000000000"
EOF

# Pre-build acme.am as a library object the test will link against.
# Crypto is loaded via the package registry (cache + lock); passing
# its facade.am via --external too would emit duplicate struct defs
# (the PkgClasses path already emits forward typedefs). json.am IS
# external — amc's bundled stdlib isn't in the package registry.
export AMALGAME_PACKAGES_DIR="$SELF_CACHE"
"$AMC" --lib -o "$BUILD_DIR/acme" acme.am \
    --external "$STDLIB_DIR/json.am" 2>&1 | tail -5
gcc -O2 -I"$RUNTIME_DIR" -I"$PKG_DIR/runtime" -I"$CRYPTO_DIR" \
    -c "$BUILD_DIR/acme.c" -o "$BUILD_DIR/acme.o" 2>"$BUILD_DIR/acme-gcc.log"
head -5 "$BUILD_DIR/acme-gcc.log"
if [ ! -s "$BUILD_DIR/acme.o" ]; then
    echo -e "${RED}FAIL${NC} (acme.am lib build)"
    exit 1
fi

# Build + run the smoke test.  acme.am is loaded via PkgRegistry
# (its classes appear in tls's amalgame.toml); --external would
# duplicate the struct defs.
"$AMC" -o "$BUILD_DIR/acme_smoke" tests/acme_native_smoke_test.am \
    --external "$STDLIB_DIR/json.am" 2>&1 | tail -5
gcc -O2 -I"$RUNTIME_DIR" -I"$PKG_DIR/runtime" -I"$CRYPTO_DIR" \
    "$BUILD_DIR/acme_smoke.c" \
    "$BUILD_DIR/acme.o" "$BUILD_DIR/crypto.o" "$BUILD_DIR/json.o" \
    -lssl -lcrypto -lgc -o "$BUILD_DIR/acme_smoke" 2>"$BUILD_DIR/smoke-gcc.log"
head -10 "$BUILD_DIR/smoke-gcc.log"
if [ ! -x "$BUILD_DIR/acme_smoke" ]; then
    echo -e "${RED}FAIL${NC} (acme smoke link)"
    exit 1
fi
SMOKE_OUT="$("$BUILD_DIR/acme_smoke")"
echo "$SMOKE_OUT"
if echo "$SMOKE_OUT" | grep -qE "\[FAIL\]"; then
    echo -e "${RED}FAIL${NC} (assertion mismatch)"
    exit 1
fi
echo -e "${GREEN}AcmeNative smoke passed${NC}"

# ── 3) Legacy e2e (server + client over TLS) ────────────────────
echo ""
echo "── E2E test (server + client) ──"
echo -e "${GREEN}skipped${NC} (requires amalgame-threading + cross-pkg import resolver)"
exit 0
