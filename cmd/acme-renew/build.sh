#!/usr/bin/env bash
# Build acme-renew from local checkouts of amalgame-tls + amalgame-crypto.
#
# Why a shell script instead of `amc build main.am`?
#   The `amc build` path for tls/AcmeNative trips a known multi-source
#   resolver bug (AmalgameTlsAcmeHttpResponse not visible during the
#   facade re-compile). This script mirrors the working pattern from
#   amalgame-tls' own tests/run_tests.sh — pre-build crypto.am +
#   json.am + acme.am as .o files, then link the user binary against
#   them with a fake package-cache + transient lockfile.
#
# Usage:
#   ./build.sh [path-to-amc]
#
# Layout it expects (sibling checkouts under ~/Développement/):
#   amalgame-tls/        (this repo)
#   amalgame-crypto/
#   Amalgame/            (amc + runtime + stdlib)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

AMC="${1:-}"
if [ -z "$AMC" ]; then
    if [ -x "$PKG_DIR/../Amalgame/amc" ]; then
        AMC="$PKG_DIR/../Amalgame/amc"
    elif command -v amc >/dev/null 2>&1; then
        AMC="$(command -v amc)"
    else
        echo "error: amc binary not found" >&2
        exit 2
    fi
fi
AMC_DIR="$(cd "$(dirname "$AMC")" && pwd)"
RUNTIME_DIR="$AMC_DIR/../runtime"
[ -d "$RUNTIME_DIR" ] || RUNTIME_DIR="$AMC_DIR/runtime"
[ -d "$RUNTIME_DIR" ] || { echo "error: runtime dir not found near $AMC" >&2; exit 2; }
STDLIB_DIR="$AMC_DIR/../src/stdlib"
[ -d "$STDLIB_DIR" ] || STDLIB_DIR="$PKG_DIR/../Amalgame/src/stdlib"

CRYPTO_DIR="$PKG_DIR/../amalgame-crypto"
[ -d "$CRYPTO_DIR" ] || CRYPTO_DIR="$HOME/.amalgame/packages/github.com/amalgame-lang/amalgame-crypto"/v0.3.*
CRYPTO_DIR="$(ls -d $CRYPTO_DIR 2>/dev/null | tail -1)"
[ -d "$CRYPTO_DIR" ] && [ -f "$CRYPTO_DIR/facade.am" ] || {
    echo "error: amalgame-crypto checkout/cache not found" >&2
    exit 2
}

BUILD_DIR="$(mktemp -d -t acme-renew-XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "amc:      $AMC"
echo "runtime:  $RUNTIME_DIR"
echo "stdlib:   $STDLIB_DIR"
echo "tls:      $PKG_DIR"
echo "crypto:   $CRYPTO_DIR"
echo ""

# ── 1) crypto.am → crypto.o (BEFORE the lock is in play) ──
echo "building crypto facade.o..."
"$AMC" --lib -o "$BUILD_DIR/crypto" "$CRYPTO_DIR/facade.am" 2>&1 | tail -3
gcc -O2 -I"$RUNTIME_DIR" -I"$CRYPTO_DIR" \
    -c "$BUILD_DIR/crypto.c" -o "$BUILD_DIR/crypto.o"
[ -s "$BUILD_DIR/crypto.o" ] || { echo "crypto build failed"; exit 1; }

# ── 2) json.am → json.o ──
echo "building bundled json.am..."
"$AMC" --lib -o "$BUILD_DIR/json" "$STDLIB_DIR/json.am" 2>&1 | tail -3
gcc -O2 -I"$RUNTIME_DIR" -c "$BUILD_DIR/json.c" -o "$BUILD_DIR/json.o"
[ -s "$BUILD_DIR/json.o" ] || { echo "json build failed"; exit 1; }

# ── 3) Fake pkg cache + transient lock ──
SELF_CACHE="$BUILD_DIR/pkg_cache"
mkdir -p "$SELF_CACHE/github.com/amalgame-lang/amalgame-tls"
mkdir -p "$SELF_CACHE/github.com/amalgame-lang/amalgame-crypto"
ln -s "$PKG_DIR"    "$SELF_CACHE/github.com/amalgame-lang/amalgame-tls/v0.3.2_aabbccdd"
ln -s "$CRYPTO_DIR" "$SELF_CACHE/github.com/amalgame-lang/amalgame-crypto/v0.3.0_ddeeff00"
export AMALGAME_PACKAGES_DIR="$SELF_CACHE"

# amc looks for amalgame.lock in its cwd. The acme.am build runs from
# $PKG_DIR (amalgame-tls/), so the lock has to live there transiently.
EXISTING_LOCK_BACKUP=""
TRANSIENT_LOCK="$PKG_DIR/amalgame.lock"
if [ -f "$TRANSIENT_LOCK" ]; then
    EXISTING_LOCK_BACKUP="$BUILD_DIR/amalgame.lock.bak"
    cp "$TRANSIENT_LOCK" "$EXISTING_LOCK_BACKUP"
fi
trap '
    rm -rf "$BUILD_DIR"
    if [ -n "'"$EXISTING_LOCK_BACKUP"'" ] && [ -f "'"$EXISTING_LOCK_BACKUP"'" ]; then
        mv "'"$EXISTING_LOCK_BACKUP"'" "'"$TRANSIENT_LOCK"'"
    else
        rm -f "'"$TRANSIENT_LOCK"'"
    fi
' EXIT

cat > "$TRANSIENT_LOCK" <<EOF
[[package]]
name = "amalgame-tls"
git  = "github.com/amalgame-lang/amalgame-tls"
tag  = "v0.3.2"
rev  = "aabbccdd00000000000000000000000000000000"

[[package]]
name = "amalgame-crypto"
git  = "github.com/amalgame-lang/amalgame-crypto"
tag  = "v0.3.0"
rev  = "ddeeff0000000000000000000000000000000000"
EOF

# ── 4) acme.am → acme.o ──
# IMPORTANT: cd to $PKG_DIR (amalgame-tls root) so amc reads its
# amalgame.toml as the active package context. From cmd/acme-renew/,
# amc would treat tls as an external git dep — but the PkgRegistry
# fake cache symlinks the SAME source dir under both names, so
# referencing acme.am from $PKG_DIR gives clean cgen.
echo "building acme.am..."
(
    cd "$PKG_DIR"
    "$AMC" --lib -o "$BUILD_DIR/acme" acme.am \
        --external "$STDLIB_DIR/json.am" 2>&1 | tee "$BUILD_DIR/acme-amc.log" | tail -3
    [ -s "$BUILD_DIR/acme.c" ] || {
        echo "--- acme.am amc log ---"
        cat "$BUILD_DIR/acme-amc.log"
        echo "--- end ---"
        exit 1
    }
)
gcc -O2 -I"$RUNTIME_DIR" -I"$PKG_DIR/runtime" -I"$CRYPTO_DIR" \
    -include "$RUNTIME_DIR/_runtime.h" \
    -include "$PKG_DIR/runtime/Amalgame_Tls.h" \
    -include "$PKG_DIR/runtime/Amalgame_Tls_Acme.h" \
    -c "$BUILD_DIR/acme.c" -o "$BUILD_DIR/acme.o" 2>"$BUILD_DIR/acme-gcc.log" || {
        head -30 "$BUILD_DIR/acme-gcc.log"
        exit 1
    }
[ -s "$BUILD_DIR/acme.o" ] || { echo "acme build failed"; exit 1; }

# ── 5) main.am → acme-renew binary ──
# Same cd-into-PKG-DIR trick — the lock + AMALGAME_PACKAGES_DIR are
# already set up at the tls level, so main.am's `import Amalgame.Tls`
# resolves via PkgRegistry. main.am path must be passed absolute.
echo "building main.am + linking..."
(
    cd "$PKG_DIR"
    "$AMC" -o "$BUILD_DIR/acme_renew" "$SCRIPT_DIR/main.am" \
        --external "$STDLIB_DIR/json.am" 2>&1 | tail -3
)
gcc -O2 -I"$RUNTIME_DIR" -I"$PKG_DIR/runtime" -I"$CRYPTO_DIR" \
    -include "$RUNTIME_DIR/_runtime.h" \
    -include "$PKG_DIR/runtime/Amalgame_Tls.h" \
    -include "$PKG_DIR/runtime/Amalgame_Tls_Acme.h" \
    "$BUILD_DIR/acme_renew.c" \
    "$BUILD_DIR/acme.o" "$BUILD_DIR/crypto.o" "$BUILD_DIR/json.o" \
    -lssl -lcrypto -lgc -o "$SCRIPT_DIR/acme-renew" 2>"$BUILD_DIR/link-gcc.log" || {
        head -30 "$BUILD_DIR/link-gcc.log"
        exit 1
    }
[ -x "$SCRIPT_DIR/acme-renew" ] || { echo "final link failed"; exit 1; }

echo ""
echo "✓ built $SCRIPT_DIR/acme-renew"
ls -l "$SCRIPT_DIR/acme-renew"
