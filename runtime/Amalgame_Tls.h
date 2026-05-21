/*
 * Amalgame.Tls — TLS 1.2 / 1.3 client + server primitives.
 * Copyright (c) 2026 Bastien MOUGET
 * Licensed under the Apache License, Version 2.0.
 * https://github.com/amalgame-lang/amalgame-tls
 *
 * Provides three AM classes:
 *   TlsConfig   — builder for TLS settings (certs, ALPN, min version, ...)
 *   TlsContext  — SSL_CTX wrapper, server or client side
 *   TlsStream   — TLS over a raw fd: handshake, read, write, close
 *
 * Requires OpenSSL 3.x (or LibreSSL — drop-in ABI compatible):
 *   Debian/Ubuntu : sudo apt install libssl-dev
 *   Fedora/RHEL   : sudo dnf install openssl-devel
 *   macOS         : brew install openssl@3
 *   Windows/MSYS2 : pacman -S mingw-w64-x86_64-openssl
 *
 * Link with -lssl -lcrypto (handled automatically by amc via
 * the `libs = ["ssl","crypto"]` line in amalgame.toml).
 *
 * If OpenSSL is not installed, every function returns NULL / 0 / ""
 * with a descriptive error in LastError — no compile-time crash.
 */

#ifndef AMALGAME_TLS_H
#define AMALGAME_TLS_H

#include "_runtime.h"
#include "Amalgame_Collections.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

/* ================================================================
   OpenSSL detection — multi-OS
   ----------------------------------------------------------------
   On Linux + Windows/MSYS2 + Fedora etc., <openssl/...> is on the
   default include path (provided by the -dev/-devel package).

   On macOS Homebrew installs OpenSSL "keg-only" — the headers live
   under /opt/homebrew/opt/openssl@3/include (Apple Silicon) or
   /usr/local/opt/openssl@3/include (Intel). They're NOT on the
   default search path, so __has_include falls back to the absolute
   path. Users who already added the Homebrew include dir via
   CPATH or AMALGAME_CFLAGS hit the first branch instead.
   ================================================================ */

#if defined(__has_include)
#  if __has_include(<openssl/ssl.h>)
#    define AMALGAME_HAS_OPENSSL 1
#    include <openssl/ssl.h>
#    include <openssl/err.h>
#    include <openssl/x509v3.h>
#  elif defined(__APPLE__) && __has_include("/opt/homebrew/opt/openssl@3/include/openssl/ssl.h")
#    define AMALGAME_HAS_OPENSSL 1
#    define AMALGAME_OPENSSL_HOMEBREW_ARM 1
#    include "/opt/homebrew/opt/openssl@3/include/openssl/ssl.h"
#    include "/opt/homebrew/opt/openssl@3/include/openssl/err.h"
#    include "/opt/homebrew/opt/openssl@3/include/openssl/x509v3.h"
#  elif defined(__APPLE__) && __has_include("/usr/local/opt/openssl@3/include/openssl/ssl.h")
#    define AMALGAME_HAS_OPENSSL 1
#    define AMALGAME_OPENSSL_HOMEBREW_INTEL 1
#    include "/usr/local/opt/openssl@3/include/openssl/ssl.h"
#    include "/usr/local/opt/openssl@3/include/openssl/err.h"
#    include "/usr/local/opt/openssl@3/include/openssl/x509v3.h"
#  endif
#endif

/* ================================================================
   Common forward decls — same shape with or without OpenSSL.
   When OpenSSL is absent we still need the AM-level types so user
   code that imports Amalgame.Tls keeps compiling; all calls become
   no-ops that surface a clear error via LastError.
   ================================================================ */

typedef struct AmalgameTlsConfig  AmalgameTlsConfig;
typedef struct AmalgameTlsContext AmalgameTlsContext;
typedef struct AmalgameTlsStream  AmalgameTlsStream;

struct AmalgameTlsConfig {
    code_string CertFile;          /* PEM path, or NULL */
    code_string KeyFile;           /* PEM path, or NULL */
    code_string CertPem;           /* inline PEM, or NULL */
    code_string KeyPem;            /* inline PEM, or NULL */
    code_string CaBundlePath;      /* for client-auth verify, or NULL */
    i64         MinVersion;        /* 0 = default (TLS 1.2), 12 = 1.2, 13 = 1.3 */
    code_string AlpnCsv;           /* comma-separated list, e.g. "h2,http/1.1" */
    code_bool   SessionTickets;    /* default true */
    code_bool   InsecureSkipVerify;/* client-side, dev only */
};

struct AmalgameTlsContext {
    void*       _ctx;              /* SSL_CTX* (opaque to AM) */
    code_bool   IsServer;
    code_string LastError;
};

struct AmalgameTlsStream {
    void*       _ssl;              /* SSL* (opaque to AM) */
    i64         Fd;                /* underlying socket fd */
    code_bool   Connected;
    code_bool   IsServer;
    code_string LastError;
    code_string AlpnNegotiated;
};

/* Helper — duplicate a C string into the GC heap so the returned
 * AM-side string survives the C stack. Returns "" for NULL input. */
static inline code_string _amtls_strdup(const char* s) {
    if (!s) return "";
    size_t n = strlen(s);
    char* d = (char*) GC_MALLOC(n + 1);
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

#ifdef AMALGAME_HAS_OPENSSL

/* ================================================================
   OpenSSL-backed implementation
   ================================================================ */

/* One-shot library init — OpenSSL 1.1.0+ does this automatically
 * via implicit constructors, but on some link configurations the
 * explicit call is safer. SSL_library_init() is a no-op on 1.1+. */
static inline void _amtls_init_once(void) {
    static int done = 0;
    if (!done) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        done = 1;
    }
}

/* Format the top OpenSSL error from the thread-local error queue
 * into a GC-allocated string. Empty queue → "". */
static inline code_string _amtls_last_ssl_error(void) {
    unsigned long e = ERR_get_error();
    if (e == 0) return "";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return _amtls_strdup(buf);
}

/* ── TlsConfig — builder ───────────────────────────────────────── */

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_Default(void) {
    AmalgameTlsConfig* c =
        (AmalgameTlsConfig*) GC_MALLOC(sizeof(AmalgameTlsConfig));
    c->CertFile           = "";
    c->KeyFile            = "";
    c->CertPem            = "";
    c->KeyPem             = "";
    c->CaBundlePath       = "";
    c->MinVersion         = 12;          /* TLS 1.2 floor */
    c->AlpnCsv            = "";
    c->SessionTickets     = true;
    c->InsecureSkipVerify = false;
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithCertFile(
        AmalgameTlsConfig* c, code_string certPath, code_string keyPath) {
    if (!c) return c;
    c->CertFile = certPath ? certPath : "";
    c->KeyFile  = keyPath  ? keyPath  : "";
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithCertBytes(
        AmalgameTlsConfig* c, code_string certPem, code_string keyPem) {
    if (!c) return c;
    c->CertPem = certPem ? certPem : "";
    c->KeyPem  = keyPem  ? keyPem  : "";
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithClientAuth(
        AmalgameTlsConfig* c, code_string caBundlePath) {
    if (!c) return c;
    c->CaBundlePath = caBundlePath ? caBundlePath : "";
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithMinVersion(
        AmalgameTlsConfig* c, i64 v) {
    if (!c) return c;
    c->MinVersion = v;
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithAlpn(
        AmalgameTlsConfig* c, code_string protosCsv) {
    if (!c) return c;
    c->AlpnCsv = protosCsv ? protosCsv : "";
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithSessionTickets(
        AmalgameTlsConfig* c, code_bool enabled) {
    if (!c) return c;
    c->SessionTickets = enabled;
    return c;
}

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithInsecureSkipVerify(
        AmalgameTlsConfig* c, code_bool skip) {
    if (!c) return c;
    c->InsecureSkipVerify = skip;
    return c;
}

/* ── ALPN helper — convert "h2,http/1.1" to OpenSSL wire format ──
 *
 * OpenSSL's ALPN API wants a length-prefixed concatenation:
 *   <len1><proto1><len2><proto2>...
 * e.g. "h2,http/1.1" → "\x02h2\x08http/1.1" (12 bytes).
 * Returns malloc'd buffer + length via out params. Caller owns. */
static inline int _amtls_encode_alpn(
        const char* csv, unsigned char** out, unsigned int* outLen) {
    *out = NULL;
    *outLen = 0;
    if (!csv || csv[0] == '\0') return 0;

    size_t csvLen = strlen(csv);
    /* Upper bound: every comma becomes a length byte; we also add
     * one length byte for the first proto. So worst case is csvLen+1. */
    unsigned char* buf = (unsigned char*) malloc(csvLen + 1);
    if (!buf) return -1;

    size_t pos = 0;
    const char* start = csv;
    const char* p     = csv;
    while (1) {
        if (*p == ',' || *p == '\0') {
            size_t protoLen = (size_t)(p - start);
            if (protoLen == 0 || protoLen > 255) { free(buf); return -1; }
            buf[pos++] = (unsigned char) protoLen;
            memcpy(buf + pos, start, protoLen);
            pos += protoLen;
            if (*p == '\0') break;
            start = p + 1;
        }
        p++;
    }
    *out    = buf;
    *outLen = (unsigned int) pos;
    return 0;
}

/* Server-side ALPN selection callback — picks the first protocol
 * in the client's offered list that matches our advertised set. */
static int _amtls_alpn_select_cb(
        SSL* ssl,
        const unsigned char** out, unsigned char* outlen,
        const unsigned char* in, unsigned int inlen,
        void* arg) {
    (void) ssl;
    unsigned char* serverAlpn    = (unsigned char*) arg;
    if (!serverAlpn) return SSL_TLSEXT_ERR_NOACK;

    /* `serverAlpn` is in OpenSSL wire format already. SSL_select_next_proto
     * matches by walking both lists. */
    unsigned char  serverAlpnLen = 0;
    {
        /* Recover the total length by walking the buffer: each entry
         * is <len><bytes>. We stored the length in the first 2 bytes
         * (big-endian) prefixed when we attached it via SSL_CTX_set_alpn_select_cb. */
        serverAlpnLen = (unsigned char)((serverAlpn[0] << 8) | serverAlpn[1]);
    }
    int r = SSL_select_next_proto(
        (unsigned char**) out, outlen,
        serverAlpn + 2, (unsigned int) serverAlpnLen,
        in, inlen);
    return (r == OPENSSL_NPN_NEGOTIATED) ? SSL_TLSEXT_ERR_OK
                                         : SSL_TLSEXT_ERR_NOACK;
}

/* ── TlsContext — Server / Client SSL_CTX ─────────────────────── */

static inline AmalgameTlsContext* _amtls_new_ctx(
        AmalgameTlsConfig* cfg, code_bool isServer) {
    _amtls_init_once();
    AmalgameTlsContext* tc =
        (AmalgameTlsContext*) GC_MALLOC(sizeof(AmalgameTlsContext));
    tc->_ctx      = NULL;
    tc->IsServer  = isServer;
    tc->LastError = "";

    /* TLS_server_method / TLS_client_method are the auto-negotiate
     * factories on OpenSSL 1.1+ (replaces deprecated SSLv23_*_method). */
    const SSL_METHOD* m = isServer ? TLS_server_method() : TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(m);
    if (!ctx) {
        tc->LastError = _amtls_last_ssl_error();
        return tc;
    }

    /* Min protocol version: 12 → TLS 1.2, 13 → TLS 1.3.
     * Default (0) = TLS 1.2 floor. */
    i64 minV = cfg ? cfg->MinVersion : 12;
    int proto = TLS1_2_VERSION;
    if (minV == 13) proto = TLS1_3_VERSION;
    SSL_CTX_set_min_proto_version(ctx, proto);

    /* Certificate + key — file path takes precedence over inline PEM. */
    if (cfg && cfg->CertFile && cfg->CertFile[0] != '\0') {
        if (SSL_CTX_use_certificate_chain_file(ctx, cfg->CertFile) != 1) {
            tc->LastError = _amtls_last_ssl_error();
            SSL_CTX_free(ctx);
            return tc;
        }
        if (cfg->KeyFile && cfg->KeyFile[0] != '\0' &&
            SSL_CTX_use_PrivateKey_file(ctx, cfg->KeyFile, SSL_FILETYPE_PEM) != 1) {
            tc->LastError = _amtls_last_ssl_error();
            SSL_CTX_free(ctx);
            return tc;
        }
    } else if (cfg && cfg->CertPem && cfg->CertPem[0] != '\0') {
        BIO* bio = BIO_new_mem_buf(cfg->CertPem, -1);
        X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!cert) {
            tc->LastError = _amtls_strdup("invalid PEM certificate");
            SSL_CTX_free(ctx);
            return tc;
        }
        if (SSL_CTX_use_certificate(ctx, cert) != 1) {
            tc->LastError = _amtls_last_ssl_error();
            X509_free(cert);
            SSL_CTX_free(ctx);
            return tc;
        }
        X509_free(cert);

        if (cfg->KeyPem && cfg->KeyPem[0] != '\0') {
            BIO* kbio = BIO_new_mem_buf(cfg->KeyPem, -1);
            EVP_PKEY* pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
            BIO_free(kbio);
            if (!pkey) {
                tc->LastError = _amtls_strdup("invalid PEM private key");
                SSL_CTX_free(ctx);
                return tc;
            }
            if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
                tc->LastError = _amtls_last_ssl_error();
                EVP_PKEY_free(pkey);
                SSL_CTX_free(ctx);
                return tc;
            }
            EVP_PKEY_free(pkey);
        }
    }
    /* Server with cert+key: sanity check they match. */
    if (isServer && cfg &&
        (cfg->CertFile[0] != '\0' || cfg->CertPem[0] != '\0')) {
        if (SSL_CTX_check_private_key(ctx) != 1) {
            tc->LastError = _amtls_strdup("cert/key mismatch");
            SSL_CTX_free(ctx);
            return tc;
        }
    }

    /* Client-auth CA bundle (optional). */
    if (cfg && cfg->CaBundlePath && cfg->CaBundlePath[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, cfg->CaBundlePath, NULL) != 1) {
            tc->LastError = _amtls_last_ssl_error();
            SSL_CTX_free(ctx);
            return tc;
        }
        SSL_CTX_set_verify(ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else if (!isServer && cfg && !cfg->InsecureSkipVerify) {
        /* Default client behaviour: verify the server cert against
         * the system CA store. */
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else if (!isServer && cfg && cfg->InsecureSkipVerify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* ALPN. For clients we set the offer list directly; for servers
     * we register a selection callback. */
    if (cfg && cfg->AlpnCsv && cfg->AlpnCsv[0] != '\0') {
        unsigned char* wire = NULL;
        unsigned int   wireLen = 0;
        if (_amtls_encode_alpn(cfg->AlpnCsv, &wire, &wireLen) == 0) {
            if (isServer) {
                /* Stash the wire-format ALPN list as a 2-byte
                 * big-endian length prefix + payload so the callback
                 * can recover it without a global. */
                unsigned char* stash = (unsigned char*) malloc(wireLen + 2);
                stash[0] = (unsigned char)((wireLen >> 8) & 0xFF);
                stash[1] = (unsigned char)(wireLen & 0xFF);
                memcpy(stash + 2, wire, wireLen);
                free(wire);
                SSL_CTX_set_alpn_select_cb(ctx, _amtls_alpn_select_cb, stash);
            } else {
                SSL_CTX_set_alpn_protos(ctx, wire, wireLen);
                free(wire);
            }
        }
    }

    /* Session tickets (default on for both sides). */
    if (cfg && !cfg->SessionTickets) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }

    tc->_ctx = (void*) ctx;
    return tc;
}

static inline AmalgameTlsContext* Amalgame_Tls_TlsContext_Server(
        AmalgameTlsConfig* cfg) {
    return _amtls_new_ctx(cfg, true);
}
static inline AmalgameTlsContext* Amalgame_Tls_TlsContext_Client(
        AmalgameTlsConfig* cfg) {
    return _amtls_new_ctx(cfg, false);
}

static inline code_string Amalgame_Tls_TlsContext_LastError(
        AmalgameTlsContext* tc) {
    return tc ? tc->LastError : "";
}

/* ── TlsStream — TLS over a raw fd ─────────────────────────────── */

static inline AmalgameTlsStream* Amalgame_Tls_TlsStream_Wrap(
        i64 fd, AmalgameTlsContext* tc, code_bool isServer) {
    AmalgameTlsStream* s =
        (AmalgameTlsStream*) GC_MALLOC(sizeof(AmalgameTlsStream));
    s->_ssl           = NULL;
    s->Fd             = fd;
    s->Connected      = false;
    s->IsServer       = isServer;
    s->LastError      = "";
    s->AlpnNegotiated = "";

    if (!tc || !tc->_ctx) {
        s->LastError = _amtls_strdup("invalid TlsContext");
        return s;
    }
    SSL* ssl = SSL_new((SSL_CTX*) tc->_ctx);
    if (!ssl) {
        s->LastError = _amtls_last_ssl_error();
        return s;
    }
    if (SSL_set_fd(ssl, (int) fd) != 1) {
        s->LastError = _amtls_last_ssl_error();
        SSL_free(ssl);
        return s;
    }
    s->_ssl = (void*) ssl;
    return s;
}

/* Perform the TLS handshake. Blocking — caller is responsible for
 * making sure the underlying fd is in blocking mode (which it is
 * after accept()/connect() on a regular BSD socket). Returns true
 * on success; on failure, LastError is populated. */
static inline code_bool Amalgame_Tls_TlsStream_Handshake(
        AmalgameTlsStream* s) {
    if (!s || !s->_ssl) return false;
    SSL* ssl = (SSL*) s->_ssl;
    int r = s->IsServer ? SSL_accept(ssl) : SSL_connect(ssl);
    if (r != 1) {
        s->LastError = _amtls_last_ssl_error();
        return false;
    }

    /* Cache the negotiated ALPN for cheap AM-side access. */
    const unsigned char* alpn = NULL;
    unsigned int alpnLen = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpnLen);
    if (alpn && alpnLen > 0 && alpnLen < 64) {
        char* buf = (char*) GC_MALLOC(alpnLen + 1);
        memcpy(buf, alpn, alpnLen);
        buf[alpnLen] = '\0';
        s->AlpnNegotiated = buf;
    }
    s->Connected = true;
    return true;
}

static inline i64 Amalgame_Tls_TlsStream_Read(
        AmalgameTlsStream* s, AmalgameList* buf, i64 max) {
    if (!s || !s->_ssl || !s->Connected || !buf) return -1;
    if (max <= 0) max = 4096;
    unsigned char* tmp = (unsigned char*) GC_MALLOC((size_t) max);
    int n = SSL_read((SSL*) s->_ssl, tmp, (int) max);
    if (n <= 0) {
        int err = SSL_get_error((SSL*) s->_ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN) {
            s->Connected = false;
            return 0;
        }
        s->LastError = _amtls_last_ssl_error();
        return -1;
    }
    /* Copy decrypted bytes into the AM-side List<int>. AmalgameList
     * stores `void*` slots; AM boxes ints via `(intptr_t)` casts at
     * call sites, so we mirror that here. */
    for (int i = 0; i < n; i++) {
        AmalgameList_add(buf, (void*)(intptr_t)(unsigned char) tmp[i]);
    }
    return (i64) n;
}

static inline i64 Amalgame_Tls_TlsStream_Write(
        AmalgameTlsStream* s, AmalgameList* buf) {
    if (!s || !s->_ssl || !s->Connected || !buf) return -1;
    int n = buf->size;
    if (n <= 0) return 0;
    unsigned char* tmp = (unsigned char*) GC_MALLOC((size_t) n);
    for (int i = 0; i < n; i++) {
        tmp[i] = (unsigned char)((i64)(size_t) buf->data[i] & 0xFF);
    }
    int written = SSL_write((SSL*) s->_ssl, tmp, n);
    if (written <= 0) {
        s->LastError = _amtls_last_ssl_error();
        return -1;
    }
    return (i64) written;
}

/* ── Raw-byte read/write (v0.1.3+) ────────────────────────────────
 * The List-based Read/Write above box every byte into an AmalgameList
 * cell — convenient for pure-AM code but allocation-heavy on the H2
 * server hot path (recv 16 KB chunks, send frames repeatedly).
 *
 * These raw-byte versions skip the boxing: they read/write directly
 * into a caller-owned buffer via SSL_read / SSL_write. amalgame-net-http
 * v0.3 uses them from its nghttp2 send/recv callbacks so TLS data path
 * has the same cost as plain socket I/O.
 *
 * Returns the number of bytes transferred (> 0), 0 on clean close,
 * -1 on error (with LastError set on the stream).
 */
static inline i64 Amalgame_Tls_TlsStream_ReadBytes(
        AmalgameTlsStream* s, char* buf, i64 max) {
    if (!s || !s->_ssl || !s->Connected || !buf || max <= 0) return -1;
    int n = SSL_read((SSL*) s->_ssl, buf, (int) max);
    if (n > 0) return (i64) n;
    int err = SSL_get_error((SSL*) s->_ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) {
        s->Connected = false;
        return 0;
    }
    s->LastError = _amtls_last_ssl_error();
    return -1;
}

static inline i64 Amalgame_Tls_TlsStream_WriteBytes(
        AmalgameTlsStream* s, const char* buf, i64 len) {
    if (!s || !s->_ssl || !s->Connected || !buf || len <= 0) return -1;
    int written = SSL_write((SSL*) s->_ssl, buf, (int) len);
    if (written > 0) return (i64) written;
    s->LastError = _amtls_last_ssl_error();
    return -1;
}

/* ── ACME (Let's Encrypt) — v0.2.0 ─────────────────────────────────
 *
 * v0.2.x ships a SUBPROCESS-WRAPPING client: Acme.EnsureCert
 * fork+execvp's `certbot` (which must be installed) in --standalone
 * mode. No shell is invoked — domain/email/dir are passed as argv
 * elements, so they cannot inject shell metacharacters.
 * Port 80 must be free during the call — certbot binds it itself,
 * runs the http-01 challenge, gets the cert, and we read the
 * resulting files back. ~100 LoC of wrapping over a battle-tested
 * client. Production-usable today.
 *
 * **STILL TODO for v0.3.0**: native pure-AM ACME (RFC 8555) — JWS
 * account signing via EVP_PKEY + JSON marshaling + order /
 * authorization / finalize state machine + CSR DER encoding. The
 * `Acme.EnsureCert` API will stay stable; only the implementation
 * swaps.
 *
 * Acme.ChallengeServer is a minimal HTTP/1.1 listener that responds
 * to /.well-known/acme-challenge/<token> from a webroot directory.
 * For webroot-mode certbot (server stays up, no port-80 hand-off).
 *
 * Usage:
 *
 *     // Prod: provision a Let's Encrypt cert (needs port 80 free + DNS)
 *     let rc = Acme.EnsureCert("example.com", "admin@example.com", "./certs")
 *     if (rc != 0) { Console.WriteLine("cert provisioning failed"); return }
 *     let cert = Acme.CertPath("example.com", "./certs")
 *     let key  = Acme.KeyPath("example.com", "./certs")
 *     Https.Serve(443, cert, key, handler)
 *
 * For dev / localhost, use self-signed via `openssl req -x509 -newkey ...`
 * — Acme.EnsureCert against Let's Encrypt won't issue for localhost.
 */

/* EnsureCertMulti — multi-SAN variant (v0.2.3+).
 *
 * Identical to EnsureCertEx except `domains` is a comma-separated list
 * of hostnames. All hostnames end up on one certificate as Subject
 * Alternative Names; the first one becomes the cert-name (so
 * Acme.CertPath / Acme.KeyPath compose against it).
 *
 *   domains       — "example.com,www.example.com,api.example.com"
 *                   Leading/trailing whitespace per element is trimmed.
 *                   Empty elements (",,") are skipped.
 *                   At least one non-empty element required.
 *   email/dir/acme_server/certbot_path — same as EnsureCertEx.
 *
 * Up to 32 SANs supported (enough for any sane multi-host cert; ACME
 * CAs themselves usually cap at 100, but argv would balloon).
 *
 * EnsureCertEx is now a thin wrapper that calls this with a single
 * element. EnsureCert still calls EnsureCertEx for the env-var path.
 */
#define AMALGAME_TLS_MAX_SANS 32
static inline i64 Amalgame_Tls_Acme_EnsureCertMulti(code_string domains,
                                                     code_string email,
                                                     code_string dir,
                                                     code_string acme_server,
                                                     code_string certbot_path) {
    if (!domains || !domains[0] || !email || !email[0] || !dir || !dir[0]) {
        fprintf(stderr, "Acme.EnsureCert: domains, email, dir all required\n");
        return -1;
    }
    /* Copy domains CSV into a writable buffer so we can split on ',' by
     * NUL-stuffing. 4KB caps the input — any real SAN list fits well
     * under that (32 × 64-byte domain ≈ 2KB max). */
    char dbuf[4096];
    size_t dlen = strlen(domains);
    if (dlen >= sizeof(dbuf)) {
        fprintf(stderr, "Acme.EnsureCert: domains list too long (%zu bytes, max %zu)\n",
                dlen, sizeof(dbuf) - 1);
        return -1;
    }
    memcpy(dbuf, domains, dlen + 1);
    char* dlist[AMALGAME_TLS_MAX_SANS];
    int dcount = 0;
    char* p = dbuf;
    while (*p && dcount < AMALGAME_TLS_MAX_SANS) {
        /* skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;
        char* start = p;
        while (*p && *p != ',') p++;
        char* end = p;
        if (*p == ',') { *p = '\0'; p++; }
        /* trim trailing whitespace */
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
            *end = '\0';
        }
        if (*start) {
            dlist[dcount++] = start;
        }
    }
    if (dcount == 0) {
        fprintf(stderr, "Acme.EnsureCert: no non-empty domain in '%s'\n", domains);
        return -1;
    }
    if (*p && dcount == AMALGAME_TLS_MAX_SANS) {
        fprintf(stderr, "Acme.EnsureCert: more than %d SANs not supported\n",
                AMALGAME_TLS_MAX_SANS);
        return -1;
    }
    code_string domain = dlist[0]; /* cert-name = first */
    /* Resolve server + binary: explicit param > env var > default. */
    const char* server = (acme_server && acme_server[0]) ? acme_server : NULL;
    if (!server) {
        const char* env = getenv("MOSAIC_TLS_ACME_SERVER");
        if (env && env[0]) server = env;
    }
    const char* certbot = (certbot_path && certbot_path[0]) ? certbot_path : NULL;
    if (!certbot) {
        const char* env = getenv("MOSAIC_TLS_CERTBOT_PATH");
        if (env && env[0]) certbot = env;
    }
    if (!certbot) certbot = "certbot";   /* let execvp search $PATH */
    /* --config-dir / --work-dir / --logs-dir keep all state under
     * the user-chosen directory (no /etc/letsencrypt by default —
     * we want unprivileged usable). Compose the three paths up-front;
     * they're passed to certbot as argv elements (no shell), so they
     * don't need quoting — they just need to fit. */
    char etc_dir[1024], work_dir[1024], log_dir[1024];
    int n1 = snprintf(etc_dir,  sizeof(etc_dir),  "%s/etc",  dir);
    int n2 = snprintf(work_dir, sizeof(work_dir), "%s/work", dir);
    int n3 = snprintf(log_dir,  sizeof(log_dir),  "%s/log",  dir);
    if (n1 < 0 || (size_t)n1 >= sizeof(etc_dir) ||
        n2 < 0 || (size_t)n2 >= sizeof(work_dir) ||
        n3 < 0 || (size_t)n3 >= sizeof(log_dir)) {
        fprintf(stderr, "Acme.EnsureCert: directory path too long\n");
        return -1;
    }
    /* argv vector — execvp does not interpret shell metacharacters,
     * so domain/email/dir cannot inject commands. argv[0] is the
     * conventional program name (certbot sees it via $0). Sized for
     * AMALGAME_TLS_MAX_SANS × (-d <host>) plus the fixed prelude. */
    char* argv[16 + 2 * AMALGAME_TLS_MAX_SANS];
    int ai = 0;
    argv[ai++] = (char*)certbot;
    argv[ai++] = (char*)"certonly";
    argv[ai++] = (char*)"--standalone";
    argv[ai++] = (char*)"--config-dir"; argv[ai++] = etc_dir;
    argv[ai++] = (char*)"--work-dir";   argv[ai++] = work_dir;
    argv[ai++] = (char*)"--logs-dir";   argv[ai++] = log_dir;
    for (int i = 0; i < dcount; i++) {
        argv[ai++] = (char*)"-d";       argv[ai++] = dlist[i];
    }
    argv[ai++] = (char*)"--email";      argv[ai++] = (char*)email;
    argv[ai++] = (char*)"--agree-tos";
    argv[ai++] = (char*)"--non-interactive";
    argv[ai++] = (char*)"--no-eff-email";
    argv[ai++] = (char*)"--cert-name";  argv[ai++] = (char*)domain;
    if (server) {
        argv[ai++] = (char*)"--server"; argv[ai++] = (char*)server;
    }
    argv[ai] = NULL;

    if (dcount == 1) {
        fprintf(stdout, "Acme.EnsureCert: running %s for %s%s%s...\n",
                certbot, domain,
                server ? " against " : "",
                server ? server      : "");
    } else {
        fprintf(stdout, "Acme.EnsureCert: running %s for %s + %d SAN(s)%s%s...\n",
                certbot, domain, dcount - 1,
                server ? " against " : "",
                server ? server      : "");
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Acme.EnsureCert: fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* Child. Merge stderr into stdout so the user sees the full
         * certbot log on failure (matches the previous "2>&1" behavior). */
        dup2(STDOUT_FILENO, STDERR_FILENO);
        execvp(certbot, argv);
        /* exec only returns on failure. */
        fprintf(stdout, "Acme.EnsureCert: exec %s failed: %s "
                "(install with: sudo apt install certbot)\n",
                certbot, strerror(errno));
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "Acme.EnsureCert: waitpid failed: %s\n", strerror(errno));
        return -1;
    }
    if (!WIFEXITED(status)) {
        fprintf(stderr, "Acme.EnsureCert: certbot terminated abnormally\n");
        return -2;
    }
    int rc = WEXITSTATUS(status);
    if (rc != 0) {
        fprintf(stderr, "Acme.EnsureCert: certbot exited %d "
                "(install with: sudo apt install certbot)\n", rc);
        return -2;
    }
    fprintf(stdout, "Acme.EnsureCert: cert ready for %s\n", domain);
    return 0;
}

/* Convenience wrapper — keeps the v0.2.2 single-domain API working.
 * Since v0.2.3 this is a thin shim over EnsureCertMulti. */
static inline i64 Amalgame_Tls_Acme_EnsureCertEx(code_string domain,
                                                  code_string email,
                                                  code_string dir,
                                                  code_string acme_server,
                                                  code_string certbot_path) {
    return Amalgame_Tls_Acme_EnsureCertMulti(domain, email, dir,
                                              acme_server, certbot_path);
}

/* Convenience wrapper — keeps the v0.2.0 API compiling unchanged.
 * The env-var fallbacks (MOSAIC_TLS_ACME_SERVER, MOSAIC_TLS_CERTBOT_PATH)
 * still apply via EnsureCertMulti. */
static inline i64 Amalgame_Tls_Acme_EnsureCert(code_string domain,
                                                code_string email,
                                                code_string dir) {
    return Amalgame_Tls_Acme_EnsureCertMulti(domain, email, dir, "", "");
}

static inline code_string Amalgame_Tls_Acme_CertPath(code_string domain,
                                                      code_string dir) {
    if (!domain || !dir) return "";
    char* buf = (char*)GC_MALLOC_ATOMIC(strlen(dir) + strlen(domain) + 48);
    sprintf(buf, "%s/etc/live/%s/fullchain.pem", dir, domain);
    return buf;
}

static inline code_string Amalgame_Tls_Acme_KeyPath(code_string domain,
                                                     code_string dir) {
    if (!domain || !dir) return "";
    char* buf = (char*)GC_MALLOC_ATOMIC(strlen(dir) + strlen(domain) + 48);
    sprintf(buf, "%s/etc/live/%s/privkey.pem", dir, domain);
    return buf;
}

/* ── ChallengeServer — webroot-mode http-01 ────────────────────────
 *
 * Minimal HTTP/1.1 listener that responds to:
 *   GET /.well-known/acme-challenge/<token>
 * by reading `<webroot>/.well-known/acme-challenge/<token>` from
 * disk. Everything else gets 301 redirect to https://<host><path>.
 *
 * Blocks forever — typically run in a separate process (or as a
 * sibling of your HTTPS server via fork). Returns -2 on listen
 * fail. Useful when certbot is run in --webroot mode and the
 * server stays up during cert renewal.
 */
static inline i64 Amalgame_Tls_Acme_ChallengeServer(i64 port,
                                                    code_string webroot) {
    if (!webroot || !webroot[0]) {
        fprintf(stderr, "Acme.ChallengeServer: webroot required\n");
        return -1;
    }
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return -2;
    int one = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(sfd, 64) < 0) {
        close(sfd);
        return -2;
    }
    fprintf(stdout,
        "Acme.ChallengeServer: listening on :%lld (webroot=%s)\n",
        (long long)port, webroot);
    fflush(stdout);

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        /* Read up to 8 KB of request — way more than needed for
         * a challenge GET. */
        char req[8192];
        ssize_t n = recv(cfd, req, sizeof(req) - 1, 0);
        if (n <= 0) { close(cfd); continue; }
        req[n] = 0;

        /* Parse: "GET /path HTTP/1.x\r\n..." */
        char path[1024]; path[0] = 0;
        if (sscanf(req, "GET %1023s HTTP/", path) != 1) {
            const char* bad = "HTTP/1.1 400 Bad Request\r\n"
                              "Content-Length: 0\r\n\r\n";
            send(cfd, bad, strlen(bad), 0);
            close(cfd);
            continue;
        }

        if (strncmp(path, "/.well-known/acme-challenge/", 28) == 0) {
            /* Serve from webroot. Path-traversal guard: token must
             * not contain '/' or '..'. */
            const char* token = path + 28;
            if (strchr(token, '/') || strstr(token, "..")) {
                const char* bad = "HTTP/1.1 400 Bad Request\r\n"
                                  "Content-Length: 0\r\n\r\n";
                send(cfd, bad, strlen(bad), 0);
                close(cfd);
                continue;
            }
            char file_path[2048];
            snprintf(file_path, sizeof(file_path),
                     "%s/.well-known/acme-challenge/%s", webroot, token);
            FILE* f = fopen(file_path, "r");
            if (!f) {
                const char* nf = "HTTP/1.1 404 Not Found\r\n"
                                 "Content-Length: 0\r\n"
                                 "Connection: close\r\n\r\n";
                send(cfd, nf, strlen(nf), 0);
                close(cfd);
                continue;
            }
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            char* body = (char*)malloc(sz + 1);
            fread(body, 1, sz, f);
            body[sz] = 0;
            fclose(f);

            char hdr[256];
            int hlen = snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %ld\r\n"
                "Connection: close\r\n\r\n", sz);
            send(cfd, hdr, hlen, 0);
            if (sz > 0) send(cfd, body, sz, 0);
            free(body);
        } else {
            /* Everything else: 301 redirect to HTTPS. We don't know
             * the host header reliably here, so emit a relative
             * redirect — the browser appends the same host. */
            char hdr[1024];
            int hlen = snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://localhost%s\r\n"  /* placeholder host */
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n", path);
            send(cfd, hdr, hlen, 0);
        }
        close(cfd);
    }
    /* unreachable */
    close(sfd);
    return 0;
}

static inline void Amalgame_Tls_TlsStream_Close(AmalgameTlsStream* s) {
    if (!s || !s->_ssl) return;
    SSL* ssl = (SSL*) s->_ssl;
    if (s->Connected) {
        SSL_shutdown(ssl);
        s->Connected = false;
    }
    SSL_free(ssl);
    s->_ssl = NULL;
}

static inline code_bool Amalgame_Tls_TlsStream_IsConnected(
        AmalgameTlsStream* s) {
    return s && s->Connected;
}

static inline code_string Amalgame_Tls_TlsStream_LastError(
        AmalgameTlsStream* s) {
    return s ? s->LastError : "";
}

static inline code_string Amalgame_Tls_TlsStream_PeerCertSubject(
        AmalgameTlsStream* s) {
    if (!s || !s->_ssl) return "";
    X509* peer = SSL_get_peer_certificate((SSL*) s->_ssl);
    if (!peer) return "";
    X509_NAME* subj = X509_get_subject_name(peer);
    char buf[256];
    X509_NAME_oneline(subj, buf, sizeof(buf));
    X509_free(peer);
    return _amtls_strdup(buf);
}

static inline code_string Amalgame_Tls_TlsStream_AlpnProto(
        AmalgameTlsStream* s) {
    return s ? s->AlpnNegotiated : "";
}

static inline code_string Amalgame_Tls_TlsStream_TlsVersion(
        AmalgameTlsStream* s) {
    if (!s || !s->_ssl) return "";
    return _amtls_strdup(SSL_get_version((SSL*) s->_ssl));
}

static inline code_string Amalgame_Tls_TlsStream_CipherSuite(
        AmalgameTlsStream* s) {
    if (!s || !s->_ssl) return "";
    return _amtls_strdup(SSL_get_cipher_name((SSL*) s->_ssl));
}

#else /* no OpenSSL */

/* ================================================================
   Stub implementation — every call surfaces a clear error.
   ----------------------------------------------------------------
   This keeps user code compilable when OpenSSL isn't installed.
   The error is the same for every call so users get a single,
   actionable message on first use.
   ================================================================ */

#define _AMTLS_STUB_ERR \
    "amalgame-tls: OpenSSL not found. Install libssl-dev (Linux), " \
    "openssl@3 (macOS Homebrew), or mingw-w64-openssl (Windows MSYS2)."

static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_Default(void) {
    AmalgameTlsConfig* c =
        (AmalgameTlsConfig*) GC_MALLOC(sizeof(AmalgameTlsConfig));
    memset(c, 0, sizeof(*c));
    c->CertFile = ""; c->KeyFile = ""; c->CertPem = ""; c->KeyPem = "";
    c->CaBundlePath = ""; c->AlpnCsv = "";
    return c;
}
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithCertFile(
    AmalgameTlsConfig* c, code_string a, code_string b)
    { (void)a; (void)b; return c; }
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithCertBytes(
    AmalgameTlsConfig* c, code_string a, code_string b)
    { (void)a; (void)b; return c; }
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithClientAuth(
    AmalgameTlsConfig* c, code_string a) { (void)a; return c; }
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithMinVersion(
    AmalgameTlsConfig* c, i64 v) { (void)v; return c; }
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithAlpn(
    AmalgameTlsConfig* c, code_string a) { (void)a; return c; }
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithSessionTickets(
    AmalgameTlsConfig* c, code_bool a) { (void)a; return c; }
static inline AmalgameTlsConfig* Amalgame_Tls_TlsConfig_WithInsecureSkipVerify(
    AmalgameTlsConfig* c, code_bool a) { (void)a; return c; }

static inline AmalgameTlsContext* _amtls_stub_ctx(code_bool isServer) {
    AmalgameTlsContext* tc =
        (AmalgameTlsContext*) GC_MALLOC(sizeof(AmalgameTlsContext));
    tc->_ctx = NULL;
    tc->IsServer = isServer;
    tc->LastError = _AMTLS_STUB_ERR;
    return tc;
}
static inline AmalgameTlsContext* Amalgame_Tls_TlsContext_Server(
    AmalgameTlsConfig* cfg) { (void)cfg; return _amtls_stub_ctx(true); }
static inline AmalgameTlsContext* Amalgame_Tls_TlsContext_Client(
    AmalgameTlsConfig* cfg) { (void)cfg; return _amtls_stub_ctx(false); }
static inline code_string Amalgame_Tls_TlsContext_LastError(
    AmalgameTlsContext* tc) { return tc ? tc->LastError : _AMTLS_STUB_ERR; }

static inline AmalgameTlsStream* Amalgame_Tls_TlsStream_Wrap(
        i64 fd, AmalgameTlsContext* tc, code_bool isServer) {
    (void)fd; (void)tc; (void)isServer;
    AmalgameTlsStream* s =
        (AmalgameTlsStream*) GC_MALLOC(sizeof(AmalgameTlsStream));
    memset(s, 0, sizeof(*s));
    s->LastError = _AMTLS_STUB_ERR;
    s->AlpnNegotiated = "";
    return s;
}
static inline code_bool Amalgame_Tls_TlsStream_Handshake(AmalgameTlsStream* s)
    { (void)s; return false; }
static inline i64 Amalgame_Tls_TlsStream_Read(
    AmalgameTlsStream* s, AmalgameList* b, i64 m)
    { (void)s; (void)b; (void)m; return -1; }
static inline i64 Amalgame_Tls_TlsStream_Write(
    AmalgameTlsStream* s, AmalgameList* b)
    { (void)s; (void)b; return -1; }
static inline i64 Amalgame_Tls_TlsStream_ReadBytes(
    AmalgameTlsStream* s, char* buf, i64 max)
    { (void)s; (void)buf; (void)max; return -1; }
static inline i64 Amalgame_Tls_TlsStream_WriteBytes(
    AmalgameTlsStream* s, const char* buf, i64 len)
    { (void)s; (void)buf; (void)len; return -1; }
static inline void Amalgame_Tls_TlsStream_Close(AmalgameTlsStream* s)
    { (void)s; }
static inline code_bool Amalgame_Tls_TlsStream_IsConnected(AmalgameTlsStream* s)
    { (void)s; return false; }
static inline code_string Amalgame_Tls_TlsStream_LastError(AmalgameTlsStream* s)
    { return s ? s->LastError : _AMTLS_STUB_ERR; }
static inline code_string Amalgame_Tls_TlsStream_PeerCertSubject(
    AmalgameTlsStream* s) { (void)s; return ""; }
static inline code_string Amalgame_Tls_TlsStream_AlpnProto(
    AmalgameTlsStream* s) { (void)s; return ""; }
static inline code_string Amalgame_Tls_TlsStream_TlsVersion(
    AmalgameTlsStream* s) { (void)s; return ""; }
static inline code_string Amalgame_Tls_TlsStream_CipherSuite(
    AmalgameTlsStream* s) { (void)s; return ""; }

#endif /* AMALGAME_HAS_OPENSSL */

#endif /* AMALGAME_TLS_H */
