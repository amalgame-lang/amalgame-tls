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
