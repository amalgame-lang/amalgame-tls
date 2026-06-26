/* ================================================================
   Amalgame_Tls_Acme.h — native ACME (RFC 8555) C primitives.

   Companion to Amalgame_Tls.h. Provides the two C-side pieces of
   the native ACME flow that don't fit AM (HTTPS round-trip + CSR
   DER encoding); the state machine, JWS payload assembly, and
   challenge-server orchestration live in acme.am.

   Public surface (all included via Amalgame_Tls.h since v0.3.0):

     AmalgameTlsAcmeHttpResponse* Acme_Http(
         url, method, content_type, body)
       — Minimal HTTPS client.  Returns NULL on transport failure
         (DNS / connect / TLS handshake / read).  Otherwise the
         struct's status / body / location / nonce fields are
         always non-NULL strings (empty when the header isn't sent).

     code_string Acme_CsrDer_Base64Url(jws_key_handle, domain)
       — Build a PKCS#10 CSR DER for `domain` (single CN + SAN),
         signed by the EVP_PKEY pointed to by jws_key_handle (the
         opaque integer carried by Amalgame.Crypto.JwsKey.Handle),
         then base64url-encode it for the ACME finalize request.
         Returns "" on any failure.

     code_string Acme_LoadPemFile(path)
     i64         Acme_SavePemFile(path, content)
       — File I/O helpers.  Pure AM I/O works too but these handle
         the 0600 mode automatically for cert/key files.

   The HTTPS client deliberately reimplements a small request/
   response loop rather than reaching back into net-http's
   HttpClient: net-http's client is TCP-only today, and pulling
   in a TLS-aware HTTP client would either re-introduce libcurl
   (which amc dropped in v0.8.31) or upgrade net-http first.
   The ACME need is narrow — three methods, two response headers
   to capture, body < 64 KB in practice — so an inline
   ~150-line C client is the cheaper engineering choice.

   ================================================================ */

#ifndef AMALGAME_TLS_ACME_H
#define AMALGAME_TLS_ACME_H

#ifdef AMALGAME_HAS_OPENSSL

#include <openssl/x509.h>
#include <openssl/pem.h>
#ifndef _WIN32
  #include <netdb.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <fcntl.h>
#else
  #include <direct.h>   /* _mkdir for the cert-dir mkdir -p */
#endif
/* On Windows the socket API + getaddrinfo come from winsock2/ws2tcpip,
 * already included by Amalgame_Tls.h (which pulls this header in after
 * its POSIX→Winsock shim), so the socket/close calls below route through
 * the shared shim macros. */

typedef struct AmalgameTlsAcmeHttpResponse {
    i64           status;     /* HTTP status code (200, 201, 400, …) */
    code_string   body;       /* Response body, always non-NULL (may be "") */
    code_string   location;   /* Location header, "" if absent */
    code_string   nonce;      /* Replay-Nonce header, "" if absent */
    code_string   content_type; /* Content-Type, "" if absent */
} AmalgameTlsAcmeHttpResponse;

/* Parse a URL into (host, port, path).  Scheme MUST be "https".
 * Returns 1 on success, 0 on malformed input. */
static inline int amalgame_tls_acme_parse_url(
        const char* url,
        char* host_out, size_t host_max,
        char* port_out, size_t port_max,
        char* path_out, size_t path_max) {
    if (!url) return 0;
    static const char prefix[] = "https://";
    size_t plen = sizeof(prefix) - 1;
    if (strncmp(url, prefix, plen) != 0) return 0;
    const char* h = url + plen;

    /* host : up to ':' or '/' */
    const char* slash = strchr(h, '/');
    const char* colon = strchr(h, ':');
    if (colon && slash && colon > slash) colon = NULL;

    size_t host_len;
    if (colon) host_len = (size_t)(colon - h);
    else if (slash) host_len = (size_t)(slash - h);
    else host_len = strlen(h);
    if (host_len == 0 || host_len + 1 > host_max) return 0;
    memcpy(host_out, h, host_len);
    host_out[host_len] = 0;

    /* port */
    if (colon) {
        const char* p = colon + 1;
        size_t port_len = slash ? (size_t)(slash - p) : strlen(p);
        if (port_len == 0 || port_len + 1 > port_max) return 0;
        memcpy(port_out, p, port_len);
        port_out[port_len] = 0;
    } else {
        if (port_max < 4) return 0;
        memcpy(port_out, "443", 4);
    }

    /* path */
    if (slash) {
        size_t path_len = strlen(slash);
        if (path_len + 1 > path_max) return 0;
        memcpy(path_out, slash, path_len + 1);
    } else {
        if (path_max < 2) return 0;
        memcpy(path_out, "/", 2);
    }
    return 1;
}

/* Read response into a growing GC buffer until EOF / SSL_read returns
 * zero.  Cap at 16 MB so a misbehaving server can't pin memory. */
#define AMALGAME_TLS_ACME_RESP_CAP (16u * 1024u * 1024u)

static inline char* amalgame_tls_acme_read_all(SSL* ssl, size_t* out_len) {
    size_t cap = 16 * 1024;
    size_t len = 0;
    char* buf = (char*) GC_MALLOC(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 4096 + 1 > cap) {
            if (cap >= AMALGAME_TLS_ACME_RESP_CAP) break;
            size_t ncap = cap * 2;
            if (ncap > AMALGAME_TLS_ACME_RESP_CAP) ncap = AMALGAME_TLS_ACME_RESP_CAP;
            char* nb = (char*) GC_MALLOC(ncap);
            if (!nb) break;
            memcpy(nb, buf, len);
            buf = nb;
            cap = ncap;
        }
        int n = SSL_read(ssl, buf + len, 4096);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN ||
                err == SSL_ERROR_SYSCALL ||
                err == SSL_ERROR_SSL) break;
            if (n == 0) break;
            break;
        }
        len += (size_t) n;
    }
    buf[len] = 0;
    if (out_len) *out_len = len;
    return buf;
}

/* Locate the end of the response headers ("\r\n\r\n") and split the
 * raw buffer into (headers, body).  In-place: returns the body
 * pointer and NUL-terminates the headers chunk.  Returns NULL if
 * no header terminator is present. */
static inline char* amalgame_tls_acme_split_headers(char* raw, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (raw[i] == '\r' && raw[i+1] == '\n' &&
            raw[i+2] == '\r' && raw[i+3] == '\n') {
            raw[i] = 0;
            return raw + i + 4;
        }
    }
    return NULL;
}

/* Look up a header (case-insensitive on the name).  `headers` is a
 * NUL-terminated block of CRLF-separated lines.  Returns a freshly
 * allocated NUL-terminated copy of the value (trimmed of leading
 * spaces).  Returns "" if not present. */
static inline char* amalgame_tls_acme_header(const char* headers, const char* name) {
    size_t nlen = strlen(name);
    const char* p = headers;
    while (*p) {
        const char* line_end = strstr(p, "\r\n");
        if (!line_end) line_end = p + strlen(p);
        size_t line_len = (size_t)(line_end - p);
        if (line_len > nlen + 1) {
            int match = 1;
            for (size_t i = 0; i < nlen; i++) {
                char a = p[i], b = name[i];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b) { match = 0; break; }
            }
            if (match && p[nlen] == ':') {
                const char* v = p + nlen + 1;
                while (v < line_end && (*v == ' ' || *v == '\t')) v++;
                size_t vlen = (size_t)(line_end - v);
                char* out = (char*) GC_MALLOC(vlen + 1);
                memcpy(out, v, vlen);
                out[vlen] = 0;
                return out;
            }
        }
        if (*line_end == 0) break;
        p = line_end + 2;
    }
    char* empty = (char*) GC_MALLOC(1);
    empty[0] = 0;
    return empty;
}

/* Make the named TCP+TLS connection.  Returns the SSL* handshake-
 * complete or NULL on any failure.  `out_fd` receives the socket fd
 * so the caller can close it after SSL_free. */
static inline SSL* amalgame_tls_acme_dial(SSL_CTX* ctx, const char* host,
                                           const char* port, int* out_fd) {
    *out_fd = -1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return NULL;
    int fd = -1;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return NULL;

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { close(fd); return NULL; }
    SSL_set_fd(ssl, fd);
    /* SNI + hostname verification — modern OpenSSL refuses to
     * cooperate with public CAs without these set. */
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set1_host(ssl, host);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); close(fd); return NULL;
    }
    *out_fd = fd;
    return ssl;
}

/* The lazy global SSL_CTX shared by all ACME requests.  Uses the
 * system default CA bundle (OpenSSL's SSL_CTX_set_default_verify_paths
 * picks up /etc/ssl/certs on Linux, the Homebrew bundle on macOS). */
static inline SSL_CTX* amalgame_tls_acme_get_ctx(void) {
    static SSL_CTX* ctx = NULL;
    if (!ctx) {
        static int ssl_initialised = 0;
        if (!ssl_initialised) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            ssl_initialised = 1;
        }
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
            if (!SSL_CTX_set_default_verify_paths(ctx)) {
                fprintf(stderr,
                    "Acme.Http: SSL_CTX_set_default_verify_paths failed\n");
            }
        }
    }
    return ctx;
}

static inline AmalgameTlsAcmeHttpResponse* Amalgame_Tls_Acme_Http(
        code_string url, code_string method,
        code_string content_type, code_string body) {

    if (!url || !method) return NULL;
    if (!body) body = "";
    if (!content_type) content_type = "";

    char host[256], port[8], path[1024];
    if (!amalgame_tls_acme_parse_url(url, host, sizeof(host),
                                          port, sizeof(port),
                                          path, sizeof(path))) {
        fprintf(stderr, "Acme.Http: bad URL '%s'\n", url);
        return NULL;
    }
    SSL_CTX* ctx = amalgame_tls_acme_get_ctx();
    if (!ctx) {
        fprintf(stderr, "Acme.Http: SSL_CTX setup failed\n");
        return NULL;
    }
    int fd = -1;
    SSL* ssl = amalgame_tls_acme_dial(ctx, host, port, &fd);
    if (!ssl) {
        fprintf(stderr, "Acme.Http: %s://%s:%s — dial / TLS failed\n",
                "https", host, port);
        return NULL;
    }

    /* Assemble the request.  ACME bodies are tiny (< 4 KB JWS); a
     * single stack buffer is enough — body capped at 64 KB out of
     * paranoia. */
    size_t blen = strlen(body);
    if (blen > 64 * 1024) {
        SSL_free(ssl); close(fd);
        fprintf(stderr, "Acme.Http: body > 64KB rejected\n");
        return NULL;
    }
    char hdr[4096];
    int hl = snprintf(hdr, sizeof(hdr),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: amalgame-tls/0.3.0 (acme)\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n"
        "%s%s%s"
        "\r\n",
        method, path, host, blen,
        content_type[0] ? "Content-Type: " : "",
        content_type[0] ? content_type      : "",
        content_type[0] ? "\r\n"            : "");
    if (hl < 0 || (size_t)hl >= sizeof(hdr)) {
        SSL_free(ssl); close(fd);
        fprintf(stderr, "Acme.Http: request line / headers > 4KB\n");
        return NULL;
    }
    if (SSL_write(ssl, hdr, hl) != hl) {
        SSL_free(ssl); close(fd);
        fprintf(stderr, "Acme.Http: write headers failed\n");
        return NULL;
    }
    if (blen > 0) {
        if (SSL_write(ssl, body, (int) blen) != (int) blen) {
            SSL_free(ssl); close(fd);
            fprintf(stderr, "Acme.Http: write body failed\n");
            return NULL;
        }
    }

    /* Read the whole response. */
    size_t raw_len = 0;
    char* raw = amalgame_tls_acme_read_all(ssl, &raw_len);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    if (!raw || raw_len < 12) {
        fprintf(stderr, "Acme.Http: short or empty response\n");
        return NULL;
    }

    /* Parse status line. */
    if (strncmp(raw, "HTTP/1.", 7) != 0 ||
        (raw[7] != '0' && raw[7] != '1') || raw[8] != ' ') {
        fprintf(stderr, "Acme.Http: malformed status line\n");
        return NULL;
    }
    int status = (raw[9] - '0') * 100
               + (raw[10] - '0') * 10
               +  raw[11] - '0';
    if (status < 100 || status > 599) {
        fprintf(stderr, "Acme.Http: bad status code\n");
        return NULL;
    }

    /* Find the headers/body boundary. */
    char* body_ptr = amalgame_tls_acme_split_headers(raw, raw_len);
    if (!body_ptr) {
        fprintf(stderr, "Acme.Http: missing header terminator\n");
        return NULL;
    }
    /* Skip the first line (HTTP/x.x status reason). */
    char* hstart = strstr(raw, "\r\n");
    if (hstart) hstart += 2; else hstart = raw;

    AmalgameTlsAcmeHttpResponse* r = (AmalgameTlsAcmeHttpResponse*)
        GC_MALLOC(sizeof(*r));
    r->status       = (i64) status;
    r->body         = body_ptr;
    r->location     = amalgame_tls_acme_header(hstart, "Location");
    r->nonce        = amalgame_tls_acme_header(hstart, "Replay-Nonce");
    r->content_type = amalgame_tls_acme_header(hstart, "Content-Type");
    return r;
}

/* ── CSR DER (PKCS#10) ────────────────────────────────────────────
 *
 * Build a CertificateSigningRequest with a single Subject CN +
 * SubjectAlternativeName (single dNSName entry) for `domain`, signed
 * by `pkey_handle` (i64 cast of EVP_PKEY*).
 *
 * RFC 8555 §11.5: the CSR's Subject is ignored by ACME CAs except
 * for the SAN extension, which is the authoritative list of
 * hostnames.  We still set CN = domain for legacy clients that
 * inspect the cert outside of an ACME flow.
 *
 * Returns the base64url-encoded DER (no padding, RFC 4648 §5), or
 * "" on any failure.  This is the form ACME expects in the
 * finalize-order POST.
 */
static inline code_string Amalgame_Tls_Acme_CsrDer_Base64Url(
        i64 pkey_handle, code_string domain) {
    EVP_PKEY* pkey = (EVP_PKEY*)(intptr_t) pkey_handle;
    if (!pkey || !domain || !domain[0]) return "";

    X509_REQ* req = X509_REQ_new();
    if (!req) return "";
    code_string out = "";
    int der_len = -1;
    unsigned char* der = NULL;

    do {
        /* version v1 (encoded as 0 per X.509) */
        if (!X509_REQ_set_version(req, 0)) break;

        /* `domain` may be a comma-separated list (multi-SAN). The first
         * non-empty element is the CN; every element becomes a dNSName
         * SAN. A single hostname (no comma) behaves exactly as before. */
        char _dbuf[1024];
        size_t _dl = strlen(domain);
        if (_dl >= sizeof(_dbuf)) break;
        memcpy(_dbuf, domain, _dl + 1);
        char* _dlist[64];   /* generous SAN cap, independent of include order */
        int _dn = 0;
        {
            char* _p = _dbuf;
            while (*_p && _dn < 64) {
                while (*_p == ' ' || *_p == '\t' || *_p == ',') _p++;
                if (!*_p) break;
                char* _s = _p;
                while (*_p && *_p != ',') _p++;
                char* _e = _p;
                if (*_p == ',') { *_p = '\0'; _p++; }
                while (_e > _s && (_e[-1] == ' ' || _e[-1] == '\t')) { _e--; *_e = '\0'; }
                if (*_s) _dlist[_dn++] = _s;
            }
        }
        if (_dn == 0) break;

        X509_NAME* name = X509_NAME_new();
        if (!name) break;
        if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                (const unsigned char*) _dlist[0], -1, -1, 0)) {
            X509_NAME_free(name); break;
        }
        if (!X509_REQ_set_subject_name(req, name)) {
            X509_NAME_free(name); break;
        }
        X509_NAME_free(name);

        /* SubjectAltName extension — one dNSName per element. */
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
        if (!exts) break;
        char san_value[2048];
        size_t _sp = 0;
        int _sanbad = 0;
        for (int _i = 0; _i < _dn; _i++) {
            int _w = snprintf(san_value + _sp, sizeof(san_value) - _sp,
                              "%sDNS:%s", _i ? "," : "", _dlist[_i]);
            if (_w < 0 || (size_t)(_sp + (size_t) _w) >= sizeof(san_value)) { _sanbad = 1; break; }
            _sp += (size_t) _w;
        }
        if (_sanbad) {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            break;
        }
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL,
                NID_subject_alt_name, san_value);
        if (!ext) {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            break;
        }
        sk_X509_EXTENSION_push(exts, ext);
        if (!X509_REQ_add_extensions(req, exts)) {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            break;
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

        if (!X509_REQ_set_pubkey(req, pkey)) break;
        if (!X509_REQ_sign(req, pkey, EVP_sha256())) break;

        der_len = i2d_X509_REQ(req, &der);
        if (der_len <= 0 || !der) break;

        /* base64url encode (no padding). */
        static const char alpha[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        size_t out_max = 4 * (((size_t) der_len + 2) / 3) + 1;
        char* o = (char*) GC_MALLOC(out_max);
        size_t oi = 0;
        size_t i = 0;
        while (i + 3 <= (size_t) der_len) {
            uint32_t v = ((uint32_t) der[i] << 16)
                       | ((uint32_t) der[i+1] << 8)
                       |  (uint32_t) der[i+2];
            o[oi++] = alpha[(v >> 18) & 0x3F];
            o[oi++] = alpha[(v >> 12) & 0x3F];
            o[oi++] = alpha[(v >>  6) & 0x3F];
            o[oi++] = alpha[ v        & 0x3F];
            i += 3;
        }
        size_t rem = (size_t) der_len - i;
        if (rem == 1) {
            uint32_t v = (uint32_t) der[i] << 16;
            o[oi++] = alpha[(v >> 18) & 0x3F];
            o[oi++] = alpha[(v >> 12) & 0x3F];
        } else if (rem == 2) {
            uint32_t v = ((uint32_t) der[i] << 16)
                       | ((uint32_t) der[i+1] << 8);
            o[oi++] = alpha[(v >> 18) & 0x3F];
            o[oi++] = alpha[(v >> 12) & 0x3F];
            o[oi++] = alpha[(v >>  6) & 0x3F];
        }
        o[oi] = 0;
        out = o;
    } while (0);

    if (der) OPENSSL_free(der);
    X509_REQ_free(req);
    return out;
}

/* ── File I/O helpers ─────────────────────────────────────────────
 * 0600 mode for keys, 0644 for certs.  Creates parent directories
 * with 0700 if needed.  Returns 0 on success, -1 on failure. */
static inline i64 Amalgame_Tls_Acme_SavePemFile(
        code_string path, code_string content, i64 secret) {
    if (!path || !path[0] || !content) return -1;
    /* mkdir -p of the parent. */
    char dir[1024];
    size_t pl = strlen(path);
    if (pl + 1 > sizeof(dir)) return -1;
    memcpy(dir, path, pl + 1);
    for (size_t i = pl; i > 0; i--) {
        if (dir[i] == '/') {
            dir[i] = 0;
            /* walk down creating each segment. */
            for (size_t j = 1; j <= strlen(dir); j++) {
                if (dir[j] == '/' || dir[j] == 0) {
                    char saved = dir[j];
                    dir[j] = 0;
                    if (dir[0]) {
#ifdef _WIN32
                        _mkdir(dir);
#else
                        mkdir(dir, 0700);
#endif
                    }
                    dir[j] = saved;
                    if (saved == 0) break;
                }
            }
            break;
        }
    }
    /* Portable file write via stdio — avoids POSIX open/write/fchmod AND
     * the socket-close shim macro (these fds are FILES, not sockets). */
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    size_t len = strlen(content);
    size_t wrote = fwrite(content, 1, len, f);
    fclose(f);
    if (wrote != len) return -1;
#ifndef _WIN32
    /* Best-effort restrictive perms for private keys (POSIX only). */
    chmod(path, secret ? 0600 : 0644);
#else
    (void) secret;
#endif
    return 0;
}

static inline code_string Amalgame_Tls_Acme_LoadPemFile(code_string path) {
    if (!path || !path[0]) return "";
    FILE* f = fopen(path, "rb");
    if (!f) return "";
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 0 || sz > 256 * 1024) { fclose(f); return ""; }
    char* buf = (char*) GC_MALLOC((size_t) sz + 1);
    size_t got = fread(buf, 1, (size_t) sz, f);
    fclose(f);
    buf[got] = 0;
    return buf;
}

/* ── Background http-01 challenge server ──────────────────────────
 *
 * fork() a child that runs Acme.ChallengeServer(port, webroot) and
 * returns its PID to the parent.  The parent uses the PID to kill
 * the child once the ACME server has validated the challenge.
 *
 * Returns >0 PID on success, -1 if fork failed.  The child never
 * returns from this function — it execs the ChallengeServer loop
 * directly (no execvp, just a C call), so it inherits the parent's
 * env / cwd / open FDs.  The fork+inherit pattern is safe here
 * because we kill the child cleanly before any AM code in the
 * parent touches the inherited state.
 */
static inline i64 Amalgame_Tls_Acme_SpawnChallengeServer(
        i64 port, code_string webroot) {
    if (!webroot || !webroot[0]) return -1;
#ifdef _WIN32
    /* fork() doesn't exist on Windows. ACME's standalone challenge
     * server (which forks a child) isn't supported on the native
     * Windows build — provide a cert file directly. FF-TAROT and other
     * plain-HTTP users never reach this path. */
    (void) port;
    return -1;
#else
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Child: run the existing ChallengeServer forever (it never
         * returns).  fprintf to stderr already goes to the parent's
         * controlling terminal, which is what we want. */
        Amalgame_Tls_Acme_ChallengeServer(port, webroot);
        _exit(1);
    }
    return (i64) pid;
#endif
}

static inline i64 Amalgame_Tls_Acme_StopProcess(i64 pid) {
    if (pid <= 0) return -1;
#ifdef _WIN32
    return 0;   /* no child was ever spawned (see SpawnChallengeServer) */
#else
    if (kill((pid_t) pid, SIGTERM) < 0) {
        if (errno != ESRCH) return -1;
        return 0;  /* already gone */
    }
    int status;
    /* Reap to avoid zombies.  Don't block forever — give the child
     * 250ms to exit cleanly, then SIGKILL. */
    for (int i = 0; i < 25; i++) {
        pid_t r = waitpid((pid_t) pid, &status, WNOHANG);
        if (r == (pid_t) pid) return 0;
        if (r < 0) return 0;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    kill((pid_t) pid, SIGKILL);
    waitpid((pid_t) pid, &status, 0);
    return 0;
#endif
}

#else  /* !AMALGAME_HAS_OPENSSL — stubs */

typedef struct AmalgameTlsAcmeHttpResponse {
    i64         status;
    code_string body;
    code_string location;
    code_string nonce;
    code_string content_type;
} AmalgameTlsAcmeHttpResponse;

static inline AmalgameTlsAcmeHttpResponse* Amalgame_Tls_Acme_Http(
        code_string url, code_string method,
        code_string content_type, code_string body) {
    (void)url; (void)method; (void)content_type; (void)body;
    fprintf(stderr, "Acme.Http: OpenSSL not compiled in\n");
    return NULL;
}
static inline code_string Amalgame_Tls_Acme_CsrDer_Base64Url(
        i64 h, code_string d) {
    (void)h; (void)d;
    return "";
}
static inline i64 Amalgame_Tls_Acme_SavePemFile(
        code_string p, code_string c, i64 s) {
    (void)p; (void)c; (void)s;
    return -1;
}
static inline code_string Amalgame_Tls_Acme_LoadPemFile(code_string p) {
    (void)p;
    return "";
}
static inline i64 Amalgame_Tls_Acme_SpawnChallengeServer(
        i64 p, code_string w) {
    (void)p; (void)w;
    return -1;
}
static inline i64 Amalgame_Tls_Acme_StopProcess(i64 pid) {
    (void)pid;
    return -1;
}

#endif /* AMALGAME_HAS_OPENSSL */

#endif /* AMALGAME_TLS_ACME_H */
