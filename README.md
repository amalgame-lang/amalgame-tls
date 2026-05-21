# amalgame-tls

TLS 1.2 / 1.3 client + server primitives for [Amalgame](https://github.com/amalgame-lang/Amalgame). Thin binding over **OpenSSL 3.x** (or LibreSSL — drop-in compatible).

This is the foundation layer of the Amalgame web stack: [`amalgame-net-http`](https://github.com/amalgame-lang/amalgame-net-http) builds on top of it for HTTPS, and [`amalgame-web`](https://github.com/amalgame-lang/amalgame-web) (Mosaic) builds on top of that for the full framework.

## Install

```bash
amc package add tls
```

You also need OpenSSL development headers (the runtime libraries are already installed on every modern OS):

| Platform | Command |
|---|---|
| Debian / Ubuntu | `sudo apt install libssl-dev` |
| Fedora / RHEL | `sudo dnf install openssl-devel` |
| Arch Linux | `sudo pacman -S openssl` |
| macOS (Homebrew) | `brew install openssl@3` |
| Windows (MSYS2) | `pacman -S mingw-w64-x86_64-openssl` |

The header auto-detects OpenSSL via `__has_include`. On macOS Homebrew it falls back to `/opt/homebrew/opt/openssl@3/include` (Apple Silicon) or `/usr/local/opt/openssl@3/include` (Intel) — no extra flags needed.

## API at a glance

```amalgame
import Amalgame.Tls

// Builder pattern for TLS settings.
let cfg: TlsConfig = TlsConfig.Default()
    .WithCertFile("cert.pem", "key.pem")
    .WithMinVersion(13)                       // TLS 1.3 floor
    .WithAlpn("h2,http/1.1")                  // ALPN advertisement

// Create a server context.
let ctx: TlsContext = TlsContext.Server(cfg)

// Wrap an already-connected socket fd (from amalgame-net or similar)
// and perform the TLS handshake.
let stream: TlsStream = TlsStream.Wrap(fd, ctx, true)   // true = server
if (!stream.Handshake()) {
    Console.WriteLine("TLS error: " + stream.LastError())
    return
}

// Negotiated parameters.
Console.WriteLine("TLS version : " + stream.TlsVersion())
Console.WriteLine("Cipher suite: " + stream.CipherSuite())
Console.WriteLine("ALPN proto  : " + stream.AlpnProto())

// Read / write encrypted payload.
let buf: List<int> = new List<int>()
let n: int = stream.Read(buf, 4096)

stream.Write(payload)
stream.Close()
```

## Classes

### `TlsConfig`

Fluent builder. All `With*` methods return the same config (mutated) so they chain.

| Method | Purpose |
|---|---|
| `Default()` | New config with sane defaults (TLS 1.2 floor, session tickets on) |
| `WithCertFile(certPath, keyPath)` | Server cert + key from PEM files |
| `WithCertBytes(certPem, keyPem)` | Same but from in-memory PEM strings |
| `WithClientAuth(caBundlePath)` | Require + verify client certs against a CA bundle |
| `WithMinVersion(v)` | `12` = TLS 1.2 (default), `13` = TLS 1.3 only |
| `WithAlpn(csv)` | ALPN list, e.g. `"h2,http/1.1"` |
| `WithSessionTickets(enabled)` | RFC 5077 session tickets |
| `WithInsecureSkipVerify(skip)` | Client-side: skip cert verification (DEV ONLY) |

### `TlsContext`

Wraps an OpenSSL `SSL_CTX`. Reusable across many `TlsStream` instances (the standard pattern: one context per server / client config, many streams per connection).

| Method | Purpose |
|---|---|
| `Server(cfg)` | New server-side context |
| `Client(cfg)` | New client-side context |
| `LastError()` | Last OpenSSL error from this context's setup |

### `TlsStream`

TLS over a raw fd. The fd comes from `amalgame-net` (TCP socket) or any other source that produces a connected file descriptor.

| Method | Purpose |
|---|---|
| `Wrap(fd, ctx, isServer)` | Wrap an existing socket fd with TLS |
| `Handshake()` | Perform `SSL_accept`/`SSL_connect`; returns true on success |
| `Read(buf, max)` | Decrypted bytes into a `List<int>`; returns bytes read |
| `Write(buf)` | Encrypt + write a `List<int>` of bytes |
| `Close()` | Send close-notify + free resources |
| `IsConnected()` | Whether the handshake completed and stream is live |
| `LastError()` | Last OpenSSL error from read/write/handshake |
| `PeerCertSubject()` | DN of the peer's certificate (RFC 2253-ish) |
| `AlpnProto()` | Negotiated ALPN protocol, e.g. `"h2"` |
| `TlsVersion()` | `"TLSv1.2"` or `"TLSv1.3"` |
| `CipherSuite()` | Negotiated cipher, e.g. `"TLS_AES_128_GCM_SHA256"` |

## Examples

### TLS echo server

```amalgame
import Amalgame.Net
import Amalgame.Tls

public class Program {
    public static void Main(string[] args) {
        let cfg = TlsConfig.Default().WithCertFile("server.pem", "server.key")
        let ctx = TlsContext.Server(cfg)

        let srv = TcpServer_Listen(8443, 5)
        while (TcpServer_IsListening(srv)) {
            let conn = TcpServer_Accept(srv)
            let stream = TlsStream.Wrap(conn._fd, ctx, true)
            if (!stream.Handshake()) {
                Console.WriteLine("TLS error: " + stream.LastError())
                continue
            }
            let buf = new List<int>()
            let n = stream.Read(buf, 4096)
            if (n > 0) {
                stream.Write(buf)
            }
            stream.Close()
            TcpConn_Close(conn)
        }
    }
}
```

### TLS client

```amalgame
import Amalgame.Net
import Amalgame.Tls

public class Program {
    public static void Main(string[] args) {
        let cfg = TlsConfig.Default().WithMinVersion(13)
        let ctx = TlsContext.Client(cfg)

        let conn = TcpClient_Connect("example.com", 443)
        let stream = TlsStream.Wrap(conn._fd, ctx, false)
        if (!stream.Handshake()) {
            Console.WriteLine("TLS error: " + stream.LastError())
            return
        }

        // Send a minimal HTTP/1.1 GET.
        let req = new List<int>()
        let s = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        for (var i = 0; i < String_Length(s); i = i + 1) {
            req.Add(String_CharCodeAt(s, i))
        }
        stream.Write(req)

        let buf = new List<int>()
        stream.Read(buf, 8192)
        Console.WriteLine("Got " + String_FromInt(buf.Count()) + " bytes")
        stream.Close()
    }
}
```

## Generating a self-signed cert for testing

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.pem \
        -days 365 -subj "/CN=localhost"
```

## Roadmap

- **v0.1**: file-based and inline-PEM certs, client+server, TLS 1.2/1.3, ALPN, client-auth, custom verify
- **v0.2**: ACME / Let's Encrypt automatic certs (tls-alpn-01 + http-01)
- **v0.2.1**: `Acme.EnsureCert` switched from `system()` to `fork`+`execvp` — eliminates shell-injection risk on user-controlled `domain`/`email`/`dir` arguments
- **v0.2.2**: `Acme.EnsureCertEx(domain, email, dir, acme_server, certbot_path)` — opt-in ACME directory URL (LE-staging / Buypass / ZeroSSL / corporate CA) + certbot binary path. Both also read from env vars `MOSAIC_TLS_ACME_SERVER` / `MOSAIC_TLS_CERTBOT_PATH` (and the bare `EnsureCert` keeps working — the env vars apply via the wrapper)
- **v0.2.3**: `Acme.EnsureCertMulti(domains, email, dir, acme_server, certbot_path)` — multi-SAN provisioning. `domains` is a comma-separated list (whitespace + empty entries tolerated); the first one becomes the cert-name so `Acme.CertPath(dom0, dir)` still resolves. Up to 32 SANs per cert. `EnsureCert` and `EnsureCertEx` are now thin wrappers
- **v0.3.0** ← *here*: **native ACME (RFC 8555)** via `AcmeNative.EnsureCert(domain, email, dir, acme_server)`. Pure-AM state machine (directory → newNonce → newAccount → newOrder → http-01 → finalize → cert pickup) built on `amalgame-crypto v0.3.0`'s `JwsKey` (ES256) and an inline HTTPS client (`runtime/Amalgame_Tls_Acme.h`). No subprocess, no certbot dep. Account key persisted at `<dir>/account.key`; cert at `<dir>/<domain>/{fullchain,privkey}.pem`. http-01 challenge only in v0.3.0; multi-SAN returns in v0.3.1. Legacy `Acme.EnsureCert*` (certbot wrapper) is kept side-by-side
- **v0.3.x**: SNI handler (multi-cert dispatch), OCSP stapling, dns-01 challenge support, multi-SAN in AcmeNative

## License

Apache-2.0. See [LICENSE](./LICENSE).
