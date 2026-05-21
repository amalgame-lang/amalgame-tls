# letsencrypt-site — a real HTTPS site in ~50 lines

A self-contained Amalgame program that:

1. Provisions a real Let's Encrypt certificate at startup via
   `AcmeNative.EnsureCert` (RFC 8555, http-01 challenge).
2. Serves a single HTTPS route over that cert using
   `Amalgame.Net.Http.Https.Serve`.

No certbot, no shell scripts, no separate process supervisor.

## Prerequisites

- A public domain whose A/AAAA records point at the machine running
  this program. Let's Encrypt's validator will dial it on port 80
  during the http-01 dance.
- Ports 80 and 443 must be free on the machine. Either run as root,
  or grant the binary the bind-privileged-ports capability:

  ```sh
  sudo setcap 'cap_net_bind_service=+ep' ./server
  ```

- Install `tls` via `amc package add` — amc v0.8.39+ pulls
  `amalgame-crypto` and `amalgame-net-http` transitively from the
  `[dependencies]` table:

  ```sh
  amc package add tls
  ```

  Older amc (≤ v0.8.38) ignores `[dependencies]`; in that case run
  `amc package add crypto net-http tls` and pull each one yourself.

## Build

amc v0.8.39+ ships a one-shot pipeline (`amc build`) that auto-
precompiles the package facades and links everything into a
binary:

```sh
amc build server.am          # → ./server
```

Older amc (≤ v0.8.38) needs the manual `amc -o site server.am`
then a gcc invocation with all the package `.o` files — see the
`amalgame-web/tests/run_tests.sh` runner for the boilerplate.

## First run — against LE staging (no rate-limit grief)

```sh
DOMAIN=mysite.example.com \
  EMAIL=ops@example.com \
  CERT_DIR=./certs \
  ./server
```

The cert that comes out is **not trusted by browsers** in staging
mode — that's intentional. Test with `curl -k` (or import the
[staging root](https://letsencrypt.org/docs/staging-environment/)
into your local trust store).

## Going to production

```sh
DOMAIN=mysite.example.com \
  EMAIL=ops@example.com \
  CERT_DIR=./certs \
  ACME_SERVER=https://acme-v02.api.letsencrypt.org/directory \
  ./server
```

The cert will be trusted by every modern browser. **Don't iterate
against prod** — LE prod has a 5-issuance-per-week-per-domain cap.

## What gets written to disk

```
./certs/
├── account.key                       # ES256 PEM PKCS#8 — reused on subsequent runs
├── account.url                       # ACME account URL — cached so the second
│                                     # run reuses the existing account
├── mysite.example.com/
│   ├── fullchain.pem                 # leaf + intermediates (chain)
│   └── privkey.pem                   # cert private key (mode 0600)
└── webroot/.well-known/acme-challenge/
                                       # transient challenge files (created
                                       # by AcmeNative, served by its tiny
                                       # forked HTTP listener on :80)
```

`account.key` survives forever — losing it forces a new ACME account
on the next run, which is fine but wastes the issuance budget. Back
it up like any other secret.

## Renewal

Re-run the same command. AcmeNative reuses the cached account, does
a new order against the same domain, and overwrites
`fullchain.pem` / `privkey.pem`. Schedule with cron / systemd-timer
every 60 days (LE certs are valid 90 days, renew at 60 leaves a
30-day safety margin).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `AcmeNative.EnsureCert: SpawnChallengeServer failed (port 80 in use?)` | Another process holds :80 — stop it or `setcap`. |
| `AcmeNative: authz never reached valid` | DNS doesn't point at this machine, firewall blocks :80, or the http-01 file path 404'd. Check `./certs/webroot/.well-known/acme-challenge/<token>` exists during the run. |
| `AcmeNative: newAccount failed status=403` | LE refused the account — usually rate-limit or bad email. |
| `Https.Serve: TLS handshake failed` | Cert / key mismatch, or wrong key permissions. Verify `openssl x509 -in fullchain.pem -text -noout` and `openssl rsa -in privkey.pem -check`. |

## What's next

This example sticks to the bare `Acme + Https` API — one route,
plain `HttpResponse`, no routing layer.  For a real production app:

```sh
# Once-only install
curl -sSL https://raw.githubusercontent.com/amalgame-lang/mosaic/main/install.sh | bash

# Per-app
mosaic new my-site
cd my-site
mosaic dev                   # http://localhost:3000, livereload on save
```

[Mosaic](https://github.com/amalgame-lang/mosaic) wraps the same
`amalgame-web + amalgame-net-http + amalgame-tls + amalgame-crypto`
stack with:

- **Filesystem routing** — `app/<path>.am` → route, `[id]` → `:id`,
  `[...slug]` → `*slug`. Each file declares a `public class Page`
  with one method per HTTP verb.
- **`Amalgame.Web.WebApp`** for routing + middlewares (sessions,
  CSRF, rate limit, CORS, security headers — all configurable from
  `mosaic.toml`).
- **`Amalgame.Web.AcmeConfig.FromMap(tomlAcmeSection)`** to drive
  the ACME flow from `mosaic.toml` (`[tls.acme]`) instead of env
  vars — same `EnsureCertMulti` call underneath, just declarative.
- **`Amalgame.Web.TlsBindingConfig.FromMap(tomlTlsSection)`** for
  `min_version` / `alpn` knobs, fed into
  `HttpServerConfig.WithTlsMinVersion(13)` and `WithTlsAlpn(...)`.

If you don't want the framework — this single-file example is
self-contained and stays a valid path for tiny utilities or
sidecars that need HTTPS without the Mosaic surface.
