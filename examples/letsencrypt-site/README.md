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
  sudo setcap 'cap_net_bind_service=+ep' ./site
  ```

- The packages are installed via `amc package add`. **All three are
  required** — amc doesn't yet pull transitive deps automatically
  (tracked for the v0.3.1 / amc-resolver follow-up):

  ```sh
  amc package add crypto net-http tls
  ```

  - `tls` brings the cert primitives + `AcmeNative`.
  - `net-http` brings `Https.Serve` / `HttpResponse` / `HttpRequest`.
  - `crypto` brings `JwsKey` (ES256 signing for the ACME account).

## Build

```sh
amc -o site server.am
```

## First run — against LE staging (no rate-limit grief)

```sh
DOMAIN=mysite.example.com \
  EMAIL=ops@example.com \
  CERT_DIR=./certs \
  ./site
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
  ./site
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

This example sticks to the bare `Acme + Https` API. For a real
Mosaic app you'd typically pair it with:

- `Amalgame.Web.WebApp` for routing + middlewares (sessions, CSRF,
  rate limit, …).
- `Amalgame.Web.AcmeConfig.FromMap(tomlAcmeSection)` to drive the
  same flow from `mosaic.toml` instead of env vars.
- `Https.ServeWith(port, cert, key, cfg, handler)` to wire
  `HttpServerConfig.WithTlsMinVersion(13)` and similar tunables.
