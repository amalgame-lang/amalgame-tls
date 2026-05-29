# `acme-renew` — one-shot Let's Encrypt cert renewal CLI

A tiny binary that wraps `AcmeNative.EnsureCert`. Designed to be
driven from cron / systemd timers in front of any HTTPS app
(Mosaic, your own `Https.Serve`, even an external server like nginx
that loads PEMs from disk).

No certbot, no acme.sh, no lego. Just `./acme-renew` + libssl.

## Build

```sh
./build.sh
```

`build.sh` mirrors the working pattern from `tests/run_tests.sh`:
pre-builds `crypto.am` + `json.am` + `acme.am` as `.o` files, then
links the user binary against them using a fake package-cache + a
transient `amalgame.lock` rooted at `$PKG_DIR`. Force-includes
`Amalgame_Tls.h` and `Amalgame_Tls_Acme.h` at gcc time so that
`AMALGAME_HAS_OPENSSL` is defined and the `AmalgameTlsAcmeHttpResponse`
typedef is in scope.

The cleaner `amc build main.am` recipe is the long-term plan —
blocked today on two issues in amc v0.8.5x (multi-source resolver
loses sibling-class typedefs during the `--lib` precompile of
`acme.am`, and the autodetect macro for OpenSSL isn't visible when
the generated `acme.c` is gcc'd in isolation). amalgame-tls CI runs
against amc v0.8.38 where neither bug exists.

Expected layout (sibling checkouts under `~/Développement/`):

```
amalgame-tls/        (this repo)
amalgame-crypto/
Amalgame/            (amc + runtime + stdlib)
```

## Run

```sh
acme-renew <domain> <email> <dir> [--staging | --prod]
```

| Arg       | Meaning                                                          |
|-----------|------------------------------------------------------------------|
| `domain`  | FQDN to issue a cert for — must resolve (A/AAAA) to this host    |
| `email`   | Contact email registered with the ACME account                   |
| `dir`     | Writable directory (account.key + per-domain cert dir live here) |
| `--staging` | Use Let's Encrypt staging (untrusted, generous rate limits)    |
| `--prod`  | Use Let's Encrypt production (default — trusted certs)           |

Output layout after a successful run:

```
<dir>/
├── account.key                   # ES256 PEM PKCS#8 (reused on renewals)
├── account.url                   # ACME account URL (cached)
└── <domain>/
    ├── fullchain.pem             # leaf + intermediates
    └── privkey.pem               # cert private key
```

Point your HTTPS server at `fullchain.pem` + `privkey.pem`.

## First-time bootstrap

Always test against **staging** first — LE production has a 5-issuance
per-week-per-domain rate limit that's easy to burn through:

```sh
sudo ./acme-renew demo.example.com ops@example.com /etc/amalgame-tls --staging
# certs land in /etc/amalgame-tls/demo.example.com/
# delete that dir before re-running in --prod, or LE will reuse the
# staging account
```

When the staging flow goes green end-to-end, flip to prod:

```sh
sudo ./acme-renew demo.example.com ops@example.com /etc/amalgame-tls
```

## Cron-driven renewal (recommended)

LE certs are valid 90 days; renew every 60. The challenge needs
**port 80 free** for ~30 seconds — stop the website that owns it
during the window:

```cron
# /etc/cron.d/letsencrypt-amalgame
# Every 60 days at 3am — brief downtime while the http-01 challenge runs
0 3 1 */2 * root \
    pm2 stop website && \
    /usr/local/bin/acme-renew demo.example.com ops@example.com /etc/amalgame-tls ; \
    pm2 start website && \
    systemctl reload mosaic
```

The `systemctl reload` (or equivalent SIGHUP / app-specific signal)
makes the HTTPS server re-read the cert files. If your app reads
the PEMs only at startup, restart it instead.

## Privileged port 80

`AcmeNative` spawns its own HTTP listener on :80 for the http-01
challenge. Three ways to get that bind:

1. **Run as root** — simplest, what the cron example above does.
2. **`setcap`** once after each build:

   ```sh
   sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/acme-renew
   ```

3. **systemd timer** with `AmbientCapabilities=CAP_NET_BIND_SERVICE`
   on the service unit.

## Exit codes

| Code | Meaning                                                       |
|------|---------------------------------------------------------------|
| 0    | Cert + key written to disk                                    |
| 2    | Bad CLI arguments                                             |
| -1   | (= 255) Empty domain / email / dir passed to `EnsureCert`     |
| -2   | (= 254) HTTPS / directory / account / order setup failure     |
| -3   | (= 253) http-01 challenge failed (port 80 in use? DNS wrong?) |
| -4   | (= 252) finalize / cert download failed                       |

`stderr` carries the per-step ACME flow detail — pipe it to your
logger.

## Limitations (v0.3.2)

- **http-01 challenge only.** No dns-01 (would unblock port-80-locked
  hosts) and no tls-alpn-01. Planned for a future release.
- **Single domain per call.** Multi-SAN was on the v0.2.x certbot
  wrapper; not yet wired through to the native client.
- **ES256 account key only.** RS256 is supported by JwsKey but not
  surfaced through `EnsureCert`.
