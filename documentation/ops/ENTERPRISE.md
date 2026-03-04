# NoctisAPI — Enterprise Deployment Guide

Covers production deployment behind F5 BIG-IP and Cloudflare, outbound proxy
configuration, TLS inspection environments, and a full reference of every
environment variable the stack consumes.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Deployment Behind Cloudflare](#2-deployment-behind-cloudflare)
3. [Deployment Behind F5 BIG-IP](#3-deployment-behind-f5-big-ip)
4. [Outbound Proxy Configuration](#4-outbound-proxy-configuration)
5. [TLS Inspection Considerations](#5-tls-inspection-considerations)
6. [Startup Diagnostics](#6-startup-diagnostics)
7. [Environment Variable Reference](#7-environment-variable-reference)

---

## 1. Architecture Overview

```
                         ┌──────────────────────────────────────────┐
                         │            Enterprise Perimeter           │
                         │                                           │
  Internet               │   ┌─────────────┐   ┌─────────────────┐  │
  ──────────►  80/443    │   │  Cloudflare  │   │    F5 BIG-IP    │  │
                         │   │  (or CDN)   │   │  (or Traefik)   │  │
                         │   └──────┬──────┘   └────────┬────────┘  │
                         │          │ HTTPS              │ HTTPS     │
                         │          └─────────┬──────────┘           │
                         │                   │                       │
                         └───────────────────┼───────────────────────┘
                                             │  X-Forwarded-For
                                             │  X-Forwarded-Proto
                                             │  CF-Connecting-IP (Cloudflare)
                                             ▼
                         ┌───────────────────────────────────────────┐
                         │           Docker Host / Kubernetes        │
                         │                                           │
                         │  ┌──────────────────────────────────────┐ │
                         │  │          NoctisAPI Container         │ │
                         │  │                                      │ │
                         │  │  RequestTimeoutMiddleware (ASGI)     │ │
                         │  │  ReverseProxyMiddleware  (ASGI)      │ │
                         │  │  log_all_requests        (ASGI)      │ │
                         │  │  CORSMiddleware           (ASGI)     │ │
                         │  │  FastAPI route handlers              │ │
                         │  │                                      │ │
                         │  │  :8000  Public API                   │ │
                         │  │  :9001  Admin Panel (loopback only)  │ │
                         │  └──────────────────────────────────────┘ │
                         │                                           │
                         │       Egress (outbound)                   │
                         │  ┌────────────┐   ┌─────────────────────┐ │
                         │  │  Corp Proxy│──►│  license.unkwn0wn   │ │
                         │  │  (optional)│   │  pro-backend        │ │
                         │  └────────────┘   └─────────────────────┘ │
                         └───────────────────────────────────────────┘
```

### Middleware Execution Order

Starlette adds middleware in LIFO order, so the stack executes as:

```
Request  →  RequestTimeoutMiddleware
         →  ReverseProxyMiddleware
         →  log_all_requests
         →  CORSMiddleware
         →  Route handler
Response ←  (same path, reverse)
```

`RequestTimeoutMiddleware` is outermost: it wraps the entire ASGI call, so the
408 timer includes reverse-proxy header rewriting and logging overhead.

---

## 2. Deployment Behind Cloudflare

### 2.1 Network Topology

```
                    Cloudflare Edge
                    ┌─────────────────────────────┐
  Browser ─HTTPS──► │ DDoS / WAF / CDN / Ratelimit │
                    └──────────┬──────────────────┘
                               │ HTTPS (origin pull)
                               │ CF-Connecting-IP: <real-client>
                               │ X-Forwarded-For: <real-client>
                               │ X-Forwarded-Proto: https
                               ▼
                    ┌──────────────────────┐
                    │  Traefik / nginx     │  (optional; on same host)
                    └──────────┬───────────┘
                               │ HTTP (cleartext to container)
                               ▼
                    ┌──────────────────────┐
                    │  NoctisAPI :8000     │
                    └──────────────────────┘
```

### 2.2 Trusted Proxy Configuration

Cloudflare proxies requests from its published IP ranges. Configure
`TRUSTED_PROXIES` to include all Cloudflare ranges plus your internal Docker
network so the app can safely extract the real client IP from `CF-Connecting-IP`
or `X-Forwarded-For`.

```ini
# .env.prod  — Cloudflare + private Docker subnets
TRUSTED_PROXIES=\
  173.245.48.0/20,\
  103.21.244.0/22,\
  103.22.200.0/22,\
  103.31.4.0/22,\
  141.101.64.0/18,\
  108.162.192.0/18,\
  190.93.240.0/20,\
  188.114.96.0/20,\
  197.234.240.0/22,\
  198.41.128.0/17,\
  162.158.0.0/15,\
  104.16.0.0/13,\
  104.24.0.0/14,\
  172.64.0.0/13,\
  131.0.72.0/22,\
  10.0.0.0/8,\
  172.16.0.0/12,\
  192.168.0.0/16
```

> **Note:** Cloudflare publishes its current IP list at
> https://www.cloudflare.com/ips/.  Review and update `TRUSTED_PROXIES`
> whenever Cloudflare adds new ranges.

### 2.3 Keepalive Timeouts

Cloudflare terminates idle origin connections after **90 s** by default.
Configure the app so the *server* closes connections first:

```ini
KEEPALIVE_TIMEOUT=75     # server closes at 75 s → Cloudflare never hits its 90 s limit
REQUEST_TIMEOUT=30       # individual request wall-clock limit
```

### 2.4 Public Base URL

Set `PUBLIC_BASE_URL` to your canonical HTTPS domain so OpenAPI docs,
redirects, and generated absolute URLs use the public-facing name rather
than an internal address:

```ini
PUBLIC_BASE_URL=https://api.example.com
```

When `PUBLIC_BASE_URL` is unset the middleware derives it dynamically from
`X-Forwarded-Proto` + `X-Forwarded-Host` (only when the source is in
`TRUSTED_PROXIES`).

### 2.5 Complete .env.prod Snippet — Cloudflare

```ini
# ── Reverse proxy ──────────────────────────────────────────────────────────
PUBLIC_BASE_URL=https://api.example.com

TRUSTED_PROXIES=\
  173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,\
  141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,\
  197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,\
  104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,\
  10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# ── Timeouts (safe for Cloudflare origin keepalive = 90 s) ────────────────
KEEPALIVE_TIMEOUT=75
REQUEST_TIMEOUT=30

# ── Startup egress checks ──────────────────────────────────────────────────
EGRESS_REQUIRED_HOSTS=license.unkwn0wn.com:443
EGRESS_CONNECT_TIMEOUT=5

# ── Logging ────────────────────────────────────────────────────────────────
LOG_LEVEL=info
LOG_FORMAT=json
```

### 2.6 Traefik Integration (included in docker-compose.prod.yml)

The production compose file uses Traefik as the local TLS terminator
in front of NoctisAPI. Traefik handles ACME (Let's Encrypt) and passes
cleartext HTTP to the container on port 8000:

```
Cloudflare ──HTTPS──► Traefik :443 ──HTTP──► NoctisAPI :8000
```

Traefik's `idleConnTimeout` defaults to **90 s**. The same `KEEPALIVE_TIMEOUT=75`
value keeps the server below both Cloudflare's and Traefik's limits.

```yaml
# excerpt from docker-compose.prod.yml — Traefik labels on the app service
labels:
  - "traefik.http.routers.hp-api.rule=Host(`${HP_PUBLIC_HOST}`)"
  - "traefik.http.routers.hp-api.entrypoints=websecure"
  - "traefik.http.routers.hp-api.tls.certresolver=letsencrypt"
```

---

## 3. Deployment Behind F5 BIG-IP

### 3.1 Network Topology

```
                    F5 BIG-IP
                    ┌──────────────────────────────────┐
  Client ──HTTPS──► │  Virtual Server (443)            │
                    │  ┌──────────────────────────────┐ │
                    │  │  iRule / LTM Policy          │ │
                    │  │  X-Forwarded-For insert      │ │
                    │  │  X-Forwarded-Proto insert    │ │
                    │  └──────────────────────────────┘ │
                    │  SSL offload (client-side)        │
                    └──────────────────┬────────────────┘
                                       │ HTTP (cleartext)  ← SSL offload
                                       │  OR               ← SSL pass-through
                                       │ HTTPS             ← re-encrypt
                                       ▼
                    ┌──────────────────────────────────┐
                    │  Pool Member: NoctisAPI :8000    │
                    └──────────────────────────────────┘
```

### 3.2 F5 iRule — Insert Forwarding Headers

If the F5 performs SSL offload (client HTTPS → backend HTTP), create an
iRule to inject the standard forwarding headers so the app knows the
original scheme and client IP:

```tcl
when HTTP_REQUEST {
    # Insert real client IP
    HTTP::header insert X-Forwarded-For [IP::client_addr]
    # Advertise original scheme
    HTTP::header insert X-Forwarded-Proto "https"
    # Preserve original Host header
    HTTP::header insert X-Forwarded-Host [HTTP::host]
}
```

> The app reads `CF-Connecting-IP` first, then `X-Forwarded-For`.  For F5
> environments omit `CF-Connecting-IP` — the app falls through to
> `X-Forwarded-For` automatically.

### 3.3 Trusted Proxy Configuration

Set `TRUSTED_PROXIES` to your F5 self-IPs and any intermediate hop addresses
(e.g., a DMZ load-balancer VIP):

```ini
TRUSTED_PROXIES=10.10.10.0/24,192.168.100.0/28
```

Only requests arriving **from** these CIDRs will have their `X-Forwarded-For`
header trusted.  Headers from any other source are silently ignored to prevent
IP spoofing.

### 3.4 Keepalive Timeouts

F5 BIG-IP's default server-side idle timeout is **300 s**.  The app defaults
keep the server below that limit:

```ini
# The server closes idle keep-alive connections at 75 s.
# F5 won't hit its 300 s limit, eliminating 502 race conditions.
KEEPALIVE_TIMEOUT=75
REQUEST_TIMEOUT=30
```

If your F5 profile uses a custom TCP idle timeout below 75 s, lower
`KEEPALIVE_TIMEOUT` to match:

```ini
KEEPALIVE_TIMEOUT=55    # example: F5 set to 60 s, stay 5 s below
```

### 3.5 Health Monitor Configuration

Configure an F5 HTTP health monitor to poll the liveness endpoint:

| Setting | Value |
|---------|-------|
| Type | HTTP |
| Interval | 30 s |
| Timeout | 5 s |
| Send string | `GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n` |
| Receive string | `"status": "ok"` |

Use `/ready` instead of `/health` if you want the health monitor to check
database connectivity before marking the pool member UP.

### 3.6 Complete .env.prod Snippet — F5

```ini
# ── Reverse proxy ──────────────────────────────────────────────────────────
PUBLIC_BASE_URL=https://api.example.com

# F5 self-IPs + DMZ VIPs that will send X-Forwarded-For
TRUSTED_PROXIES=10.10.10.0/24,192.168.100.0/28,10.0.0.0/8

# ── Timeouts (safe below F5 default 300 s server-side idle) ───────────────
KEEPALIVE_TIMEOUT=75
REQUEST_TIMEOUT=30

# ── Startup egress checks ──────────────────────────────────────────────────
EGRESS_REQUIRED_HOSTS=license.unkwn0wn.com:443
EGRESS_CONNECT_TIMEOUT=5

# ── Logging ────────────────────────────────────────────────────────────────
LOG_LEVEL=info
LOG_FORMAT=json
LOG_SYSLOG_HOST=siem.corp.local
LOG_SYSLOG_PORT=514
LOG_SYSLOG_SOCKTYPE=udp
LOG_SYSLOG_FACILITY=local0
```

---

## 4. Outbound Proxy Configuration

NoctisAPI makes outbound HTTPS calls to:
- `license.unkwn0wn.com` — license validation and PRO feature checks
- `PRO_BACKEND_URL` — PRO feature backend

If your network requires traffic to exit via a corporate proxy, configure the
standard proxy environment variables.

### 4.1 Basic Proxy Setup

```ini
HTTP_PROXY=http://proxy.corp.local:3128
HTTPS_PROXY=http://proxy.corp.local:3128
NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,*.corp.local
```

`urllib.request` (used by the licensing client) honours these variables
automatically.  `httpx` clients (campaign and monitor) use `build_httpx_mounts()`
which translates these into its `mounts=` API with TLS verification always
enabled.

### 4.2 NO_PROXY Bypass Rules

| Token format | Example | Matches |
|-------------|---------|---------|
| Hostname | `proxy.corp.local` | Exact hostname |
| Wildcard domain | `*.corp.local` | Any subdomain of `corp.local` |
| IP address | `10.10.10.1` | Exact IP |
| CIDR (urllib only) | `10.0.0.0/8` | IP range (httpx ignores CIDR tokens) |

`localhost`, `127.0.0.1`, and `[::1]` are always bypassed regardless of
`NO_PROXY` content.

### 4.3 Authenticated Proxy

Include credentials in the proxy URL:

```ini
HTTPS_PROXY=http://user:password@proxy.corp.local:3128
```

> Store credentials in a secrets manager (Vault, AWS Secrets Manager, etc.)
> and inject at runtime — never commit them to `.env.prod`.

### 4.4 CONNECT Tunnel for HTTPS

When `HTTPS_PROXY` is set, httpx automatically issues a `CONNECT` request to
the proxy to establish a TCP tunnel before performing the TLS handshake with
the origin.  The custom CA trust store (see §5) is applied to the tunnel's
TLS connection, so corporate-CA-signed proxy certificates work without
additional configuration.

### 4.5 Egress Declaration

Declare all expected outbound hosts so startup diagnostics verify
reachability before the first request arrives:

```ini
EGRESS_REQUIRED_HOSTS=license.unkwn0wn.com:443,pro-backend.example.com:443
EGRESS_CONNECT_TIMEOUT=5
```

At startup the app will log:

```
egress: license.unkwn0wn.com OK (dns=ok tcp=ok)
egress: pro-backend.example.com OK (dns=ok tcp=ok)
[OK] outbound HTTPS — license.unkwn0wn.com → HTTP 200
[OK] proxy — reachable: http://proxy.corp.local:3128
```

---

## 5. TLS Inspection Considerations

Many enterprise environments perform TLS inspection (also called SSL
interception or MITM).  The intercepting device presents its own certificate,
signed by a corporate CA, to the application.  Without configuration the app
will reject these connections with a certificate verification error.

### 5.1 Architecture with TLS Inspection

```
  NoctisAPI container
  ┌──────────────────────────────────────────────┐
  │                                              │
  │  httpx.Client(verify=get_ssl_context())      │
  │       │                                      │
  │       │  TLS (corp-signed cert)              │
  └───────┼──────────────────────────────────────┘
          │
          ▼
  ┌───────────────────────────────┐
  │  TLS Inspection Appliance     │
  │  (Palo Alto / Zscaler / F5)  │
  │  Presents corp CA certificate │
  └───────────────┬───────────────┘
                  │  TLS (real cert)
                  ▼
          External Origin
          (license.unkwn0wn.com)
```

### 5.2 Providing the Corporate CA Bundle

**Option A — Single PEM file (recommended)**

```ini
SSL_CERT_FILE=/certs/corp-root-ca.crt
```

In Docker Compose, mount the certificate into the container:

```yaml
services:
  app:
    volumes:
      - /path/on/host/corp-root-ca.crt:/certs/corp-root-ca.crt:ro
    environment:
      - SSL_CERT_FILE=/certs/corp-root-ca.crt
```

**Option B — Certificate directory**

Drop one or more `.crt` / `.pem` / `.cer` files into a directory and point
`HP_EXTRA_CERTS_DIR` at it.  The app loads every certificate it finds on
startup:

```ini
HP_EXTRA_CERTS_DIR=/certs
```

```yaml
services:
  app:
    volumes:
      - /etc/ssl/corporate:/certs:ro   # host dir with corp CA files
```

**Option C — requests-library convention**

If you already set `REQUESTS_CA_BUNDLE` for other Python services:

```ini
REQUESTS_CA_BUNDLE=/etc/ssl/certs/corp-bundle.pem
```

Both `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` can be set simultaneously; the
app deduplicates them by resolved path.

### 5.3 CA Loading Order

The TLS context merges all configured sources:

```
1. System CA bundle  (ssl.create_default_context())
2. certifi bundle    (ships with httpx; covers public roots)
3. SSL_CERT_FILE     (env var)
4. REQUESTS_CA_BUNDLE (env var — deduped with #3 if same path)
5. HP_EXTRA_CERTS_DIR (every .crt/.pem/.cer file, sorted)
```

This is additive — internal and public roots coexist in the same context.

### 5.4 Verifying the Configuration at Startup

The startup diagnostic check reports the TLS state:

```
[OK] TLS trust store — custom CA loaded
```

or, if only system certs are in use:

```
[OK] TLS trust store — system CA only
```

A misconfigured path produces:

```
[ERROR] TLS trust store — CA bundle specified by SSL_CERT_FILE='/bad/path.pem' does not exist
```

The app will still start, but outbound HTTPS calls will fail until the
certificate is corrected.

### 5.5 TLS Inspection and the Licensing Client

The licensing client uses `get_ssl_context()` for its urllib connections, so
the same corporate CA bundle is applied.  No additional configuration is needed
beyond §5.2.

### 5.6 Important: TLS Verification Is Never Disabled

The codebase has no mechanism to disable TLS certificate verification.
`verify_mode=CERT_REQUIRED` and `check_hostname=True` are always enforced.
If an appliance presents an untrusted certificate the connection fails — this
is intentional.  Supply the signing CA as described above.

---

## 6. Startup Diagnostics

At every process startup four environment checks run automatically.  Results
are emitted as structured log lines before the first request is served.

### 6.1 Check Output

```
[OK]    DNS resolution       — resolved 'license.unkwn0wn.com'
[OK]    outbound HTTPS       — license.unkwn0wn.com → HTTP 200
[WARN]  proxy                — not configured
[OK]    TLS trust store      — system CA only
```

| Status | Meaning |
|--------|---------|
| `[OK]` | Check passed |
| `[WARN]` | Informational — proxy not configured is expected in direct-connect environments |
| `[ERROR]` | Check failed — review logs; application continues running |

### 6.2 Diagnostic Triggers

| Check | Passes when |
|-------|------------|
| DNS resolution | First `EGRESS_REQUIRED_HOSTS` host resolves; falls back to machine hostname |
| Outbound HTTPS | TLS handshake succeeds to first `:443` host in `EGRESS_REQUIRED_HOSTS` |
| Proxy configuration | `HTTPS_PROXY` / `HTTP_PROXY` set and TCP-reachable; `[WARN]` when absent |
| TLS trust store | `build_ssl_context()` completes without error |

### 6.3 Per-Host Egress Results

In addition to the four summary checks, the app logs a result for every host
in `EGRESS_REQUIRED_HOSTS`:

```
egress: license.unkwn0wn.com OK (dns=ok tcp=ok)
```

All checks share the `EGRESS_CONNECT_TIMEOUT` setting (default 5 s).

---

## 7. Environment Variable Reference

### 7.1 Reverse Proxy & Client IP

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_BASE_URL` | *(unset)* | Canonical public URL (no trailing slash). When set, overrides all dynamic URL derivation. Example: `https://api.example.com` |
| `TRUSTED_PROXIES` | RFC 1918 + loopback | Comma or newline-separated CIDR list. Only requests from these networks have their `X-Forwarded-*` headers trusted for real-IP extraction. |
| `UVICORN_FORWARDED_IPS` | `127.0.0.1,10.0.0.0/8,`<br>`172.16.0.0/12,192.168.0.0/16` | Uvicorn's own forwarded-header trust list (used for scheme detection). Set to match `TRUSTED_PROXIES`. |
| `UVICORN_HOST` | `0.0.0.0` | Bind address for the uvicorn server. |
| `PORT` | `8000` | TCP port for the public API. |

### 7.2 HTTP Server Timeouts

| Variable | Default | Notes |
|----------|---------|-------|
| `REQUEST_TIMEOUT` | `30` s | Per-request wall-clock limit. Returns `408` if exceeded before headers are sent. Set to `0` to disable. |
| `KEEPALIVE_TIMEOUT` | `75` s | Keep-Alive idle timeout. Maps to uvicorn `timeout_keep_alive`. Takes priority over `IDLE_TIMEOUT`. |
| `IDLE_TIMEOUT` | `65` s | Alias for `KEEPALIVE_TIMEOUT`; used when `KEEPALIVE_TIMEOUT` is not set. |

**Proxy safe values:**

| Upstream | Recommended `KEEPALIVE_TIMEOUT` |
|----------|--------------------------------|
| Cloudflare | ≤ 89 s (default 75 s is safe) |
| Traefik | ≤ 89 s (idleConnTimeout default 90 s) |
| F5 BIG-IP | ≤ 299 s (default 75 s is safe) |

### 7.3 Structured Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Root log level: `debug` / `info` / `warning` / `error` / `critical` |
| `LOG_FORMAT` | *(auto-detect)* | `json` — one JSON object per line (default in containers). `text` — human-readable. Auto-detected from TTY when unset. |
| `LOG_SYSLOG_HOST` | *(unset)* | Syslog/SIEM hostname. When set, a `SysLogHandler` is added alongside stdout. |
| `LOG_SYSLOG_PORT` | `514` | Syslog UDP/TCP port. |
| `LOG_SYSLOG_SOCKTYPE` | `udp` | `udp` or `tcp`. |
| `LOG_SYSLOG_FACILITY` | `user` | Syslog facility: `user` / `daemon` / `local0` – `local7`. |

### 7.4 TLS Trust Store

| Variable | Default | Description |
|----------|---------|-------------|
| `SSL_CERT_FILE` | *(unset)* | Path to a PEM CA bundle (Python/OpenSSL convention). Required in TLS inspection environments. |
| `REQUESTS_CA_BUNDLE` | *(unset)* | Alternative name for `SSL_CERT_FILE` (requests-library convention). Deduped by resolved path if identical to `SSL_CERT_FILE`. |
| `HP_EXTRA_CERTS_DIR` | `/certs` | Directory containing extra CA certificates (`.crt` / `.pem` / `.cer`). Non-existent directory is silently ignored. |

### 7.5 Outbound Proxy

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PROXY` | *(unset)* | Corporate proxy for HTTP traffic. Case-insensitive (`http_proxy` also read). |
| `HTTPS_PROXY` | *(unset)* | Corporate proxy for HTTPS traffic. Case-insensitive (`https_proxy` also read). |
| `NO_PROXY` | *(unset)* | Comma-separated bypass list. Accepts hostnames, `*.wildcard` domains, IP addresses, and CIDR ranges (CIDR handled by urllib only). `localhost`, `127.0.0.1`, `[::1]` are always bypassed. |

### 7.6 Egress Dependency Declaration

| Variable | Default | Description |
|----------|---------|-------------|
| `EGRESS_REQUIRED_HOSTS` | *(unset)* | Comma or newline-separated `host[:port]` entries. Bare hostname → DNS-only check. `host:443` → DNS + TCP connect. Both the egress checker and startup diagnostics use this list. |
| `EGRESS_CONNECT_TIMEOUT` | `5` s | Timeout per host for DNS resolution and TCP connect. Shared by egress checker and all startup diagnostic probes. |

### 7.7 Application

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `prod` | Deployment environment label, surfaced in `/version` response. |
| `APP_VERSION` | *(unset)* | Semver or image tag, surfaced in `/version`. |
| `BUILD_SHA` | *(unset)* | Git commit SHA injected by CI, surfaced in `/version`. |
| `BUILD_TIME` | *(unset)* | Build timestamp injected by CI, surfaced in `/version`. |
| `HP_DB_PATH` | `/data/honeypot.db` | SQLite database path inside the container. |
| `HP_SEED` | *(required)* | Long random secret used to seed actor identity hashing. Must remain stable across restarts. |
| `HP_PUBLIC_BASE_URL` | `http://127.0.0.1:8080` | Internal address of the public API (used by the admin panel to fetch the OpenAPI catalogue). Use the Docker service name: `http://app:8000`. |

### 7.8 Licensing / PRO

| Variable | Default | Description |
|----------|---------|-------------|
| `LICENSE_KEY` | *(required for PRO)* | License key (`sk_live_...`). |
| `PRO_BACKEND_URL` | *(required for PRO)* | URL of the PRO feature backend. |
| `LICENSING_URL` | `https://license.unkwn0wn.com` | License validation endpoint. |
| `LICENSING_PINNED_PUBLIC_KEY_PATH` | `/app/app/licensing_server_public_key.pem` | Path to the licensing server's pinned public key. |
| `HP_LICENSE_REPORT_TO_SERVER` | `0` | Set to `1` to post license telemetry back to the backend. |

### 7.9 Data Retention

| Variable | Default | Description |
|----------|---------|-------------|
| `HP_RETENTION_ENABLE` | `1` | Set to `0` to disable automatic pruning. |
| `HP_RETENTION_EVENTS_DAYS` | `30` | Retain raw event records for N days. |
| `HP_RETENTION_SESSIONS_DAYS` | `30` | Retain session records for N days. |
| `HP_RETENTION_STEPS_DAYS` | `30` | Retain step records for N days. |
| `HP_RETENTION_CHECKS_DAYS` | `14` | Retain check records for N days. |
| `HP_RETENTION_TOKENS_DAYS` | `90` | Retain canary token records for N days. |
| `HP_RETENTION_JOBS_DAYS` | `30` | Retain background job records for N days. |

---

## Appendix A — Minimal .env.prod for Enterprise

The following combines all enterprise-relevant settings with safe defaults
for a Cloudflare + corporate-proxy + TLS-inspection environment.

```ini
# ── General ────────────────────────────────────────────────────────────────
APP_ENV=prod
APP_VERSION=0.1.0
LOG_LEVEL=info
LOG_FORMAT=json
LOG_SYSLOG_HOST=siem.corp.local
LOG_SYSLOG_PORT=514
LOG_SYSLOG_SOCKTYPE=udp
LOG_SYSLOG_FACILITY=local0

# ── Database ───────────────────────────────────────────────────────────────
HP_DB_PATH=/data/honeypot.db
DATABASE_URL=sqlite+pysqlite:////data/honeypot.db

# ── Public endpoints ───────────────────────────────────────────────────────
PUBLIC_BASE_URL=https://api.example.com
HP_PUBLIC_BASE_URL=http://app:8000
HP_PUBLIC_HOST=api.example.com
HP_ADMIN_HOST=admin.internal.example.com
ACME_EMAIL=ops@example.com

# ── Reverse proxy trust (Cloudflare + Docker) ─────────────────────────────
TRUSTED_PROXIES=\
  173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,\
  141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,\
  197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,\
  104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,\
  10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# ── HTTP server timeouts ───────────────────────────────────────────────────
REQUEST_TIMEOUT=30
KEEPALIVE_TIMEOUT=75

# ── Corporate egress proxy ─────────────────────────────────────────────────
HTTPS_PROXY=http://proxy.corp.local:3128
HTTP_PROXY=http://proxy.corp.local:3128
NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,*.corp.local

# ── TLS trust store (corporate CA for TLS inspection) ─────────────────────
SSL_CERT_FILE=/certs/corp-root-ca.crt
HP_EXTRA_CERTS_DIR=/certs

# ── Egress checks ─────────────────────────────────────────────────────────
EGRESS_REQUIRED_HOSTS=license.unkwn0wn.com:443,pro-backend.example.com:443
EGRESS_CONNECT_TIMEOUT=5

# ── Application secrets ────────────────────────────────────────────────────
HP_SEED=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
LICENSE_KEY=sk_live_...
PRO_BACKEND_URL=https://pro-backend.example.com
LICENSING_URL=https://license.unkwn0wn.com

# ── Data retention ─────────────────────────────────────────────────────────
HP_RETENTION_ENABLE=1
HP_RETENTION_EVENTS_DAYS=30
HP_RETENTION_SESSIONS_DAYS=30
```

---

## Appendix B — Health Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Liveness: returns `{"status":"ok"}` if process is alive. Always 200. Use for process restart probes. |
| `/ready` | GET | None | Readiness: checks database connectivity. Returns 200 `{"status":"ok"}` or 503 `{"status":"degraded"}`. Use for load-balancer and Kubernetes readiness probes. |
| `/version` | GET | None | Build metadata: `{"version":"...","env":"prod","build_sha":"...","build_time":"..."}`. |

F5 health monitor: poll `/health` every 30 s with a 5 s timeout.
Kubernetes: use `/ready` for readiness and `/health` for liveness.

---

*Last updated: see `BUILD_SHA` / `BUILD_TIME` in `/version` response.*
