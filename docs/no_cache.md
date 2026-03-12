# Anti-Cache Protection — NoctisAPI Honeypot

## Why this matters

A CDN or shared proxy that caches and replays a honeypot response breaks the deception:

- Attackers receive stale data that does not adapt to their session stage.
- The actor profiling middleware never runs — no IP recorded, no score updated.
- Rate-limiting and session tracking are bypassed entirely.

`NoCacheMiddleware` prevents this by injecting the correct headers on every response from the application layer.

---

## What the middleware does

For every HTTP response on a non-static path the middleware:

| Action | Detail |
|---|---|
| Injects `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0, private` |
| Injects `Pragma` | `no-cache` (HTTP/1.0 back-compat) |
| Injects `Expires` | `0` (proxy back-compat) |
| Strips `ETag` | Prevents clients from sending `If-None-Match` conditional requests |
| Strips `Last-Modified` | Prevents clients from sending `If-Modified-Since` conditional requests |
| Converts `304 Not Modified` | Rewritten to `200 OK` with an empty body so no cached copy is used |

This applies to **all** honeypot endpoints including `/docs`, `/redoc`, and `/openapi.json`, which are part of the decoy API surface.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `HP_NO_CACHE_ENABLED` | `true` | Set to `false` / `0` / `no` to disable (dev only) |
| `HP_NO_CACHE_SKIP_STATIC` | `true` | Skip `/static/*` paths (CSS/JS assets are safe to cache) |

---

## Limits — what the middleware cannot do

`NoCacheMiddleware` operates at the **application layer**.  It cannot override caching behaviour imposed by a reverse proxy or CDN *after* the response leaves the application.

### Traefik (recommended)

No action needed.  Traefik forwards the application `Cache-Control` header unchanged by default.  Confirm with:

```bash
curl -sI https://<your-api-host>/health | grep -i cache
```

### Nginx (if used instead of Traefik)

Add to the `location` block that proxies to the app:

```nginx
proxy_hide_header Cache-Control;
proxy_hide_header ETag;
add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0, private" always;
add_header Pragma "no-cache" always;
add_header Expires "0" always;
```

### Cloudflare

If you place the honeypot behind Cloudflare, configure a **Cache Rule** or **Page Rule** to bypass caching for the entire honeypot domain:

1. **Cache Rules** (recommended) → Match `hostname eq your-api-host` → Cache status: **Bypass**.
2. Or use the legacy Page Rule: `your-api-host/*` → Cache Level: **Bypass**.

Without this, Cloudflare may still cache `200` responses for paths it considers safe (e.g. `/health`) even when `no-store` is set, depending on your plan and configuration.

### AWS CloudFront

Add a **Cache Policy** with `Cache-Control` forwarded as-is (`CachingDisabled` policy), or set a **Response Headers Policy** that adds `no-store`.

---

## Execution order

The final middleware execution order (outermost → innermost) is:

```
RequestTimeoutMiddleware
  └── NoCacheMiddleware           ← injects headers on the way out
        └── ReverseProxyMiddleware
              └── log_all_requests (http decorator)
                    └── CORSMiddleware
                          └── route handlers
```

`NoCacheMiddleware` wraps `ReverseProxyMiddleware` so it sees the final response after all route logic, and injects the no-cache headers on the outbound path.

---

## Verifying the headers

```bash
curl -sI https://<your-api-host>/api/v1/users | grep -iE "cache|pragma|etag|expires"
```

Expected output:

```
cache-control: no-store, no-cache, must-revalidate, max-age=0, private
pragma: no-cache
expires: 0
```

`ETag` and `Last-Modified` should be absent.
