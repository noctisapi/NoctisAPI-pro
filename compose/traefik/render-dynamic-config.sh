#!/bin/sh
# Renders compose/traefik's File Provider dynamic config from env vars already
# resolved by docker-compose (HP_PUBLIC_HOST, HP_PUBLIC_RATELIMIT_AVG/BURST).
# Runs once at stack startup, mirroring the existing one-shot `migrate` service
# pattern -- Traefik only ever reads the rendered file, never this script.
set -eu

: "${HP_PUBLIC_HOST:?HP_PUBLIC_HOST must be set}"
: "${HP_PUBLIC_RATELIMIT_AVG:?HP_PUBLIC_RATELIMIT_AVG must be set}"
: "${HP_PUBLIC_RATELIMIT_BURST:?HP_PUBLIC_RATELIMIT_BURST must be set}"

OUT="/etc/traefik/dynamic/dynamic.yml"

cat > "$OUT" <<EOF
http:
  routers:
    hp-api:
      rule: "Host(\`${HP_PUBLIC_HOST}\`)"
      entryPoints:
        - websecure
      service: hp-api
      tls:
        certResolver: letsencrypt
      middlewares:
        - hp-public-ratelimit
    hp-health:
      rule: "Host(\`${HP_PUBLIC_HOST}\`) && (Path(\`/health\`) || Path(\`/status\`))"
      entryPoints:
        - websecure
      service: hp-api
      priority: 100
      tls:
        certResolver: letsencrypt
      # Public, unauthenticated router reachable by anyone -- NOC-012: never
      # tag this traffic with the internal-monitor header.
      middlewares:
        - hp-health-ratelimit
    hp-internal:
      rule: "PathPrefix(\`/\`)"
      entryPoints:
        - webinternal
      service: hp-api
      priority: 120
      # No customRequestHeaders middleware here on purpose: Traefik's
      # customRequestHeaders *overwrites* a same-named header rather than only
      # setting it when absent (verified against a real Traefik v3.7.16 --
      # see the corrective-branch report), so injecting a static literal here
      # would destroy the real HP_MONITOR_SECRET value admin's monitor client
      # already sends (app.honeypot_monitor._base_headers()) before it ever
      # reaches app._is_monitor()'s secrets.compare_digest check. Trust comes
      # from network isolation (webinternal is loopback + net-internal only,
      # NOC-011) plus that real secret passing through untouched -- not from
      # anything Traefik adds.
      middlewares:
        - hp-monitor-ratelimit
  middlewares:
    hp-public-ratelimit:
      rateLimit:
        average: ${HP_PUBLIC_RATELIMIT_AVG}
        burst: ${HP_PUBLIC_RATELIMIT_BURST}
    hp-health-ratelimit:
      rateLimit:
        average: 30
        burst: 60
    hp-monitor-ratelimit:
      rateLimit:
        average: 30
        burst: 60
  services:
    hp-api:
      loadBalancer:
        servers:
          - url: "http://app:8000"
EOF

echo "traefik-config: rendered $OUT for host=${HP_PUBLIC_HOST}"
