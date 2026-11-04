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
      middlewares:
        - hp-monitor-headers
        - hp-monitor-ratelimit
    hp-internal:
      rule: "PathPrefix(\`/\`)"
      entryPoints:
        - webinternal
      service: hp-api
      priority: 120
      middlewares:
        - hp-monitor-headers
        - hp-monitor-ratelimit
  middlewares:
    hp-public-ratelimit:
      rateLimit:
        average: ${HP_PUBLIC_RATELIMIT_AVG}
        burst: ${HP_PUBLIC_RATELIMIT_BURST}
    hp-monitor-headers:
      headers:
        customRequestHeaders:
          X-Internal-Monitor: "1"
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
