# NoctisAPI PRO

`Honey_app` is the current PRO build of the NoctisAPI honeypot platform.
It ships the attacker-facing API, the internal admin panel, the licensing
layer, and the current modular runtime used to shape the exposed API surface.

## Important DNS Requirement Before Deploying

Before you deploy, create a DNS `A` record for the public domain you will use
and point it to the public IP address of the machine where the honeypot will
run.

Example:

- `api.example.com -> 203.0.113.10`

This is required for `HP_PUBLIC_HOST`, Traefik host-based routing, and the
Let's Encrypt HTTP challenge to work correctly. If the domain does not resolve
to the server first, the public API will not be reachable over TLS.

## What This Repo Contains

- The public honeypot API in `app/honeypot_public.py`
- The internal admin panel in `app/panel_mvp.py`
- The current catalog-driven modular API runtime in `app/catalog/`,
  `app/runtime/`, `app/runtime_provider.py`, and `app/response_factory/`
- Docker deployment assets in `compose/docker-compose.prod.yml`
- PRO licensing helpers in `honey_licensing/`

## How the Current Modular API Works

This repo no longer relies only on per-route overrides. The current runtime is
built in layers:

1. A validated static endpoint catalog defines the available deception surface.
   The built-in base templates are:
   - `ecommerce`
   - `corporate_saas`

2. Optional extensions can be added on top of the base template:
   - `file_server_ext`
   - `webhooks_ext`

3. Instance configuration is persisted in the database and adapted from legacy
   settings by `LegacyConfigAdapter`.

4. `RuntimeConfigProvider` builds the `EffectiveRuntimeConfig` from:
   - the immutable catalog
   - the persisted instance configuration
   - legacy endpoint overrides still stored in the database

5. `EndpointResolver` maps each incoming `(method, path)` request to the
   effective endpoint definition that should handle it.

6. Response generation is currently hybrid:
   - migrated endpoints can be served by `ResponseFactory`
   - non-migrated endpoints still fall back to the legacy handlers
   - telemetry, scoring, sessions, and actor tracking continue to work in both
     paths

7. The admin panel exposes the runtime state and controls from
   `/dashboard/api-modular`, including:
   - active template and extensions
   - effective endpoint catalog
   - per-endpoint overrides
   - resolution preview
   - analytics
   - PRO-only mutation and rule controls when the license enables
     `API_MUTATION`

### Progressive ResponseFactory Rollout

The factory is intentionally partial, not global. At the time of this README,
the migrated batches are:

- Middleware-level interception:
  - `recon_env`
  - `recon_config`
  - `recon_openapi`
- Handler-assisted interception:
  - `auth_register`
  - `users_list`
  - `users_get`
  - `users_update`
  - `orders_list`
  - `orders_get`
  - `orders_create`

Everything else continues to use the legacy route handlers until it is migrated.

## Feature Gating

The modular runtime itself is always present, but some controls remain
license-gated:

- Core runtime building, endpoint resolution, telemetry, and the hybrid
  response path are part of the base product
- Cases, campaigns, replay, and other investigation workflows are PRO features
- Advanced modular controls such as rule-based mutation are available only when
  the `API_MUTATION` feature is enabled by the license

## Production Deployment

### Option A: install script

The packaged VPS installer lives at:

```bash
ops/vps/install.sh
```

It downloads or reuses the image, writes `.env.prod`, writes a production
compose file if needed, and starts the stack.

### Option B: deploy from this repo

```bash
cp .env.prod.example .env.prod
```

Set at least:

- `HP_PUBLIC_HOST`
- `ACME_EMAIL`
- `HP_SEED`
- `HP_PANEL_TOKEN`
- `APP_VERSION` / `HP_IMAGE` if you are not using the defaults

Then start the production stack:

```bash
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

### What the production stack runs

`compose/docker-compose.prod.yml` starts four services:

- `migrate`: runs Alembic and GeoIP setup
- `app`: public API on port `8000`
- `admin`: internal panel on port `9001`
- `traefik`: public reverse proxy and TLS termination on `80/443`

The public host is routed through Traefik with:

- `Host(${HP_PUBLIC_HOST}) -> app:8000`

The admin panel is intentionally not public. It is published only on:

- `127.0.0.1:9001`

## Accessing the Admin Panel

Create an SSH tunnel from your workstation:

```bash
ssh -L 9001:127.0.0.1:9001 user@your-server
```

Then open:

```text
http://localhost:9001
```

The panel login token is `HP_PANEL_TOKEN`.

## Local Development

```bash
docker compose -f compose/docker-compose.dev.yml up -d
```

Development URLs:

- Public API: `http://127.0.0.1:8000`
- Admin panel: `http://127.0.0.1:9001`

Useful commands:

```bash
make db-upgrade
docker compose -f compose/docker-compose.dev.yml logs -f
docker compose -f compose/docker-compose.dev.yml down
```

## Operational Notes

- Keep `HP_SEED` stable after first deployment. Changing it breaks actor
  continuity across sessions and events.
- The public API keeps its decoy `/health` surface. Real health and readiness
  checks live behind the internal services.
- The admin panel can inspect the public OpenAPI document and compare it with
  the effective modular runtime state.

## How Stages and Behavior Labels Work

Two different classifications are shown in the product:

- `Stage` is the actor's cumulative threat level.
- `Automated` / `Targeted` is a per-request behavior classification.

### Stage (0-8)

The numeric `Stage` is derived from the actor's cumulative score, not from a
single request. Higher-signal actions add more score, and the score is then
mapped to a fixed 0-8 ladder.

Examples of score-producing events include:

- public recon such as `/docs`, `/openapi.json`, `/.env`, and `/config.json`
- authentication activity such as login, MFA, token issuance, and token usage
- access to internal/admin surfaces
- backup and secret access
- vault, cloud metadata, and console escalation paths

Current score-to-stage mapping:

| Score range | Stage label |
| --- | --- |
| `< 10` | `0-Idle` |
| `10-19` | `1-Curious` |
| `20-31` | `2-Exploring` |
| `32-47` | `3-Probing` |
| `48-67` | `4-Targeting` |
| `68-91` | `5-Aggressive` |
| `92-119` | `6-Exploiting` |
| `120-154` | `7-Persistent` |
| `>= 155` | `8-Critical` |

### Automated vs Targeted

`Automated` / `Targeted` is computed by a deterministic heuristic classifier.
It does not use ML, external services, or randomness.

The classifier combines eight normalized signals:

- Automated-leaning signals:
  - request frequency
  - path entropy or random-looking URLs
  - minimal or tool-like headers
  - known scanner or script-like user agents
  - highly uniform request timing
- Targeted-leaning signals:
  - logical endpoint progression
  - multi-step or stateful behavior
  - adaptation after errors or blocking responses

Internally, each signal produces a value in `[0, 1]`, weighted signals are
combined into a final score, and the result is classified as:

- `targeted` when the final score is `>= 0.5`
- `automated` otherwise

The stored event payload also includes:

- `attack_confidence`: confidence in the automated vs targeted decision
- `attack_signals`: the individual signal scores used to reach that decision

### Important distinction

This `Stage` ladder is different from the per-request attack phase stored as
`attack_phase` (`recon`, `access`, `collection`, `exfiltration`, `impact`).
In short:

- `Stage` answers: "How far has this actor progressed overall?"
- `attack_phase` answers: "What kind of activity is this request performing?"

## License

This repo contains the PRO build and its licensing layer. Feature availability
depends on the signed license loaded by the instance.
