# Managed deployment secrets (NOC-023/NOC-025)

Per-deployment state the Managed compose override
(`docker-compose.managed.yml`) uses. Gitignored except this README — a
single shared repo must never carry one client's secret or identity into
another's deployment.

Generate both files with one command (idempotent — safe to re-run after
every deploy/upgrade, see `python scripts/init_deployment.py --help`):

```bash
python scripts/init_deployment.py --public-host <HP_PUBLIC_HOST> --admin-host <HP_ADMIN_HOST>
```

| File | Secret? | Used by | Content |
|---|---|---|---|
| `hp_seed.txt` | **Yes** | `migrate`, `app`, `admin` | The same value you'd otherwise set as `HP_SEED` in `.env.prod` — a long random string, unique to this instance. **Never changes once set** (see CLAUDE.md: changing `HP_SEED` on an existing deployment breaks actor/session identity continuity for every record it's ever made). `init_deployment.py` enforces this: it only ever generates the file if it's missing, never overwrites an existing one, unless you explicitly pass `--force-regenerate-seed`. |
| `deployment-manifest.json` | No | Nobody (operator reference only) | A random, non-secret `deployment_id`, `created_at`, and which domains this instance is configured for. Safe to log, display in a future Control Center, or paste into a support ticket — it never holds a credential, which is exactly why it's kept in its own file instead of next to `hp_seed.txt`'s actual value. |

Override `hp_seed.txt`'s path with `HP_SEED_SECRET_FILE` (defaults to
`./secrets/hp_seed.txt`, relative to the compose file) if you keep it
somewhere else, e.g. a path your provisioning tooling writes to directly.

## Rotation

- **`hp_seed.txt`** — don't, on a live instance. See above. If a seed is
  ever genuinely compromised, the only real remedy is standing up a new
  instance with a new seed and migrating the customer to it — not
  swapping the value in place.
- **`CLOUDFLARE_TUNNEL_TOKEN`** (plain env var in `.env.prod`, not a file
  here — see `docker-compose.managed.yml`'s own note on why) — routine to
  rotate: revoke the old token and issue a new one in the Cloudflare Zero
  Trust dashboard, update `.env.prod`, `docker compose up -d` to recreate
  `cloudflared`. No continuity impact — it's a connection credential, not
  an identity one.
- **`CF_ACCESS_AUD`** — not a secret (it's an application identifier, not
  a credential), but changes if the Access Application itself is ever
  recreated: update the env var and redeploy the same way.
