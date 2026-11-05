# Managed deployment secrets (NOC-023/NOC-025/NOC-026)

Per-deployment state the Managed compose override
(`docker-compose.managed.yml`) uses, and what `backup_sqlite.sh` /
`restore_backup.sh` read regardless of whether you're on Managed or
self-hosted. Gitignored except this README — a single shared repo must
never carry one client's secret or identity into another's deployment.

Generate all three files with one command (idempotent — safe to re-run
after every deploy/upgrade, see `python scripts/init_deployment.py --help`):

```bash
python scripts/init_deployment.py --public-host <HP_PUBLIC_HOST> --admin-host <HP_ADMIN_HOST>
```

| File | Secret? | Used by | Content |
|---|---|---|---|
| `hp_seed.txt` | **Yes** | `migrate`, `app`, `admin` | The same value you'd otherwise set as `HP_SEED` in `.env.prod` — a long random string, unique to this instance. **Never changes once set** (see CLAUDE.md: changing `HP_SEED` on an existing deployment breaks actor/session identity continuity for every record it's ever made). `init_deployment.py` enforces this: it only ever generates the file if it's missing, never overwrites an existing one, unless you explicitly pass `--force-regenerate-seed`. |
| `backup_encryption_key.txt` | **Yes** | `backup_sqlite.sh` / `restore_backup.sh` (via `scripts/backup_tool.py`) | A dedicated Fernet key encrypting the daily SQLite + `/var/lib/myapp` backups (NOC-026) — deliberately a *different* secret from `hp_seed.txt`, so a leaked backup key can't also be used to derive actor/session identity, and a leaked `HP_SEED` doesn't automatically make every off-site backup readable. **Never changes once set** either — every backup taken with the old key becomes permanently undecryptable with a new one. Same never-overwrite-unless-forced behavior, via `--force-regenerate-backup-key`. |
| `deployment-manifest.json` | No | Nobody (operator reference only) | A random, non-secret `deployment_id`, `created_at`, and which domains this instance is configured for. Safe to log, display in a future Control Center, or paste into a support ticket — it never holds a credential, which is exactly why it's kept in its own file instead of next to the actual secret values above. |

Override `hp_seed.txt`'s path with `HP_SEED_SECRET_FILE` (defaults to
`./secrets/hp_seed.txt`, relative to the compose file) if you keep it
somewhere else, e.g. a path your provisioning tooling writes to directly.
`backup_encryption_key.txt`'s path is fixed (`backup_sqlite.sh` looks for
it at this exact location) since it's read by a plain shell script, not
through `docker-compose.managed.yml`'s secret-mounting.

## Rotation

- **`hp_seed.txt`** — don't, on a live instance. See above. If a seed is
  ever genuinely compromised, the only real remedy is standing up a new
  instance with a new seed and migrating the customer to it — not
  swapping the value in place.
- **`backup_encryption_key.txt`** — don't, either, unless you've confirmed
  you no longer need any backup taken before the change (or have
  separately decrypted and re-encrypted your backup archive with the new
  key — `scripts/backup_tool.py` has no bulk re-encrypt mode, only
  one-file-at-a-time `encrypt`/`decrypt`).
- **`CLOUDFLARE_TUNNEL_TOKEN`** (plain env var in `.env.prod`, not a file
  here — see `docker-compose.managed.yml`'s own note on why) — routine to
  rotate: revoke the old token and issue a new one in the Cloudflare Zero
  Trust dashboard, update `.env.prod`, `docker compose up -d` to recreate
  `cloudflared`. No continuity impact — it's a connection credential, not
  an identity one.
- **`CF_ACCESS_AUD`** — not a secret (it's an application identifier, not
  a credential), but changes if the Access Application itself is ever
  recreated: update the env var and redeploy the same way.
