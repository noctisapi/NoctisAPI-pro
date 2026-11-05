# Managed deployment secrets (NOC-023)

Files the Managed compose override (`docker-compose.managed.yml`) mounts
as Docker secrets. Never committed — this directory is gitignored except
this README.

| File | Used by | Content |
|---|---|---|
| `hp_seed.txt` | `migrate`, `app`, `admin` | The same value you'd otherwise set as `HP_SEED` in `.env.prod` — a long random string. Generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`. Never changes once set (see CLAUDE.md: changing `HP_SEED` on an existing deployment breaks actor/session identity continuity). |

Override the path with `HP_SEED_SECRET_FILE` (defaults to
`./secrets/hp_seed.txt`, relative to the compose file) if you keep it
somewhere else, e.g. a path your provisioning tooling writes to directly.
