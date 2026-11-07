# Terraform module: Hetzner Cloud VPS + cloud-init bootstrap (NOC-032/033)

Creates one customer's isolated VPS + firewall (+ optional extra volume)
on Hetzner Cloud, and (unless `enable_cloud_init = false`) boots it
straight into a running Managed instance via cloud-init -- the first
two pieces of the Noctis Deployer (ADR 0001: "Automatizado por el
Deployer (Terraform + cloud-init, NOC-032/033)"). It does **not** tear
anything down automatically (NOC-037's job), and does **not** automate
the Cloudflare Tunnel/Access dashboard side or DNS (NOC-034's job) --
those stay manual, external prerequisites you complete before `apply`.

## Usage

```bash
export HCLOUD_TOKEN=...   # never pass this as a .tf variable or commit it

terraform -chdir=terraform/hetzner init
terraform -chdir=terraform/hetzner plan \
  -var "deployment_id=<the SAME value as deployment-manifest.json's deployment_id, NOC-031>" \
  -var "customer_id=acme-01" \
  -var "region=nbg1" \
  -var "sizing=cx22" \
  -var 'ssh_public_key=ssh-ed25519 AAAA...' \
  -var 'ssh_allowed_cidrs=["203.0.113.4/32"]' \
  -var "app_version=1.5.0" \
  -var "hp_public_host=api.example.com" \
  -var "hp_admin_host=admin.example.com" \
  -var "acme_email=ops@example.com" \
  -var "cloudflare_tunnel_token=<from the Cloudflare Zero Trust dashboard, DEPLOY.md Sec8>" \
  -var "git_deploy_token=<a token with read access to clone this repo>"
```

Pass `-var "enable_cloud_init=false"` to provision the bare VM only
(NOC-032's original behavior, no `user_data`) and configure it by hand
per `documentation/ops/vps/DEPLOY.md` instead.

Prefer a `.tfvars` file over long `-var` flags for repeated runs --
just never commit one that contains `ssh_public_key`, `cloudflare_tunnel_token`,
`git_deploy_token`, `ghcr_token`, or anything else sensitive-looking
(this repo's `.gitignore` already excludes every `*.tfvars` file).

## What this does and doesn't cover

| In scope (NOC-032/033) | Out of scope (later Issues) |
|---|---|
| The VM, its firewall, labels/tags, optional extra block storage, and the outputs (IP, ids) a later step needs | DNS records, Cloudflare Tunnel/Access **dashboard-side** provisioning (NOC-034) -- you still create the tunnel by hand and pass its token in |
| cloud-init bootstrap: Docker, a hardened non-root admin user, SSH hardening, cloning the repo, generating `.env.prod`, running `scripts/init_deployment.py`, `docker compose up`, installing the systemd unit, and a first local health check (`ops/vps/bootstrap-managed.sh`) | Creating the first admin-panel account (`scripts/panel_user.py`) -- deliberately left manual; see "Why the first admin account isn't automated" below |
| Pinned, reproducible `terraform plan` | Teardown, reconciliation and state protection beyond the private CLI (NOC-037/038) |
| Minimal firewall: 22 (restricted to `ssh_allowed_cidrs`), 80, 443 only -- matches exactly what `compose/docker-compose.prod.yml` itself publishes | Actually tearing an instance down (NOC-037) |
| `prevent_destroy` on the server/volume (see below) | — |
| Runtime-configured encrypted remote state with locking (NOC-038) | — |

## NOC-038: remote state and secrets

The private Deployer now initializes this module with a tenant-scoped,
encrypted S3-compatible backend and DynamoDB locking. The bucket, key and
role are supplied at runtime; they are never committed to this module. The
CLI rejects local state for real operations. See
`documentation/NOC-038-ESTADO-SECRETS.md` for the runner contract and the
remaining account-level recovery tests.

## "Credenciales no aparecen en logs" (NOC-033)

cloud-init logs every `runcmd` command's full stdout -- and the command
line itself -- to `/var/log/cloud-init-output.log`. `templates/cloud-init.yaml.tftpl`
only ever puts a secret into a `write_files` entry's *content* (writing
a file isn't a logged command) and references it in `runcmd` by file
*path* (e.g. `$(cat /root/.git-deploy-token)`), never by interpolating
the raw value into a command string. `ops/vps/bootstrap-managed.sh`
follows the same rule for `GHCR_TOKEN`. Verified by actually rendering
the template (`terraform console` + `nonsensitive()`) and reading the
output, not just by code review.

## Why the first admin-panel account isn't automated

`scripts/panel_user.py create-user`/`reset-password` either prompts
interactively for a password or prints a one-time reset *link* to
stdout -- either way, a real credential with nowhere safe to land
non-interactively (no email integration exists yet). Automating it
would put a credential directly into `cloud-init-output.log`, which is
exactly what the Issue's own "credenciales no aparecen en logs"
criterion rules out. Creating the first operator account stays the one
manual step after bootstrap (DEPLOY.md Sec8), over the hardened admin
user cloud-init creates:

```bash
ssh <admin_ssh_user>@<server_ipv4>   # see the ssh_connection_hint output
sudo docker compose --env-file .env.prod -f compose/docker-compose.prod.yml -f compose/docker-compose.managed.yml \
  exec admin python scripts/panel_user.py create-user --username ops
```

## Diagnosing a failed bootstrap

SSH in (as `admin_ssh_user` -- root login is disabled by the hardening
above) and check, in order: `cloud-init status` (did cloud-init itself
finish, and without error), `/var/log/cloud-init-output.log` (every
command's real stdout/stderr, in order), `/var/log/noctisapi-bootstrap.log`
(`ops/vps/bootstrap-managed.sh`'s own narrower log), and
`/opt/hp-app/.bootstrap-status` (`ok`, or `failed: <reason>` -- written
as the very last or very first thing that goes wrong, so it's always
present one way or the other once `bootstrap-managed.sh` has started).

## "Destroy no borra sin controles"

The server and volume resources both set
`lifecycle { prevent_destroy = true }`. A bare `terraform destroy` (or
an `apply` that would implicitly replace either resource) **fails on
purpose**:

```
Error: Instance cannot be destroyed
  Resource hcloud_server.this has lifecycle.prevent_destroy set...
```

Tearing an instance down for real is a deliberate, auditable sequence
(NOC-037's job, not this module's): back up first (reusing
`backup_sqlite.sh`/`scripts/dr_drill.py`'s proven operations), set
`deployment-manifest.json`'s status to `decommissioning`
(`scripts/deployment_manifest.py set-status decommissioning`, NOC-031 --
which itself only allows that transition from `active`/`degraded`/
`suspended`), *then* remove `prevent_destroy` (or `terraform state rm`
+ destroy out-of-band) and run `terraform destroy`.

## Reconciliation / idempotency

`deployment_id` is the same stable id `deployment-manifest.json` already
uses (NOC-031) -- it's baked into every resource's name and labels.
Re-running `terraform plan`/`apply` with the same `deployment_id` against
the same state produces an empty plan (no changes), not a duplicate
server; this is what "ID estable para reconciliación e idempotencia"
means in practice here.
