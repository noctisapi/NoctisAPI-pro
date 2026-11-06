# Terraform module: Hetzner Cloud VPS (NOC-032)

Creates one customer's isolated VPS + firewall (+ optional extra volume)
on Hetzner Cloud -- the first piece of the Noctis Deployer (ADR 0001:
"Automatizado por el Deployer (Terraform + cloud-init, NOC-032/033)").
This module only provisions infrastructure; it does **not** install or
configure anything on the server (that's NOC-033's cloud-init job) and
it does **not** tear anything down automatically (that's NOC-037's
controlled teardown job).

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
  -var 'ssh_allowed_cidrs=["203.0.113.4/32"]'
```

Prefer a `.tfvars` file over long `-var` flags for repeated runs --
just never commit one that contains `ssh_public_key` or anything else
sensitive-looking (this repo's `.gitignore` does not special-case
`terraform/hetzner/*.tfvars`; add your own locally, or keep it outside
the repo entirely).

## What this does and doesn't cover

| In scope (NOC-032) | Out of scope (later Issues) |
|---|---|
| The VM, its firewall, labels/tags, optional extra block storage, and the outputs (IP, ids) a later step needs | Installing Docker, cloning the repo, running `docker compose up` -- cloud-init (NOC-033) |
| Pinned, reproducible `terraform plan` | DNS records, Cloudflare Tunnel/Access provisioning (NOC-034) |
| Minimal firewall: 22 (restricted to `ssh_allowed_cidrs`), 80, 443 only -- matches exactly what `compose/docker-compose.prod.yml` itself publishes | A CLI wrapping any of this (NOC-035) |
| `prevent_destroy` on the server/volume (see below) | Actually tearing an instance down (NOC-037) |
| Local Terraform state | Protecting that state and any secrets involved (NOC-038) -- **this module currently uses local state, which is NOT yet safe for real multi-instance use; treat this as a reference implementation until NOC-038 lands a real backend.** |

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
