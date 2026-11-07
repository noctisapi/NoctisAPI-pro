# Terraform module: Cloudflare Tunnel, Access, DNS (NOC-034)

Creates one customer's console perimeter on Cloudflare: a Tunnel routing
`admin_hostname` to `http://admin:9001`, optionally a Zero Trust Access
Application + Policy gating it (allowlisted emails only), and optionally
the DNS records -- but **only** for a zone you explicitly hand this
module the id for ("DNS público solo cuando se controla la zona"). This
replaces DEPLOY.md §8's manual Zero Trust dashboard clicks; creating the
Access policy's identity providers (Google/GitHub/OTP/etc.) in the
dashboard is still a one-time, account-wide, out-of-scope prerequisite.

## Usage

```bash
export CLOUDFLARE_API_TOKEN=...   # never pass this as a .tf variable or commit it

terraform -chdir=terraform/cloudflare init
terraform -chdir=terraform/cloudflare apply \
  -var "account_id=<your Cloudflare account id>" \
  -var "deployment_id=<the SAME value as deployment-manifest.json's deployment_id, NOC-031>" \
  -var "admin_hostname=admin.example.com" \
  -var 'access_allowed_emails=["ops@example.com"]'

# capture this for terraform/hetzner's cloudflare_tunnel_token variable:
terraform -chdir=terraform/cloudflare output -raw tunnel_token
# and this for .env.prod's CF_ACCESS_AUD:
terraform -chdir=terraform/cloudflare output -raw access_application_aud
```

The API token needs, at minimum: Account.Cloudflare Tunnel:Edit,
Account.Access: Apps and Policies:Edit, and (only if you also set
`admin_zone_id`/`public_zone_id`) Zone.DNS:Edit for those specific
zones -- scope it to exactly these, not a global token.

To also create DNS records (optional -- skip entirely if you manage
DNS elsewhere, or don't control the zone in this Cloudflare account):

```bash
  -var "admin_zone_id=<zone id owning admin_hostname's domain>" \
  -var "public_zone_id=<zone id owning public_hostname's domain>" \
  -var "public_hostname=api.example.com" \
  -var "vps_ipv4=<terraform/hetzner's server_ipv4 output>"
```

## Operator CLI (NOC-035)

The modules remain independently addressed, but the private operator CLI now
composes them in the safe order: Cloudflare Tunnel/Access first, Hetzner VPS
and cloud-init second, then the optional public DNS record once the VPS IPv4
exists. The same `deployment_id` and per-deployment cache/manifest directory
are used on retries, while Terraform state remains in the remote backend, so
a failed retry reconciles instead of creating a second instance.

```bash
export HCLOUD_TOKEN=...                 # never pass as a CLI argument
export CLOUDFLARE_API_TOKEN=...         # never pass as a CLI argument
export GIT_DEPLOY_TOKEN=...             # read by Terraform from the environment
python scripts/deployer.py deploy \
  --customer-id acme-01 --region nbg1 --sizing cx22 \
  --public-host api.example.com --admin-host admin.example.com \
  --acme-email ops@example.com --app-version 1.5.0 \
  --ssh-public-key-file ~/.ssh/id_ed25519.pub \
  --ssh-private-key-file ~/.ssh/id_ed25519 \
  --ssh-allowed-cidr 203.0.113.4/32 \
  --cloudflare-account-id <account-id> \
  --access-email ops@example.com
```

Use `--dry-run` to validate both Terraform modules without contacting the
providers. `status` and `verify` read the saved state and use the SSH key to
inspect the managed VPS. New host keys are accepted only when the explicit
`--accept-new-host-key` flag is supplied.

The CLI never prints secret values or puts them in subprocess arguments.
Terraform state is remote, encrypted and locked when invoked by the real
Deployer; provider-free `--dry-run` and tests deliberately use no backend.

## Manual module usage

This module and `terraform/hetzner/` are independent, standalone modules.
The CLI composes them without turning them into one Terraform root module:
the Hetzner apply consumes this module's sensitive `tunnel_token`, and a
second Cloudflare apply adds the public DNS record after Hetzner returns the
VPS IPv4. The tunnel ingress still points at `http://admin:9001` inside the
managed stack, as required by the deployment architecture.

## "Un cliente no obtiene acceso a consola de otro"

The Access policy's `include` list is built entirely from
`access_allowed_emails` -- never an `everyone` condition, never shared
across deployments. Every resource is also named/labeled with
`deployment_id`, same convention as `terraform/hetzner/`.

## "No se sobreescriben zonas de clientes"

`admin_zone_id`/`public_zone_id` default to empty, which skips creating
the corresponding DNS record entirely -- this module never assumes it
owns a zone it wasn't explicitly handed the id for. `public`'s record is
created **unproxied** (`proxied = false`) on purpose: Traefik's ACME
HTTP-01 challenge (`scripts/verify_domain.py`, NOC-024) needs
`HP_PUBLIC_HOST` to resolve directly to the VPS, with no CDN/proxy in
front of it.

## "Recursos tienen IDs persistidos y teardown seguro"

Every resource's id is exposed as an output. The tunnel and both DNS
records set `lifecycle { prevent_destroy = true }` -- same pattern and
rationale as `terraform/hetzner/`'s own README. **One real limitation,
confirmed by actually running `terraform plan`, not assumed from docs:**
`cloudflare_zero_trust_tunnel_cloudflared_config` has **no destroy
operation in the provider at all** -- Terraform warns
`"This resource cannot be destroyed from Terraform. If you create this
resource, it will be present in the API until manually deleted."`
Tearing one down for real means deleting the parent tunnel (which
cascades) via the Cloudflare dashboard/API, not a targeted
`terraform destroy` of the config alone -- NOC-037's controlled teardown
procedure needs to account for this when it's built.

## NOC-038: remote state and secrets

The private Deployer now initializes this module with a tenant-scoped,
encrypted S3-compatible backend and DynamoDB locking. The sensitive
`tunnel_token` is captured in memory and passed only through the protected
execution environment. See
`documentation/NOC-038-ESTADO-SECRETS.md`; real-provider recovery and IAM
tests remain intentionally deferred to the final infrastructure gate.
