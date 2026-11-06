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

## Not wired to terraform/hetzner automatically

This module and `terraform/hetzner/` are independent, standalone
modules, applied as two separate steps (in either order, but the
Hetzner one needs this one's `tunnel_token` output, and this one's
`cloudflare_zero_trust_tunnel_cloudflared_config` ingress always points
at `http://admin:9001` regardless of which VPS is actually behind the
tunnel -- there is no cross-module reference). A single root module
composing both is a reasonable thing for a future CLI (NOC-035) to do;
out of scope here.

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

## Known limitation: secrets in local Terraform state

Same caveat as `terraform/hetzner/`: this module uses local state, and
`tunnel_token` -- while redacted from `plan`/`apply` console output
(marked sensitive) -- is recorded in cleartext in `terraform.tfstate`.
Do not use this for a real multi-customer rollout before NOC-038 lands
a real backend.
