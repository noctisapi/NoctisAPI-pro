locals {
  name_prefix = "noctisapi-${substr(var.deployment_id, 0, 12)}"
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "this" {
  account_id = var.account_id
  name       = "${local.name_prefix}-tunnel"
  config_src = "cloudflare" # ingress managed remotely by the _config resource below, not a local YAML on the connector

  lifecycle {
    prevent_destroy = true
  }
}

# The connector token cloudflared authenticates with (compose/docker-compose.prod.yml's
# cloudflared service, TUNNEL_TOKEN env var -- CLOUDFLARE_TUNNEL_TOKEN in .env.prod).
# Not the tunnel's `tunnel_secret` -- that's a different, lower-level value this
# module never sets or reads.
data "cloudflare_zero_trust_tunnel_cloudflared_token" "this" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.this.id
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "this" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.this.id

  config = {
    ingress = [
      {
        hostname = var.admin_hostname
        service  = "http://admin:9001"
      },
      {
        # Required catch-all: cloudflared itself rejects a config whose
        # last ingress rule still has a hostname. Anything not matching
        # admin_hostname above gets a plain 404, never routed anywhere.
        service = "http_status:404"
      },
    ]
  }
}

resource "cloudflare_dns_record" "admin" {
  count   = var.admin_zone_id != "" ? 1 : 0
  zone_id = var.admin_zone_id
  name    = var.admin_hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.this.id}.cfargotunnel.com"
  ttl     = 1 # "automatic" -- required by Cloudflare when proxied
  proxied = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_dns_record" "public" {
  count   = var.public_zone_id != "" && var.vps_ipv4 != "" ? 1 : 0
  zone_id = var.public_zone_id
  name    = var.public_hostname
  type    = "A"
  content = var.vps_ipv4
  ttl     = 300
  proxied = false # see variables.tf's vps_ipv4 docstring -- ACME HTTP-01 needs this unproxied

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_zero_trust_access_policy" "this" {
  count      = var.enable_access_application ? 1 : 0
  account_id = var.account_id
  name       = "${local.name_prefix}-allow-operators"
  decision   = "allow"

  include = [
    for email in var.access_allowed_emails : {
      email = { email = email }
    }
  ]
}

resource "cloudflare_zero_trust_access_application" "this" {
  count                = var.enable_access_application ? 1 : 0
  account_id           = var.account_id
  name                 = "${local.name_prefix}-admin-console"
  domain               = var.admin_hostname
  type                 = "self_hosted"
  session_duration     = var.access_session_duration
  app_launcher_visible = false

  policies = [
    {
      id = cloudflare_zero_trust_access_policy.this[0].id
    }
  ]
}
