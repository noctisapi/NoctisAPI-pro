variable "account_id" {
  description = "Cloudflare account id that owns the tunnel and the Zero Trust Access application."
  type        = string
  validation {
    condition     = length(var.account_id) > 0
    error_message = "account_id must not be empty."
  }
}

variable "deployment_id" {
  description = <<-EOT
    The SAME stable id as compose/secrets/deployment-manifest.json's
    `deployment_id` (NOC-031) and terraform/hetzner's own variable of the
    same name -- baked into every resource's name here too, for the same
    reconciliation/idempotency reason.
  EOT
  type        = string
  validation {
    condition     = length(var.deployment_id) > 0
    error_message = "deployment_id must not be empty."
  }
}

variable "admin_hostname" {
  description = "Full FQDN the admin console is reached at (e.g. admin.example.com) -- mirrors .env.prod's HP_ADMIN_HOST. The tunnel routes this hostname to http://admin:9001."
  type        = string
  validation {
    condition     = length(var.admin_hostname) > 0
    error_message = "admin_hostname must not be empty."
  }
}

variable "admin_zone_id" {
  description = <<-EOT
    Cloudflare zone id that owns admin_hostname's domain. Required to
    actually create the CNAME record routing admin_hostname to this
    tunnel -- leave empty (default) to skip DNS entirely and create it
    yourself (or point an existing record at
    "<tunnel_id>.cfargotunnel.com", see the tunnel_id output). This is
    the "DNS publico solo cuando se controla la zona" criterion: this
    module never guesses or assumes it owns a zone it wasn't explicitly
    given the id for.
  EOT
  type        = string
  default     = ""
}

variable "public_hostname" {
  description = "Full FQDN the public decoy API is reached at (e.g. api.example.com) -- mirrors .env.prod's HP_PUBLIC_HOST. Only used if public_zone_id and vps_ipv4 are also set."
  type        = string
  default     = ""
}

variable "public_zone_id" {
  description = "Cloudflare zone id that owns public_hostname's domain. Same opt-in-only rule as admin_zone_id -- empty (default) skips creating this record."
  type        = string
  default     = ""
}

variable "vps_ipv4" {
  description = <<-EOT
    The VPS's public IPv4 (terraform/hetzner's server_ipv4 output). Only
    used if public_zone_id is also set. Created UNPROXIED (proxied =
    false) -- Traefik's ACME HTTP-01 challenge (scripts/verify_domain.py's
    own documented requirement, NOC-024) needs this domain to resolve
    directly to the VPS, with no CDN/proxy in front of it. Do not change
    this to proxied = true.
  EOT
  type        = string
  default     = ""
}

variable "enable_access_application" {
  description = "Create a Zero Trust Access Application + Policy gating admin_hostname. false leaves the panel's own per-user login (NOC-018) as the only gate, matching .env.prod.example's documented 'optional but recommended' framing for CF_ACCESS_*."
  type        = bool
  default     = true
}

variable "access_allowed_emails" {
  description = <<-EOT
    Email addresses allowed through the Access policy -- the ONLY
    include condition this module writes (no SAML/OIDC/geo/etc; add
    those by hand in the dashboard if you need them). Required when
    enable_access_application = true. This is what makes "un cliente no
    obtiene acceso a consola de otro" true in practice: each
    deployment's policy lists only that customer's own operators, never
    a shared "everyone" rule.
  EOT
  type        = list(string)
  default     = []
  validation {
    condition     = !var.enable_access_application || length(var.access_allowed_emails) > 0
    error_message = "access_allowed_emails must list at least one address when enable_access_application = true."
  }
}

variable "access_session_duration" {
  description = "How long an Access session lasts before re-authentication."
  type        = string
  default     = "24h"
}
