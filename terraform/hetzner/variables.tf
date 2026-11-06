variable "deployment_id" {
  description = <<-EOT
    The SAME stable id as compose/secrets/deployment-manifest.json's
    `deployment_id` (NOC-031) -- never generated here, always passed in
    from that manifest. This is the one field every other system
    (future CLI, Control Center) reconciles against, so it's also the
    resource-naming/tagging key below: re-running `terraform apply` with
    the same deployment_id against the same state must plan no changes,
    not create a duplicate server (idempotency).
  EOT
  type        = string
  validation {
    condition     = length(var.deployment_id) > 0
    error_message = "deployment_id must not be empty."
  }
}

variable "allow_destroy" {
  description = "NOC-037: explicit teardown gate. Keep false for normal plans; the controlled Deployer teardown is the only caller that may set true."
  type        = bool
  default     = false
}

variable "customer_id" {
  description = "Operator-assigned customer identifier, for tagging/cost-tracking. Empty for a self-hosted (non-managed) deployment."
  type        = string
  default     = ""
}

variable "plan" {
  description = "Free-form commercial plan label. Mirrors deployment-manifest.json's `plan` field (NOC-031) -- NOT NOC-043's future billing status state machine, just a label passed through to scripts/init_deployment.py."
  type        = string
  default     = ""
}

variable "region" {
  description = "Hetzner Cloud location (e.g. nbg1, fsn1, hel1, ash). Mirrors deployment-manifest.json's `region` field."
  type        = string
  default     = "nbg1"
  validation {
    condition     = contains(["nbg1", "fsn1", "hel1", "ash", "hil", "sin"], var.region)
    error_message = "region must be a known Hetzner Cloud location (nbg1, fsn1, hel1, ash, hil, sin)."
  }
}

variable "sizing" {
  description = "Hetzner Cloud server type (e.g. cx22, cx32). Mirrors deployment-manifest.json's `sizing` field."
  type        = string
  default     = "cx22"
}

variable "image" {
  description = "Base OS image. Must match what documentation/ops/vps/DEPLOY.md's manual steps assume (Ubuntu 22.04+) until NOC-033's cloud-init is built against something else."
  type        = string
  default     = "ubuntu-22.04"
}

variable "ssh_public_key" {
  description = "The public key (contents, not a path) that will have SSH access. Required -- there is no password-auth fallback."
  type        = string
  validation {
    condition     = length(var.ssh_public_key) > 0
    error_message = "ssh_public_key must not be empty."
  }
}

variable "ssh_allowed_cidrs" {
  description = <<-EOT
    CIDR blocks allowed to reach SSH (22/tcp). Required, with NO default
    -- "puertos minimos" means SSH is never open to the world by this
    module's own fallback. Pass your own admin IP(s)/VPN range.
  EOT
  type        = list(string)
  validation {
    condition     = length(var.ssh_allowed_cidrs) > 0
    error_message = "ssh_allowed_cidrs must list at least one CIDR -- SSH is never left open to 0.0.0.0/0 by default."
  }
}

variable "volume_size_gb" {
  description = "Extra persistent block storage beyond the server's included disk, in GB. 0 (default) skips creating a volume entirely -- most sizing tiers' included disk is enough for a single-tenant honeypot instance."
  type        = number
  default     = 0
  validation {
    condition     = var.volume_size_gb == 0 || var.volume_size_gb >= 10
    error_message = "volume_size_gb must be 0 (no volume) or at least 10 (Hetzner's own minimum)."
  }
}

variable "extra_labels" {
  description = "Additional Hetzner labels merged on top of the required customer_id/deployment_id/managed_by ones below. Never put a secret value in a label -- labels are visible in the Hetzner console/API to anyone with read access to the project."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# NOC-033: cloud-init bootstrap. Set enable_cloud_init = false to provision
# a bare VM only (NOC-032's original behavior) and configure it by hand.
#
# KNOWN LIMITATION (see README.md): the variables below marked sensitive
# end up embedded in the server's rendered user_data, which Terraform
# records in its OWN state file. This module still uses local state
# (see README) -- protecting that state is explicitly NOC-038's job, not
# solved here. Until then, treat local .tfstate as sensitive material.
# ---------------------------------------------------------------------------

variable "enable_cloud_init" {
  description = "NOC-033: render and attach the Managed-instance cloud-init bootstrap as this server's user_data. false provisions a bare VM only (NOC-032's original behavior)."
  type        = bool
  default     = true
}

variable "admin_ssh_user" {
  description = "Non-root sudo user cloud-init creates, with ssh_public_key for key-only access. Root SSH login and password auth are disabled (see templates/cloud-init.yaml.tftpl)."
  type        = string
  default     = "noctisops"
}

variable "hp_image" {
  description = "Image repository (without a tag) -- mirrors .env.prod.example's HP_IMAGE."
  type        = string
  default     = "ghcr.io/0x-unkwn0wn/noctisapi-pro"
}

variable "app_version" {
  description = "Exact image tag -- becomes .env.prod's MANAGED_APP_VERSION, which has no default and breaks loudly if unset (see compose/docker-compose.managed.yml). Never \"latest\"."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_cloud_init || (var.app_version != "" && var.app_version != "latest")
    error_message = "app_version is required when enable_cloud_init = true, and must not be \"latest\"."
  }
}

variable "hp_public_host" {
  description = "Public decoy API domain -- .env.prod's HP_PUBLIC_HOST."
  type        = string
  default     = ""
}

variable "hp_admin_host" {
  description = "Admin console domain, reached only through the Cloudflare Tunnel -- .env.prod's HP_ADMIN_HOST."
  type        = string
  default     = ""
}

variable "acme_email" {
  description = "Let's Encrypt contact email -- .env.prod's ACME_EMAIL."
  type        = string
  default     = ""
}

variable "cloudflare_tunnel_token" {
  description = <<-EOT
    The token from the Cloudflare Zero Trust dashboard's tunnel for this
    instance (DEPLOY.md Sec8 -- still a manual, external step; automating
    that dashboard side is NOC-034's job). Sensitive: ends up in
    .env.prod's CLOUDFLARE_TUNNEL_TOKEN on the server, and -- see the
    KNOWN LIMITATION above -- in this module's local Terraform state.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}

variable "git_repo_url" {
  description = "HTTPS clone URL (no embedded credential) for the repo cloud-init checks out to /opt/hp-app."
  type        = string
  default     = "https://github.com/noctisapi/NoctisAPI-pro.git"
}

variable "git_deploy_token" {
  description = <<-EOT
    A token with read access to clone the (private) repo -- e.g. a
    fine-grained GitHub PAT or deploy-key-as-token. Sensitive, same
    local-state caveat as cloudflare_tunnel_token above. Written to a
    file on the server and read back by path in runcmd, never
    interpolated into a logged command string (see the template).
  EOT
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = !var.enable_cloud_init || var.git_deploy_token != ""
    error_message = "git_deploy_token is required when enable_cloud_init = true -- cloud-init needs it to clone the repo."
  }
}

variable "ghcr_token" {
  description = "Optional: a GHCR read token, only needed if hp_image's tag isn't public. Empty (default) skips the docker login step entirely."
  type        = string
  default     = ""
  sensitive   = true
}
