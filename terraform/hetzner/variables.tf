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

variable "customer_id" {
  description = "Operator-assigned customer identifier, for tagging/cost-tracking. Empty for a self-hosted (non-managed) deployment."
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
