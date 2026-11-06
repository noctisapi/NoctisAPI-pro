terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      # NOC-034: exact pin, not a `~>` range -- same "plan reproducible"
      # rationale as terraform/hetzner/versions.tf. Confirmed against the
      # real provider binary (`terraform providers schema -json`), not
      # assumed from docs -- the Cloudflare provider's resource names and
      # nested-attribute shapes have changed across major versions.
      version = "5.28.1"
    }
  }
}

# No `provider "cloudflare" {}` api_token argument here on purpose -- the
# provider reads CLOUDFLARE_API_TOKEN from the environment on its own.
# Never pass it as a .tf variable with a default, never commit a tfvars
# file containing one (see README.md).
provider "cloudflare" {}
