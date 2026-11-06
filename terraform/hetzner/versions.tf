terraform {
  required_version = ">= 1.5.0"

  required_providers {
    hcloud = {
      source = "hetznercloud/hcloud"
      # NOC-032: exact pin, not a `~>` range -- "plan reproducible" is an
      # explicit acceptance criterion, and `~> 1.46` (two segments) would
      # still float across every 1.x release. Bump this deliberately,
      # with its own commit, never implicitly.
      version = "1.70.2"
    }
  }
}

# No `provider "hcloud" {}` block with a literal token here on purpose --
# the provider reads HCLOUD_TOKEN from the environment on its own. Never
# pass a token as a .tf variable with a default, and never commit a
# tfvars file containing one (see README.md).
provider "hcloud" {}
