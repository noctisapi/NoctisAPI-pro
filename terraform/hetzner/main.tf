locals {
  # NOC-032: applied to every taggable resource below -- "estado y
  # costes por cliente identificables" means every resource must carry
  # enough to filter/cost-allocate by customer in the Hetzner console/API
  # without cross-referencing anything else.
  labels = merge(
    {
      managed_by    = "noctisapi-deployer"
      deployment_id = var.deployment_id
      customer_id   = var.customer_id
    },
    var.extra_labels,
  )

  # Stable, human-legible resource name -- deployment_id is already the
  # unique/reconciliation key (used in labels above); this is just what
  # shows up in the Hetzner console.
  name_prefix = "noctisapi-${substr(var.deployment_id, 0, 12)}"

  # NOC-033: rendered only when enable_cloud_init -- see variables.tf's
  # "KNOWN LIMITATION" note on why every value here (sensitive or not)
  # ends up in this module's local Terraform state regardless.
  cloud_init = var.enable_cloud_init ? templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    admin_ssh_user          = var.admin_ssh_user
    ssh_public_key          = var.ssh_public_key
    git_repo_url            = var.git_repo_url
    git_deploy_token        = var.git_deploy_token
    ghcr_token              = var.ghcr_token
    hp_image                = var.hp_image
    app_version             = var.app_version
    hp_public_host          = var.hp_public_host
    hp_admin_host           = var.hp_admin_host
    acme_email              = var.acme_email
    cloudflare_tunnel_token = var.cloudflare_tunnel_token
    deployment_id           = var.deployment_id
    customer_id             = var.customer_id
    region                  = var.region
    sizing                  = var.sizing
    plan                    = var.plan
  }) : null
}

resource "hcloud_ssh_key" "this" {
  name       = "${local.name_prefix}-key"
  public_key = var.ssh_public_key
  labels     = local.labels
}

resource "hcloud_firewall" "this" {
  name   = "${local.name_prefix}-fw"
  labels = local.labels

  # "Puertos minimos": only what docker-compose.prod.yml itself publishes
  # (Traefik's 80/443 -- see compose/docker-compose.prod.yml) plus SSH,
  # restricted to var.ssh_allowed_cidrs. Nothing else -- the admin panel
  # (9001) is never published by that compose file either, so there is
  # nothing to open for it here; it's reached only through the Cloudflare
  # Tunnel sidecar (NOC-016), which makes no inbound connection at all.
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.ssh_allowed_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "this" {
  name         = local.name_prefix
  server_type  = var.sizing
  image        = var.image
  location     = var.region
  ssh_keys     = [hcloud_ssh_key.this.id]
  firewall_ids = [hcloud_firewall.this.id]
  user_data    = local.cloud_init
  labels       = local.labels

  # "Destroy no borra sin controles": a bare `terraform destroy` against
  # this module refuses, on purpose -- tearing an instance down for real
  # is NOC-037's job (backup-first, gated on deployment-manifest.json's
  # own status state machine being DECOMMISSIONING, NOC-031), not
  # something this module should ever do as a side effect of an
  # unrelated `terraform destroy -auto-approve` run elsewhere. Removing
  # this protection is itself the deliberate, auditable step NOC-037's
  # controlled teardown procedure performs.
  lifecycle {
    prevent_destroy = !var.allow_destroy
  }
}

resource "hcloud_volume" "this" {
  count    = var.volume_size_gb > 0 ? 1 : 0
  name     = "${local.name_prefix}-data"
  size     = var.volume_size_gb
  location = var.region
  labels   = local.labels
  # Same destroy protection as the server -- this is where the actual
  # honeypot database would live if a customer outgrows the included disk.
  lifecycle {
    prevent_destroy = !var.allow_destroy
  }
}

resource "hcloud_volume_attachment" "this" {
  count     = var.volume_size_gb > 0 ? 1 : 0
  volume_id = hcloud_volume.this[0].id
  server_id = hcloud_server.this.id
  automount = false # NOC-033 (cloud-init) owns filesystem creation/mounting, not Terraform
}
