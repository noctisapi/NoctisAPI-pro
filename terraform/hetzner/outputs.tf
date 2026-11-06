output "server_id" {
  value       = hcloud_server.this.id
  description = "Hetzner Cloud server id."
}

output "server_ipv4" {
  value       = hcloud_server.this.ipv4_address
  description = "Public IPv4 -- this is the address DNS (NOC-024's verify_domain.py, --expected-ip) and the ACME HTTP-01 challenge need to point at."
}

output "server_ipv6" {
  value       = hcloud_server.this.ipv6_address
  description = "Public IPv6, if the resolver/DNS setup ever wants it. Not required by anything today."
}

output "firewall_id" {
  value       = hcloud_firewall.this.id
  description = "Hetzner Cloud firewall id."
}

output "volume_id" {
  value       = var.volume_size_gb > 0 ? hcloud_volume.this[0].id : null
  description = "Hetzner Cloud volume id, or null when volume_size_gb = 0 (no extra volume)."
}

output "labels" {
  value       = local.labels
  description = "The label set applied to every resource this module creates -- useful for verifying 'costes por cliente identificables' without opening the console."
}

output "ssh_connection_hint" {
  value       = var.enable_cloud_init ? "ssh ${var.admin_ssh_user}@${hcloud_server.this.ipv4_address}" : "ssh root@${hcloud_server.this.ipv4_address}"
  description = "NOC-033: root SSH login is disabled once cloud-init's hardening applies -- use the created admin_ssh_user instead. Bootstrap itself (ops/vps/bootstrap-managed.sh) takes a few minutes after the server first boots; check /var/log/noctisapi-bootstrap.log and /opt/hp-app/.bootstrap-status over this connection to see whether it finished."
}
