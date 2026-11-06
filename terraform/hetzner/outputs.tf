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
