output "tunnel_id" {
  value       = cloudflare_zero_trust_tunnel_cloudflared.this.id
  description = "Persisted id for reconciliation/teardown. Also the target for a manually-created CNAME if admin_zone_id was left empty: point it at '<this value>.cfargotunnel.com'."
}

output "tunnel_token" {
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.this.token
  sensitive   = true
  description = "Feeds .env.prod's CLOUDFLARE_TUNNEL_TOKEN -- e.g. terraform/hetzner's cloudflare_tunnel_token variable. Sensitive: apply this module first, capture this output, then pass it into the hetzner module's apply. Not wired together automatically (no root module composes both yet -- see README)."
}

output "admin_dns_record_id" {
  value       = var.admin_zone_id != "" ? cloudflare_dns_record.admin[0].id : null
  description = "Persisted id for teardown, or null when admin_zone_id was left empty (no record created)."
}

output "public_dns_record_id" {
  value       = (var.public_zone_id != "" && var.vps_ipv4 != "") ? cloudflare_dns_record.public[0].id : null
  description = "Persisted id for teardown, or null when public_zone_id/vps_ipv4 were left empty (no record created)."
}

output "access_application_id" {
  value       = var.enable_access_application ? cloudflare_zero_trust_access_application.this[0].id : null
  description = "Persisted id for teardown, or null when enable_access_application = false."
}

output "access_application_aud" {
  value       = var.enable_access_application ? cloudflare_zero_trust_access_application.this[0].aud : null
  description = "Feeds .env.prod's CF_ACCESS_AUD (app/cloudflare_access.py, NOC-017). Not sensitive -- it's an application identifier, not a credential (see .env.prod.example's own CF_ACCESS_AUD comment)."
}

output "access_policy_id" {
  value       = var.enable_access_application ? cloudflare_zero_trust_access_policy.this[0].id : null
  description = "Persisted id for teardown, or null when enable_access_application = false."
}
