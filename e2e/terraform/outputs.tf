output "iap_audience" {
  description = "Set this as IAP_AUDIENCE. The backend-service resource path the gem verifies the `aud` claim against — not a URL, not a client id."
  value       = local.iap_audience
}

output "url" {
  description = "Public HTTPS entrypoint. Everything on this host is behind IAP."
  value       = "https://${local.hostname}/"
}

output "login_url" {
  description = "Sign-in entrypoint. cru-iap README: link /?login=true — bare / loops."
  value       = "https://${local.hostname}/?login=true"
}

output "logout_url" {
  description = "Sign-out target that makes IAP clear its federated login cookie."
  value       = "https://${local.hostname}/?gcp-iap-mode=CLEAR_LOGIN_COOKIE"
}

output "lb_ip" {
  description = "Global anycast IP the hostname's A record points at."
  value       = google_compute_global_address.lb.address
}

output "cloud_run_uri" {
  description = "Raw *.run.app URL. Ingress is INTERNAL_LOAD_BALANCER, so this must NOT be reachable — curl it to prove IAP can't be bypassed."
  value       = google_cloud_run_v2_service.app.uri
}

output "backend_service_name" {
  description = "IAP backend service, for `gcloud compute backend-services describe`."
  value       = google_compute_backend_service.iap.name
}

output "ssl_certificate_name" {
  description = "Google-managed cert. `gcloud compute ssl-certificates describe <name> --global` to watch PROVISIONING -> ACTIVE."
  value       = google_compute_managed_ssl_certificate.lb.name
}

######################################
# Workforce federation (null unless enable_workforce_federation = true)
######################################

output "workforce_pool_name" {
  description = "Full workforce pool resource name, for principal:// bindings."
  value       = local.wif ? google_iam_workforce_pool.this[0].name : null
}

output "workforce_principal_prefix" {
  description = <<-EOT
    Prefix for iap_members entries. In OIDC mode google.subject is the Okta
    `sub` (an opaque user id like 00u2sr49f3tpmox7b0h8), so the binding is
    <prefix>/subject/<okta sub> — NOT the email. In SAML mode google.subject is
    the NameID, which Cru sets to the email, so it is <prefix>/subject/<url-encoded email>.
  EOT
  value       = local.wif ? "principal://iam.googleapis.com/${google_iam_workforce_pool.this[0].name}" : null
}

output "wif_acs_url" {
  description = "SAML ACS / recipient / destination URL to configure on the Okta app (SAML mode only)."
  value       = local.wif ? local.wif_acs_url : null
}

output "wif_audience" {
  description = "SAML audience (SP entity id) to configure on the Okta app (SAML mode only)."
  value       = local.wif ? local.wif_audience : null
}

output "wif_oauth_client_generated_id" {
  description = "API-generated OAuth client id. Copy into var.wif_oauth_client_generated_id and re-apply — phase 2 of the two-phase apply."
  value       = local.wif ? google_iam_oauth_client.iap[0].client_id : null
}

output "wif_oidc_redirect_uri" {
  description = "Redirect URI to register on the Okta OIDC app once the OAuth client id is known."
  value       = local.wif && var.wif_oauth_client_generated_id != "" ? "https://iap.googleapis.com/v1/oauth/clientIds/${var.wif_oauth_client_generated_id}:handleRedirect" : null
}
