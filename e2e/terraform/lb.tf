######################################
# External HTTPS load balancer
#
# Global external Application Load Balancer (EXTERNAL_MANAGED). Cru's real apps
# share one ALB owned by another project and splice themselves onto its URL map
# with an internal provider; this stack owns a whole standalone LB instead, so
# it stays inside the sandbox and destroys cleanly.
#
# Global (not regional) because IAP + a classic Google-managed certificate is
# the well-trodden combination; a regional ALB would drag in Certificate
# Manager. Global external ALBs are PREMIUM network tier only — there is no
# Standard-tier option to save money on.
######################################

resource "google_compute_global_address" "lb" {
  project     = var.project_id
  name        = "${local.name}-lb"
  description = local.description

  depends_on = [google_project_service.enabled["compute.googleapis.com"]]
}

# A record must exist and resolve BEFORE the Google-managed certificate can
# finish provisioning — Google validates domain ownership by checking that the
# name points at this LB. Zone is pre-existing and NOT managed here.
resource "google_dns_record_set" "a" {
  project      = var.project_id
  managed_zone = data.google_dns_managed_zone.this.name
  name         = "${local.hostname}."
  type         = "A"
  ttl          = 60
  rrdatas      = [google_compute_global_address.lb.address]
}

# Serverless NEG.
#
# References the Cloud Run service by its plan-time-known NAME rather than by
# resource attribute, on purpose. The values are identical so there is no plan
# diff, but dropping the resource edge breaks the cycle
#   cloud run env (IAP_AUDIENCE) -> IAP backend service -> NEG -> cloud run
# This mirrors the same trick, for the same reason, in cru-terraform-modules
# gcp/cloudrun/app/compute.tf.
resource "google_compute_region_network_endpoint_group" "app" {
  project               = var.project_id
  name                  = "${local.name}-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = local.name
  }

  depends_on = [google_project_service.enabled["compute.googleapis.com"]]
}

# Classic Google-managed cert. Provisioning is asynchronous and takes roughly
# 10-30 minutes after the A record resolves; until then the LB serves a TLS
# error. `gcloud compute ssl-certificates describe cru-iap-e2e-cert` shows the
# domain status (PROVISIONING -> ACTIVE, or FAILED_NOT_VISIBLE if DNS is wrong).
resource "google_compute_managed_ssl_certificate" "lb" {
  project     = var.project_id
  name        = "${local.name}-cert"
  description = local.description

  managed {
    domains = [local.hostname]
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [google_dns_record_set.a]
}

resource "google_compute_url_map" "https" {
  project         = var.project_id
  name            = "${local.name}-https"
  description     = local.description
  default_service = google_compute_backend_service.iap.id
}

resource "google_compute_target_https_proxy" "lb" {
  project          = var.project_id
  name             = "${local.name}-https-proxy"
  description      = local.description
  url_map          = google_compute_url_map.https.id
  ssl_certificates = [google_compute_managed_ssl_certificate.lb.id]
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${local.name}-https"
  description           = local.description
  target                = google_compute_target_https_proxy.lb.id
  ip_address            = google_compute_global_address.lb.id
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

######################################
# Port 80 -> 443 redirect
#
# Free: GCP bills forwarding rules as a bundle of the first five, so the second
# rule costs nothing. Worth having — it keeps a plain `curl http://<host>` from
# looking like the stack is broken, and gives Google's certificate validation a
# port-80 path if it wants one.
######################################

resource "google_compute_url_map" "http_redirect" {
  project     = var.project_id
  name        = "${local.name}-http-redirect"
  description = "${local.description} (http->https redirect)"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  project     = var.project_id
  name        = "${local.name}-http-proxy"
  description = local.description
  url_map     = google_compute_url_map.http_redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  project               = var.project_id
  name                  = "${local.name}-http"
  description           = local.description
  target                = google_compute_target_http_proxy.redirect.id
  ip_address            = google_compute_global_address.lb.id
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
