######################################
# IAP
#
# Adapted from cru-terraform-modules gcp/cloudrun/app/iap.tf. Same resource
# shapes, minus the parts that only make sense against Cru's shared ALB.
######################################

locals {
  # The gem's IAP_AUDIENCE. generated_id is the numeric backend-service id, not
  # the name — `/projects/<number>/global/backendServices/<numeric id>`.
  iap_audience = "/projects/${var.project_number}/global/backendServices/${google_compute_backend_service.iap.generated_id}"
}

# Provision IAP's service agent (service-<project#>@gcp-sa-iap). Enabling the
# API alone does NOT create it, and IAP-on-Cloud-Run fails every single request
# with "The IAP service account is not provisioned" until it exists
# (cloud.google.com/iap/docs/enabling-cloud-run). google-beta: no GA equivalent.
resource "google_project_service_identity" "iap" {
  provider = google-beta
  project  = var.project_id
  service  = "iap.googleapis.com"

  depends_on = [google_project_service.enabled["iap.googleapis.com"]]
}

# The IAP backend service. No health check (serverless NEGs don't take one), no
# Cloud Armor policy — IAP is the gate.
resource "google_compute_backend_service" "iap" {
  project               = var.project_id
  name                  = "${local.name}-backend-iap"
  description           = local.description
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  backend {
    group           = google_compute_region_network_endpoint_group.app.id
    capacity_scaler = 1.0
  }

  iap {
    enabled = true
  }

  depends_on = [
    google_project_service.enabled["iap.googleapis.com"],
    google_project_service_identity.iap,
  ]
}

# Who may pass through IAP.
resource "google_iap_web_backend_service_iam_member" "members" {
  for_each            = var.iap_members
  project             = var.project_id
  web_backend_service = google_compute_backend_service.iap.name
  role                = "roles/iap.httpsResourceAccessor"
  member              = each.value
}

# Federate IAP to the workforce pool. Without this, IAP authenticates with
# Google identities and the assertion JWT carries a normal `email` claim plus a
# useless `sub` (`accounts.google.com:<numeric id>`). With it, `sub` becomes
# `principal://iam.googleapis.com/.../subject/<urlencoded email>` — the shape
# the gem's workforce path parses. See cru-iap README, gotcha 1.
resource "google_iap_settings" "wif" {
  count = local.wif ? 1 : 0
  name  = "projects/${var.project_number}/iap_web/compute/services/${google_compute_backend_service.iap.name}"

  access_settings {
    identity_sources = ["WORKFORCE_IDENTITY_FEDERATION"]
    workforce_identity_settings {
      workforce_pools = [google_iam_workforce_pool.this[0].name]
      oauth2 {
        client_id     = google_iam_oauth_client.iap[0].client_id
        client_secret = google_iam_oauth_client_credential.iap[0].client_secret
      }
    }
  }
}
