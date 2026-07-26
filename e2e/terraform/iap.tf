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

# Federate IAP to a workforce pool (created or borrowed — see local.wif_borrow).
#
# What changes in the assertion JWT: `sub` goes from
# `accounts.google.com:<opaque id>` to `sts.google.com:<opaque STS token>`.
# BOTH are opaque and neither is an identity. The identity is the `email` claim
# in both modes — which under WIF exists ONLY if the pool provider maps
# google.email. The principal:// URI does appear, but in a nested
# `workforce_identity.iam_principal` claim the gem deliberately ignores.
# See cru-iap README, gotchas 1-3.
resource "google_iap_settings" "wif" {
  count = local.wif ? 1 : 0
  name  = "projects/${var.project_number}/iap_web/compute/services/${google_compute_backend_service.iap.name}"

  # Custom access-denied page. This is the AUTHORIZATION failure path — the
  # user authenticated fine (Okta accepted them, the pool minted a token) but
  # holds no roles/iap.httpsResourceAccessor binding. Without it IAP serves its
  # own bare "You don't have access" page; with it, IAP 302s to this URI.
  #
  # Distinct from the sign-in loop: an UNauthenticated request goes to
  # auth.cloud.google/authorize regardless of this setting.
  dynamic "application_settings" {
    for_each = var.access_denied_page_uri == "" ? [] : [1]
    content {
      access_denied_page_settings {
        access_denied_page_uri = var.access_denied_page_uri
        # Appends a Google-generated troubleshooting link to the redirect, so
        # the custom page can offer "why was I denied?" without the app
        # needing any IAM read access itself.
        generate_troubleshooting_uri = var.access_denied_generate_troubleshooting_uri
      }
    }
  }

  access_settings {
    identity_sources = ["WORKFORCE_IDENTITY_FEDERATION"]
    workforce_identity_settings {
      workforce_pools = [local.wif_pool_name]
      oauth2 {
        client_id     = google_iam_oauth_client.iap[0].client_id
        client_secret = google_iam_oauth_client_credential.iap[0].client_secret
      }
    }
  }
}
