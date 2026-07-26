######################################
# Workforce Identity Federation (Okta -> IAP)
#
# Gated on var.enable_workforce_federation, DEFAULT FALSE.
#
# The pool and its provider are ORG-level resources — parent is
# organizations/<id>, not the project. Creating them needs org-level IAM
# (iam.workforcePools.create), which the sandbox credentials do not have. The
# IAM OAuth client below IS project-level and would succeed on its own, but is
# useless without the pool, so it shares the gate.
#
# Adapted from cru-terraform applications/beacon/stage/workforce.tf.
######################################

resource "google_iam_workforce_pool" "this" {
  count = local.wif_create ? 1 : 0

  parent            = "organizations/${var.organization_id}"
  location          = "global"
  workforce_pool_id = local.wif_pool_id
  display_name      = "cru-iap e2e" # API caps display_name at 32 chars
  description       = "Scratch pool for cru-iap end-to-end tests. owner=mattdrees, temporary=true — safe to delete."
  session_duration  = "3600s"

  # Workforce pools soft-delete and hold their id for 30 days, so a
  # destroy/recreate cycle with the same id fails until the purge. Change
  # local.wif_pool_id if you need to recreate sooner.
}

resource "google_iam_workforce_pool_provider" "okta" {
  count = local.wif_create ? 1 : 0

  location          = "global"
  workforce_pool_id = google_iam_workforce_pool.this[0].workforce_pool_id
  provider_id       = local.wif_provider_id
  display_name      = "Okta (${var.okta_provider_type})"

  # See locals.tf — google.email is the mapping whose absence produced beacon's
  # `missing_email` rejections. Do not drop it.
  attribute_mapping = local.wif_attribute_mapping

  dynamic "oidc" {
    for_each = var.okta_provider_type == "oidc" ? [1] : []
    content {
      issuer_uri = local.okta_issuer
      client_id  = local.okta_client_id

      client_secret {
        value {
          plain_text = local.okta_client_secret
        }
      }

      web_sso_config {
        # Authorization-code flow (hence the client secret). MERGE_USER_INFO...
        # pulls the userinfo endpoint's claims over the id_token's.
        response_type             = "CODE"
        assertion_claims_behavior = "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS"

        # LOAD-BEARING — do not "simplify" this to the default.
        #
        # Google requests only `openid` unless told otherwise. Okta's org
        # authorization server then returns no `email` claim, google.email has
        # nothing to map, and the IAP assertion JWT arrives with NO identity at
        # all. The verifier reads `email` and nothing else, so that is a total
        # auth failure — and it is exactly the failure that cost beacon two
        # blind deploy cycles (cru-iap README, gotcha 2).
        additional_scopes = ["email", "profile"]
      }
    }
  }

  dynamic "saml" {
    for_each = var.okta_provider_type == "saml" ? [1] : []
    content {
      idp_metadata_xml = local.okta_saml_metadata_xml
    }
  }

  lifecycle {
    precondition {
      condition = var.okta_provider_type != "oidc" || (
        local.okta_issuer != "" && local.okta_client_id != "" && local.okta_client_secret != ""
      )
      error_message = "okta_provider_type = \"oidc\" needs issuer/client_id/client_secret. Supply them via the okta_* variables or let the Okta side write e2e/okta/outputs.json."
    }
    precondition {
      condition     = var.okta_provider_type != "saml" || local.okta_saml_metadata_xml != ""
      error_message = "okta_provider_type = \"saml\" needs okta_saml_metadata_xml (or a `metadata` key in e2e/okta/outputs.json)."
    }
  }
}

######################################
# IAM OAuth client — IAP's own credential for the workforce sign-in flow.
# Project-owned, but must live in the same org as the pool.
######################################

resource "google_iam_oauth_client" "iap" {
  count = local.wif ? 1 : 0

  project         = var.project_id
  location        = "global"
  oauth_client_id = "${local.name}-wif"
  display_name    = "cru-iap e2e IAP sign-in" # 32-char cap
  client_type     = "CONFIDENTIAL_CLIENT"

  allowed_grant_types = ["AUTHORIZATION_CODE_GRANT"]
  allowed_scopes      = ["https://www.googleapis.com/auth/cloud-platform"]

  # Two-phase apply — see var.wif_oauth_client_generated_id.
  allowed_redirect_uris = [
    var.wif_oauth_client_generated_id == ""
    ? "https://${local.hostname}/placeholder-pending-phase-2"
    : "https://iap.googleapis.com/v1/oauth/clientIds/${var.wif_oauth_client_generated_id}:handleRedirect"
  ]

  depends_on = [google_project_service.enabled["iam.googleapis.com"]]
}

resource "google_iam_oauth_client_credential" "iap" {
  count = local.wif ? 1 : 0

  project                    = var.project_id
  location                   = "global"
  oauthclient                = google_iam_oauth_client.iap[0].oauth_client_id
  oauth_client_credential_id = "${local.name}-wif-cred"
  display_name               = "cru-iap e2e IAP secret" # 32-char cap
}
