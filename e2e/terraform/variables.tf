######################################
# Target project / region
######################################

variable "project_id" {
  description = "GCP project this stack is confined to. Matt's personal sandbox — do not point this at a real Cru project."
  type        = string
  default     = "cru-mattdrees-sandbox-poc"
}

variable "project_number" {
  description = "Project number for var.project_id. Used to build the IAP audience path and the IAP service-agent email."
  type        = string
  default     = "178891842216"
}

variable "region" {
  description = "Region for the Cloud Run service and its serverless NEG."
  type        = string
  default     = "us-central1"
}

######################################
# DNS / hostname
######################################

variable "dns_managed_zone" {
  description = <<-EOT
    Name of an existing Cloud DNS public managed zone in var.project_id, whose
    delegation actually resolves. Terraform does NOT create the zone — it only
    adds an A record. `matt-sandbox.ustech.app` is delegated from ustech.app
    (Route53) into the sandbox project, which is what makes a Google-managed
    certificate possible here at all.
  EOT
  type        = string
  default     = "matt-sandbox-ustech-app"
}

variable "subdomain" {
  description = "Label prepended to the managed zone's dns_name to form the LB hostname."
  type        = string
  default     = "cru-iap-e2e"
}

######################################
# Cloud Run
######################################

variable "container_image" {
  description = <<-EOT
    Trivial public container to sit behind IAP. The default is Google's
    always-available Cloud Run sample.

    If you want the e2e test to capture a REAL IAP assertion JWT, point this at
    an echo image that dumps request headers, e.g.
    "registry.k8s.io/echoserver:1.10" (port 8080) — then
    `x-goog-iap-jwt-assertion` shows up in the response body and can be fed
    straight into CruIap::TokenVerifier.
  EOT
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "container_port" {
  description = "Port the container listens on."
  type        = number
  default     = 8080
}

######################################
# IAP access
######################################

variable "iap_members" {
  description = <<-EOT
    IAM members granted roles/iap.httpsResourceAccessor on the IAP backend
    service. In Google-identity mode these are `user:`/`group:` principals; in
    workforce-federation mode they are
    `principal://iam.googleapis.com/locations/global/workforcePools/<pool>/subject/<email>`
    or `principalSet://.../group/<okta-group>`.
  EOT
  type        = set(string)
  default     = ["user:matt.drees@cru.org"]
}

######################################
# Workforce Identity Federation (Okta)
#
# OFF BY DEFAULT. Workforce pools are ORG-level resources
# (organizations/000000000000). Matt's sandbox credentials hold no org-level
# IAM, so `terraform apply` with this set to true will 403 — see README
# "Blockers". Everything else in the stack stands up without it; IAP then runs
# in plain Google-identity mode, which still exercises the gem's token
# verification (with an `email` claim rather than a workforce `sub`).
######################################

variable "enable_workforce_federation" {
  description = "Federate IAP to a workforce pool. Combined with shared_workforce_pool this decides whether the pool is created or borrowed — see that variable."
  type        = bool
  default     = false
}

variable "shared_workforce_pool" {
  description = <<-EOT
    Full resource name of an EXISTING workforce pool to federate IAP to, e.g.
    "locations/global/workforcePools/cru-workforce-preview" (Cru's shared,
    org-wide pool, defined in cru-terraform google/workforce-identity).

    Empty (default) = create our own pool + provider, which needs org-level
    iam.workforcePools.create. Set = borrow the shared one, creating no
    org-level resource. Borrowing only needs whatever permission the IAP
    settings API demands to *reference* a pool by name, which is expected to be
    project-level — that is the point of this mode, and it is measured rather
    than assumed (see README "Which workforce mode").

    Borrowing means the Okta side is the shared SAML app too, so the app's
    users must include whoever you intend to sign in as.
  EOT
  type        = string
  default     = ""
}

variable "organization_id" {
  description = "Numeric org id that owns the workforce pool. cru.org = 000000000000."
  type        = string
  default     = "000000000000"
}

variable "shared_workforce_provider_id" {
  description = "Provider id inside shared_workforce_pool. Cru's shared SAML provider is okta-preview-saml. Only used to render the ACS/audience outputs correctly; the shared Okta app already embeds these."
  type        = string
  default     = "okta-preview-saml"
}

variable "okta_provider_type" {
  description = "Federation protocol for the workforce pool provider: \"oidc\" or \"saml\". Must match what the Okta side actually created."
  type        = string
  default     = "oidc"

  validation {
    condition     = contains(["oidc", "saml"], var.okta_provider_type)
    error_message = "okta_provider_type must be \"oidc\" or \"saml\"."
  }
}

# The four values below are normally read from ../okta/outputs.json (written by
# the Okta side of this e2e setup — see locals.tf). Set them explicitly only to
# override that file.

variable "okta_issuer" {
  description = "OIDC issuer URI of the Okta authorization server, e.g. https://cru.oktapreview.com/oauth2/default. Overrides ../okta/outputs.json."
  type        = string
  default     = null
}

variable "okta_client_id" {
  description = "OIDC client id of the scratch Okta app. Overrides ../okta/outputs.json."
  type        = string
  default     = null
}

variable "okta_client_secret" {
  description = "OIDC client secret of the scratch Okta app. Overrides ../okta/outputs.json."
  type        = string
  default     = null
  sensitive   = true
}

variable "okta_saml_metadata_xml" {
  description = "SAML IdP metadata XML, when okta_provider_type = \"saml\". Overrides ../okta/outputs.json."
  type        = string
  default     = null
}

variable "wif_oauth_client_generated_id" {
  description = <<-EOT
    Two-phase apply, copied from cru-terraform applications/beacon/stage.
    google_iam_oauth_client.allowed_redirect_uris must embed the client id
    GENERATED by the API (a UUID — not oauth_client_id), which is unknowable
    until the resource exists.

      phase 1: leave "" and apply (a placeholder redirect URI is used)
      phase 2: copy the `wif_oauth_client_generated_id` output into here and re-apply

    Google's documented create-then-patch flow, not a Terraform limitation.
  EOT
  type        = string
  default     = ""
}
