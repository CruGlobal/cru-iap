######################################
# Target project / region
#
# No defaults on the project/org/DNS variables on purpose. This stack is a
# reference for standing up a real IAP path in a throwaway project; baking in
# any particular project id would invite a `terraform apply` against something
# that was never meant to host it. Supply them via a tfvars file — see
# wif.tfvars.example.
######################################

variable "project_id" {
  description = "GCP project this stack is confined to. Use a personal or throwaway sandbox project, never one hosting real workloads."
  type        = string
}

variable "project_number" {
  description = "Project number for var.project_id. Used to build the IAP audience path and the IAP service-agent email."
  type        = string
}

variable "access_token" {
  description = <<-EOT
    OAuth access token for the identity that owns var.project_id. Empty (default)
    = use ADC. Set this when the stack's project is in a different org from your
    ADC identity, e.g.

      -var access_token="$(gcloud auth print-access-token --account=you@example.com)"

    Tokens last ~1h; refresh before a long apply. The DNS record uses ADC
    regardless, via the aliased provider.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}

variable "dns_project" {
  description = "Project that owns dns_managed_zone. Often the same as project_id, but they can differ — the zone does not have to follow the compute side between orgs."
  type        = string
}

variable "region" {
  description = "Region for the Cloud Run service and its serverless NEG."
  type        = string
  default     = "us-central1"
}

variable "owner" {
  description = "Value for the `owner` label, applied to every labelable resource so stray resources are attributable. Compute LB primitives don't support labels and repeat it in `description` instead."
  type        = string
  default     = "unknown"
}

######################################
# DNS / hostname
######################################

variable "dns_managed_zone" {
  description = <<-EOT
    Name of an existing Cloud DNS public managed zone in var.dns_project, whose
    delegation actually resolves. Terraform does NOT create the zone — it only
    adds an A record. A delegation that really resolves is what makes a
    Google-managed certificate possible here at all.
  EOT
  type        = string
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
    "gcr.io/google-containers/echoserver:1.10" (port 8080) — then
    `x-goog-iap-jwt-assertion` shows up in the response body and can be fed
    straight into the verifier.
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
    or `principalSet://.../group/<group>`.
  EOT
  type        = set(string)
}

######################################
# Workforce Identity Federation (Okta)
#
# OFF BY DEFAULT. Workforce pools are ORG-level resources — their parent is an
# organization, not a project — so creating one needs org-level IAM
# (iam.workforcePools.create) that a sandbox identity typically does not have.
# Everything else in the stack stands up without it; IAP then runs in plain
# Google-identity mode, which still exercises token verification (with a Google
# `email` claim rather than a federated one).
#
# Borrowing an existing pool (see shared_workforce_pool) avoids the org-level
# grant entirely.
######################################

variable "enable_workforce_federation" {
  description = "Federate IAP to a workforce pool. Combined with shared_workforce_pool this decides whether the pool is created or borrowed — see that variable."
  type        = bool
  default     = false
}

variable "shared_workforce_pool" {
  description = <<-EOT
    Full resource name of an EXISTING workforce pool to federate IAP to, e.g.
    "locations/global/workforcePools/my-existing-pool".

    Empty (default) = create our own pool + provider, which needs org-level
    iam.workforcePools.create. Set = borrow an existing one, creating no
    org-level resource. Borrowing only needs whatever permission the IAP
    settings API demands to *reference* a pool by name, which is project-level
    in practice — that is the point of this mode.

    Borrowing means the IdP side is that pool's existing app too, so the app's
    assigned users must include whoever you intend to sign in as.
  EOT
  type        = string
  default     = ""
}

variable "organization_id" {
  description = "Numeric org id that owns the workforce pool. Only needed when creating a pool rather than borrowing one."
  type        = string
  default     = ""
}

variable "shared_workforce_provider_id" {
  description = "Provider id inside shared_workforce_pool. Only used to render the ACS/audience outputs correctly; a shared IdP app already embeds these."
  type        = string
  default     = ""
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
  description = "OIDC issuer URI of the Okta authorization server, e.g. https://example.oktapreview.com/oauth2/default. Overrides ../okta/outputs.json."
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
    Two-phase apply. google_iam_oauth_client.allowed_redirect_uris must embed
    the client id GENERATED by the API (a UUID — not oauth_client_id), which is
    unknowable until the resource exists.

      phase 1: leave "" and apply (a placeholder redirect URI is used)
      phase 2: copy the `wif_oauth_client_generated_id` output into here and re-apply

    Google's documented create-then-patch flow, not a Terraform limitation.
  EOT
  type        = string
  default     = ""
}

######################################
# Access-denied page (authorization failure)
######################################

variable "access_denied_page_uri" {
  description = <<-EOT
    URI IAP redirects to when a request is AUTHENTICATED but not AUTHORIZED —
    i.e. the user signed in through the IdP fine, but holds no
    roles/iap.httpsResourceAccessor binding. Empty (default) = IAP's own
    built-in "You don't have access" page.

    Note this is the authorization path only. An unauthenticated request still
    goes to auth.cloud.google/authorize regardless.

    Google's docs describe the custom access-denied page as part of a paid
    enterprise security subscription (Chrome Enterprise Premium), so whether
    the setting is honoured may be org-dependent — see the README.
  EOT
  type        = string
  default     = ""
}

variable "access_denied_generate_troubleshooting_uri" {
  description = "Have IAP append a generated troubleshooting link to the access-denied redirect. Measured to have no effect — see README."
  type        = bool
  default     = false
}
