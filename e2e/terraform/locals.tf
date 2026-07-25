locals {
  name = "cru-iap-e2e"

  # Attribution + disposability, on every resource that accepts labels.
  # Anything that doesn't (compute LB primitives) repeats this in `description`.
  labels = {
    purpose   = "cru-iap-e2e"
    owner     = "mattdrees"
    temporary = "true"
  }

  description = "cru-iap e2e scratch (owner=mattdrees, temporary=true) — safe to delete"

  hostname = "${var.subdomain}.${trimsuffix(data.google_dns_managed_zone.this.dns_name, ".")}"

  ######################################
  # Okta hand-off
  #
  # The Okta side of this e2e setup owns e2e/okta/ and writes two files:
  #   outputs.json  — non-secret app details (committed)
  #   secrets.json  — client_secret + test-user password (gitignored, 0600)
  # Read them if present so the two halves compose with no copy-paste; explicit
  # variables win over the files. Every key is looked up through `try` because
  # that file's shape is owned by the Okta side, not here — a missing key must
  # degrade to a precondition error, not a crash.
  ######################################
  okta_outputs_path = "${path.module}/../okta/outputs.json"
  okta_secrets_path = "${path.module}/../okta/secrets.json"

  okta_outputs = jsondecode(fileexists(local.okta_outputs_path) ? file(local.okta_outputs_path) : "{}")
  okta_secrets = jsondecode(fileexists(local.okta_secrets_path) ? file(local.okta_secrets_path) : "{}")

  # coalesce() errors when everything is null/empty, so each is wrapped in
  # try(..., "") — "absent" has to land as "" and be caught by the preconditions
  # in workforce.tf, not blow up at plan time in a stack where WIF is off.
  #
  # `issuer_uri` is the key the Okta side actually writes; `issuer` is accepted
  # too so a rename there doesn't silently break this.
  okta_issuer = try(coalesce(
    var.okta_issuer,
    try(local.okta_outputs.issuer_uri, null),
    try(local.okta_outputs.issuer, null),
  ), "")
  okta_client_id = try(coalesce(
    var.okta_client_id,
    try(local.okta_outputs.client_id, null),
  ), "")
  okta_client_secret = try(coalesce(
    var.okta_client_secret,
    try(local.okta_secrets.client_secret, null),
  ), "")
  okta_saml_metadata_xml = try(coalesce(
    var.okta_saml_metadata_xml,
    try(local.okta_outputs.metadata, null),
    try(local.okta_outputs.idp_metadata_xml, null),
  ), "")

  wif = var.enable_workforce_federation

  # Fixed constants: the Okta app's redirect URI (OIDC) / ACS + audience URLs
  # (SAML) embed the pool and provider ids, so they cannot be derived from the
  # created resources without a chicken-and-egg. These MUST agree with what the
  # Okta side registered — hence defaulting to the ids in its outputs.json.
  wif_pool_id = coalesce(
    try(local.okta_outputs.workforce_pool_id, null),
    local.name,
  )
  wif_provider_id = coalesce(
    try(local.okta_outputs.workforce_pool_provider_id, null),
    var.okta_provider_type == "saml" ? "okta-saml" : "okta-oidc",
  )

  # Hand these to whoever configures the Okta app (SAML only; OIDC uses the
  # redirect URI on the IAM OAuth client instead).
  wif_acs_url  = "https://auth.cloud.google/signin-callback/locations/global/workforcePools/${local.wif_pool_id}/providers/${local.wif_provider_id}"
  wif_audience = "https://iam.googleapis.com/locations/global/workforcePools/${local.wif_pool_id}/providers/${local.wif_provider_id}"

  ######################################
  # Attribute mapping
  #
  # google.email is LOAD-BEARING and is the whole reason this stack exists:
  # without it the IAP JWT carries no email claim anywhere and `sub` is an
  # opaque principal:// URI (cru-iap README, gotcha 2 — beacon hit exactly this
  # live on 2026-07-24). Verifying that a correctly-mapped pool DOES emit an
  # `email` claim is the open question the README flags as "Unverified".
  ######################################
  wif_attribute_mapping = var.okta_provider_type == "saml" ? {
    # SAML attributes arrive as lists of strings, hence [0]; groups stays
    # un-indexed so principalSet group bindings work.
    "google.subject"      = "assertion.subject"
    "google.email"        = "assertion.attributes['email'][0]"
    "google.display_name" = "assertion.attributes['email'][0]"
    "google.groups"       = "assertion.attributes['groups']"
    "attribute.email"     = "assertion.attributes['email'][0]"
    } : {
    # OIDC: claims are scalars, no [0] indexing. google.subject is the raw Okta
    # `sub` (immutable) rather than the email, so an Okta rename doesn't break
    # principal:// bindings; the email rides in google.email, which is the only
    # claim the verifier reads.
    "google.subject"      = "assertion.sub"
    "google.email"        = "assertion.email"
    "google.display_name" = "assertion.name"
    "attribute.email"     = "assertion.email"
  }
}
