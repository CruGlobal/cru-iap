terraform {
  # LOCAL STATE ON PURPOSE.
  #
  # This stack is a disposable scratch environment in a sandbox project, not
  # shared infrastructure — nothing else ever needs to read its outputs, so a
  # remote backend would add a stale-lock failure mode and nothing else.
  # `terraform.tfstate` is gitignored; keep it that way.
  required_version = "~> 1.14"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.30"
    }
    # google_project_service_identity has no GA counterpart.
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 7.30"
    }
  }
}

provider "google" {
  project      = var.project_id
  region       = var.region
  access_token = var.access_token != "" ? var.access_token : null

  # Applied to every resource that supports labels. Compute LB primitives
  # (backend services, URL maps, NEGs, proxies) do NOT support labels — those
  # carry the same attribution in their `description` instead.
  default_labels = local.labels
}

provider "google-beta" {
  project        = var.project_id
  region         = var.region
  access_token   = var.access_token != "" ? var.access_token : null
  default_labels = local.labels
}

# The DNS zone can live in a different project, and a different org, from the
# rest of the stack. Workforce pools must share an org with the project they
# front, so enabling WIF can force the compute side into another org while the
# DNS zone stays where it is.
#
# So: the default provider authenticates as the compute-side identity (an
# explicit access token when the orgs differ), and this alias falls through to
# ADC, the identity that owns the zone. One apply, two identities, one A record.
provider "google" {
  alias   = "dns"
  project = var.dns_project
}
