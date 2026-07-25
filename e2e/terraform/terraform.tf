terraform {
  # LOCAL STATE ON PURPOSE.
  #
  # cru-terraform's convention is an S3 backend (cru-tf-remote-state), but this
  # stack is a disposable scratch environment in one person's sandbox project,
  # not shared infrastructure — nothing else ever needs to read its outputs, and
  # a stale lock in the shared bucket would be pure downside. `terraform.tfstate`
  # is gitignored at the repo root; keep it that way.
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
  project = var.project_id
  region  = var.region

  # Applied to every resource that supports labels. Compute LB primitives
  # (backend services, URL maps, NEGs, proxies) do NOT support labels — those
  # carry the same attribution in their `description` instead.
  default_labels = local.labels
}

provider "google-beta" {
  project        = var.project_id
  region         = var.region
  default_labels = local.labels
}
