######################################
# Service enablement
#
# All of these were already enabled in the sandbox before this stack existed;
# declaring them is idempotent and makes the stack self-contained if it is ever
# pointed at a fresh project. disable_on_destroy = false throughout: the sandbox
# is shared with unrelated POCs, and `terraform destroy` must not rip an API out
# from under them.
######################################

resource "google_project_service" "enabled" {
  for_each = toset([
    "compute.googleapis.com",
    "run.googleapis.com",
    "iap.googleapis.com",
    "iam.googleapis.com",
    "dns.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

data "google_dns_managed_zone" "this" {
  project = var.project_id
  name    = var.dns_managed_zone
}
