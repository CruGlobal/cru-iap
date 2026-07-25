######################################
# Cloud Run
######################################

resource "google_cloud_run_v2_service" "app" {
  project  = var.project_id
  name     = local.name
  location = var.region
  labels   = local.labels

  # HARD REQUIREMENT, not a preference. INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER
  # is the API spelling of `--ingress=internal-and-cloud-load-balancing`. Any
  # other value leaves the raw *.run.app URL reachable with NO IAP in front,
  # which defeats the entire point of this stack (cru-iap README, deployment
  # checklist item 2).
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  # Scratch stack — never block a destroy.
  deletion_protection = false

  template {
    scaling {
      # Scale to zero: idle cost of this service is $0.
      min_instance_count = 0
      max_instance_count = 2
    }

    containers {
      image = var.container_image

      ports {
        container_port = var.container_port
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      # The gem's contract: IAP_AUDIENCE is the backend-service resource path,
      # not a URL and not a client id (cru-iap README §1). Deliberately named
      # without an app prefix, exactly as the real cru-terraform module injects it.
      env {
        name  = "IAP_AUDIENCE"
        value = local.iap_audience
      }
    }
  }
}

# The load balancer reaches Cloud Run as an anonymous caller, so the service has
# to allow unauthenticated invocation. That is not a hole here: ingress is
# INTERNAL_LOAD_BALANCER, so the only path in is the LB, and the LB is gated by
# IAP. This is also what provisions IAP's ability to invoke the service — the
# IAP service agent is covered by allUsers.
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  project  = var.project_id
  location = google_cloud_run_v2_service.app.location
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
