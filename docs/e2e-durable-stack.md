# Moving the e2e stack onto CI-owned infrastructure

## Where we are

The live e2e stack works and all four language suites verify against it, but
every load-bearing piece of it is borrowed or disposable:

| Piece | Now | Problem |
|---|---|---|
| GCP project | `cru-iap-e2e-lb`, org **test.cru.org** | Applied with `-var access_token="$(gcloud auth print-access-token --account=phillip.drees@test.cru.org)"` — a human, in the wrong org |
| Workforce pool | `keepzero-okta-poc` (**borrowed**) | Someone else's POC. Org-level, so no dedicated project fixes it |
| Okta objects | Scratch app + user in `cru.oktapreview.com` | `e2e/okta/README.md` opens with "everything here is throwaway"; the user's app assignment is undeclared drift from `cru-terraform/google/workforce-identity/okta-saml.tf` |
| Terraform state | Local, gitignored | CI cannot take over, and a killed run leaks resources with no record |
| DNS | `cru-iap-wif.matt-sandbox.ustech.app` | Delegation lives in Matt's sandbox |
| LB | Permanent | ~$18/month for something used minutes a day |

## Target shape

Two layers, split on *who owns the lifecycle*:

**Permanent, in `cru-terraform`** — created once by a human with org rights,
then never touched by CI:

- Project in **cru.org**, in the devops folder alongside `github-oidc-cru`
- Cloud DNS zone for a new delegated subdomain, e.g. `iap-e2e.ustech.app`, plus
  the NS delegation record in `aws/route53/ustech_app/records.tf` (the
  `matt-sandbox.ustech.app` delegation there is the pattern to copy)
- **Certificate Manager** wildcard cert + DNS authorization + cert map for
  `*.iap-e2e.ustech.app` — see "Killing the cert wait" below
- IAM OAuth client + credential for IAP workforce sign-in (project-level, and
  subject to the two-phase apply, so it must not be per-run), with the secret in
  Secret Manager
- CI service account + a WIF binding on the **existing** `github-oidc-cru` pool
- Okta: a dedicated group, the test user, and the group's assignment to the
  already-declared shared SAML app
- GCS bucket for the ephemeral layer's terraform state

**Ephemeral, in this repo's `e2e/terraform`** — created and destroyed by CI on
every run:

- Cloud Run service (echoserver), serverless NEG
- Backend service with `iap { enabled = true }`, IAP service identity
- URL map, target HTTPS proxy (attaching the permanent cert map), forwarding
  rule, global IP
- The A record in the permanent zone, TTL 60
- The `iap.httpsResourceAccessor` binding on the Okta group's principalSet

Reuse the **existing shared pool** `cru-workforce-preview` / `okta-preview-saml`
rather than creating one. Its `google.email` mapping is already committed
(cru-terraform `3254217a2`), so the gap you were going to fix is closed — and
this e2e would be the first consumer of that pool, which is worth knowing: it
exercises the shared pool's mapping for real, ahead of the ten app environments
in `docs/iap-cutover.md`.

## Killing the cert wait — you may not have to pay the 10–30 minutes

You said you'd rather pay the ~7 min cert wait than $18/month. Two corrections:

1. It is worse than 7 minutes. `e2e/terraform/lb.tf:57` uses a **classic**
   `google_compute_managed_ssl_certificate`, whose own comment says 10–30
   minutes, and which cannot even start validating until the A record resolves.
2. You can avoid it entirely. `cru-terraform/google/projects/shared-alb/prod`
   already demonstrates the alternative: **Certificate Manager** with a
   **DNS authorization**. The authorization is a permanent CNAME and the
   wildcard cert validates once, then stays valid. An ephemeral LB just attaches
   the cert map.

So put the wildcard cert in the permanent layer. Managed certs are free; the
recurring cost is the forwarding rule, which stays ephemeral. Per-run infra time
drops to the ~1–2 minutes the HTTPS frontend takes to start serving — that part
is unavoidable and is already documented in `e2e/terraform/README.md`.

Net: no $18/month **and** no cert wait.

## CI wiring

`github-oidc-cru` already has a workload identity pool whose provider is scoped
to `assertion.repository_owner == "CruGlobal"`, with `attribute.repository`
mapped — so the CI SA binding narrows to this repo:

```hcl
resource "google_service_account_iam_member" "ci" {
  service_account_id = google_service_account.e2e_ci.name
  role               = "roles/iam.workloadIdentityUser"
  member = join("/", [
    "principalSet://iam.googleapis.com",
    data.terraform_remote_state.github_oidc.outputs.workload_identity_pool,
    "attribute.repository/CruGlobal/cru-iap",
  ])
}
```

Roles the SA needs, all scoped to the e2e project: `run.admin`,
`compute.loadBalancerAdmin` (+ `compute.networkAdmin` for the NEG),
`iap.admin`, `dns.admin` on the permanent zone, `iam.serviceAccountUser`,
`secretmanager.secretAccessor` for the OAuth client secret, and
`storage.objectAdmin` on the state bucket. Explicitly **not** any
`iam.workforcePools.*` create right — the pool is permanent and shared.

Note what CI does *not* need: no GCP credential is required to *run* the tests.
The verification path is public HTTP plus a browser login. Credentials are only
for `terraform apply`/`destroy`.

Okta secrets (test-user password, TOTP shared secret) go in GitHub secrets. You
confirmed no network-zone restrictions, so a runner IP is fine.

### Leak protection

Apply and destroy in one job with `if: always()` on the destroy. That is not
sufficient on its own — a cancelled or OOM-killed job strands a forwarding rule
that bills. Hence remote state in the permanent project, so the next run can
destroy what the last one left, plus a reaper: every resource already carries
`purpose=cru-iap-e2e` labels (`e2e/terraform/locals.tf`), so a scheduled sweep
can find and delete anything older than a few hours.

### Nightly, only when something changed

```yaml
on:
  schedule: [{ cron: "0 9 * * *" }]
  workflow_dispatch:
```

Gate on whether the last successful run's SHA differs from HEAD, and on whether
the diff touches anything that could plausibly change the answer:

```bash
last="$(gh run list --workflow=e2e.yml --status=success --limit=1 \
          --json headSha --jq '.[0].headSha')"
if [ -n "$last" ] && git diff --quiet "$last" HEAD -- \
     lib src cru_iap cruiap spec tests test e2e; then
  echo "nothing worth testing since $last"; exit 0
fi
```

No extra state to maintain — the run history *is* the state. `workflow_dispatch`
always runs, so you can force one.

One caveat: this gate means a *Google-side* change (new claim, moved endpoint)
is only caught on the next commit, not the next night. That is the right trade
given the JWKS smoke check already runs on every PR and covers the endpoint half
of it — but it does mean the claim-shape drift detector is commit-triggered, not
time-triggered. If that matters, add a weekly unconditional run.

## Order of work

1. **Okta objects into cru-terraform** — group, test user, group→shared-app
   assignment. Blocks everything; also removes the existing undeclared drift.
2. **Permanent GCP layer** in cru-terraform: project, DNS zone + Route53
   delegation, Certificate Manager wildcard, IAM OAuth client (two-phase, by
   hand, once), CI SA + WIF binding, state bucket, Secret Manager entry.
3. **Rework `e2e/terraform`** to be the ephemeral layer: drop the project/pool/
   classic-cert resources, add the GCS backend, take the permanent layer's
   outputs as variables, attach the cert map.
4. **The e2e workflow**: WIF auth → apply → capture → `run_all.sh --no-capture`
   → `smoke.mjs iap-front` → destroy in `always()`.
5. **Tear down the old stack** — the `wif` workspace, the scratch Okta objects
   (teardown recipe is already in `e2e/okta/README.md`), and the
   `matt-sandbox.ustech.app` record. Also drop the borrowed-pool assignment on
   `keepzero-okta-poc`.

Steps 1–2 need org-level rights and a cru-terraform PR; 3–5 are this repo.

The test code needs no changes for any of this — audience, URL and expected
email already resolve from the environment or the capture artifact, with no
infrastructure values hardcoded in any of the four suites. That was the point of
the loader contract in `e2e/README.md`.

## Why the real app module can't be reused (and what would change that)

You asked what makes this hard. It is one structural thing plus a pile of
coupling.

**The blocker: `gcp/cloudrun/app` has no standalone-LB IAP path.**
`variables.tf` enforces it:

```hcl
validation {
  condition     = var.iap == null || var.load_balancer_strategy == "shared"
  error_message = "iap requires load_balancer_strategy = \"shared\"."
}
```

This is not a missing input, it is the design. The module's IAP support *is* the
shared ALB: `iap.tf` splices a host_rule onto the shared URL map through the
private `crugcp` provider's optimistic-locking PATCH. `run.app` and `none`, the
other two strategies, have no LB to put IAP in front of. So an isolated
ephemeral LB — the entire premise of the cheap-e2e design — is outside what the
module models.

Secondary coupling, each its own reason:

- `project.tf` unconditionally creates a `google_folder` **and** a
  `google_project`. There is no "use this existing project" input, so the module
  always owns a project. Per-run project churn is also a non-starter: project
  deletion is a 30-day soft delete.
- `data.terraform_remote_state.shared_alb` reads S3 `cru-tf-remote-state` and
  splices onto the **real** shared ALB. An e2e run would mutate shared
  production-adjacent infra on every apply.
- `crugcp_compute_url_map_host_rule` PATCHes that shared URL map. Concurrent CI
  runs contend on it — lock contention against shared infra, as a flake source.
- A long tail of credentials a test stack shouldn't hold:
  `data.github_repository`, `aws_dynamodb_table` (`ECSBuildNumbers`,
  `CruApplicationInfo`), the Datadog log-forwarder pubsub topic, shared-VPC
  lookups, Artifact Registry, Route53.

**What would unlock it**, in order of leverage:

1. A `load_balancer_strategy = "standalone"` that gives the app its own LB +
   cert map and drops the shared URL map and `crugcp` entirely. Everything else
   is secondary to this.
2. An `existing_project` input making `project.tf` conditional.
3. Feature-gating the AWS / GitHub / Datadog data sources so a minimal
   instantiation doesn't need those credentials.

**But weigh the payoff honestly.** The appeal of reuse is testing the real
module path. A standalone strategy would *not* test the shared-ALB URL map
splice — which is the most intricate and most bug-prone part of the real IAP
path, and the part `docs/iap-cutover.md` shows people actually getting wrong. So
"same-shape copy" (today) and "module with a standalone strategy" cover roughly
the same surface. The extra work buys shared code, not materially better
coverage.

### The alternative that was considered and declined

For the record, since it is the obvious counter-proposal and someone will raise
it again: instantiate `gcp/cloudrun/app` **as a normal app** on the existing
shared **stage** ALB, with `iap` set and the shared pool — a real environment,
identical to the ten in the cutover doc.

It is attractive on paper. The shared stage ALB already exists and is already
paid for, so a host_rule plus a backend service on it is roughly $0 incremental
— the $18/month figure is an artifact of the standalone-LB design, not of IAP
e2e testing as such. And it would test the exact path real apps use, including
the URL-map splice that the ephemeral design cannot cover.

**Decided against (2026-07-27, Matt):** a test stack taking a permanent
hostname on the shared ALB, and contending on the shared URL map from CI, does
not align with what the devops team expects of that shared infrastructure. Not
pursuing it.

So the ephemeral design above is the plan, with its known coverage gap
acknowledged: the shared-ALB URL-map splice is exercised by the real app
environments, not by this e2e.

## Unresolved

- Subdomain name — `iap-e2e.ustech.app`? Delegated Cloud DNS zone in the new
  project, matching the `matt-sandbox` pattern?
- Project id / folder — new project in the devops folder next to
  `github-oidc-cru`, or somewhere else?
- Ephemeral state backend: GCS in the e2e project (keeps CI's blast radius in one
  project) vs S3 `cru-tf-remote-state` (the org convention)?
- Okta test user: `example.invalid` again, or a real-ish `test.cru.org` address?
- Dedicated Okta group for the e2e user, or assign the shared app to Everyone as
  `okta-saml.tf` suggests? A group is also what would let us test the
  access-denied path.
- Reaper: scheduled GHA sweep, or a Cloud Scheduler job in the e2e project?
- `probe_denied.mjs` is still a manual script. Fold the access-denied path into
  the automated suite while the stack is being rebuilt anyway?
