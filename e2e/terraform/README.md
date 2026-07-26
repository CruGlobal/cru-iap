# e2e/terraform — real IAP, in a sandbox

Stands up a genuine Google IAP path so `cru_iap` can be exercised against live
infrastructure instead of fixtures:

```
client ──▶ global external HTTPS LB ──▶ backend service (IAP enabled) ──▶ serverless NEG ──▶ Cloud Run
                    │                            │
              Google-managed cert          workforce pool (Okta)  ← optional, currently blocked
```

Everything lives in **`cru-mattdrees-sandbox-poc`** (project number
`178891842216`). Nothing here touches a real Cru project.

## Relationship to cru-terraform

Cru's real IAP apps use the `gcp/cloudrun/app` module from
`cru-terraform-modules`, with the workforce pool alongside it in `cru-terraform`
(`applications/beacon/stage/workforce.tf`).

**That module is not reused here — this is copy-and-adapt**, and deliberately so.
The module cannot run against an existing sandbox project:

| Module assumption | Why it can't hold here |
|---|---|
| `project.tf` creates a **new** `google_folder` *and* a **new** `google_project` bound to a billing account | Org-level blast radius; we must stay inside one existing project. There is no input that points the module at a pre-existing project |
| `data.terraform_remote_state.shared_alb` (S3 `cru-tf-remote-state`) | Splices onto Cru's shared ALB in another project; not reachable or appropriate from a sandbox |
| The private `crugcp` provider (`crugcp_compute_url_map_host_rule`) | Internal provider that PATCHes the shared URL map |
| Shared VPC service-project attachment + Cross-Project Service Referencing | Needs IAM on Cru's host project |
| Datadog / GitHub OIDC / Route53 / Cloud Armor / Artifact Registry wiring | Irrelevant here and each needs its own credentials |

What *was* copied verbatim in shape, so the e2e run tests the real thing:

* `iap.tf` — the backend service with `iap { enabled = true }`, the
  `google_project_service_identity` for IAP's service agent, the
  `iap.httpsResourceAccessor` grants, and `google_iap_settings` for workforce
  federation. Adapted from `gcp/cloudrun/app/iap.tf`.
* The NEG-references-the-service-**by-name** trick, which breaks the
  `IAP_AUDIENCE → backend service → NEG → Cloud Run` cycle. Adapted from
  `gcp/cloudrun/app/compute.tf`.
* `workforce.tf` — pool, provider, and the two-phase IAM OAuth client apply.
  Adapted from `cru-terraform applications/beacon/stage/workforce.tf`.

This stack owns a **standalone** load balancer rather than joining a shared one.

## Current state

Applied, running. Workforce federation is **off** (see Blockers).

| | |
|---|---|
| URL | <https://cru-iap-e2e.matt-sandbox.ustech.app/> |
| `IAP_AUDIENCE` | `/projects/178891842216/global/backendServices/3357314301240629663` |
| LB IP | `136.69.48.172` |
| Cloud Run | `cru-iap-e2e` in `us-central1`, `ingress = INTERNAL_LOAD_BALANCER`, min instances 0 |
| IAP mode | Google identities (`user:matt.drees@cru.org` granted) |

`terraform output` is the source of truth; the values above are a convenience copy.

Verified live after apply (2026-07-25), managed cert `ACTIVE`:

| Check | Result |
|---|---|
| `GET https://…/` | `302` → `accounts.google.com/o/oauth2/v2/auth` — IAP, not the app |
| `GET https://…/?login=true` | `302` → same IdP flow |
| Same request with a forged `x-goog-iap-jwt-assertion:` header | still `302` — IAP ignores the client-supplied header; the app is never reached |
| `GET http://…/` | `301` → `https://…` |
| `GET https://cru-iap-e2e-2uzbhsjb7a-uc.a.run.app/` | `404` from the Google frontend — **no IAP bypass** |

Note the cert takes ~5 min to reach `ACTIVE` and the HTTPS frontend a further
~1-2 min to start serving; `000`/`SSL_ERROR_SYSCALL` in that window is expected,
not a misconfiguration.

## Usage

```sh
terraform init
terraform plan
terraform apply

terraform output iap_audience   # → export IAP_AUDIENCE=…
```

State is **local** (`terraform.tfstate`, gitignored at the repo root). The
cru-terraform convention is an S3 backend, but this is a disposable
single-operator scratch stack — nothing else reads its outputs, and a stale lock
in the shared bucket would be pure downside.

Credentials: Application Default Credentials for a principal with Compute /
Cloud Run / IAP / DNS admin on the sandbox. `gcloud auth application-default
login` if the token is stale. (Note: the `matt-claude@…` service account in the
sandbox has **no** compute permissions and cannot apply this stack — it lacks
`compute.backendServices.create` et al. Use the user ADC.)

## What it satisfies from the gem's deployment checklist

* **`IAP_AUDIENCE`** — a terraform output, and also injected into the container
  as an env var, matching the real module's contract. It is the backend-service
  *resource path*, not a URL and not a client id.
* **`--ingress=internal-and-cloud-load-balancing`** — enforced as
  `ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"` in `cloud_run.tf`. The
  raw `*.run.app` URL returns a Google-frontend `404` rather than reaching the
  app, so there is no IAP bypass. Verify with:

  ```sh
  curl -i "$(terraform output -raw cloud_run_uri)"    # → 404 from GFE, never the app
  ```
* **`/?login=true` and `/?gcp-iap-mode=CLEAR_LOGIN_COOKIE`** — surfaced as the
  `login_url` / `logout_url` outputs. These are app-side link targets; there is
  no friendly sign-in page in this stack (the real module's `friendly_signin`
  needs a GCS bucket, a backend bucket, and URL-map route rules — out of scope
  for testing the verifier).
* **`google.email` attribute mapping** — see `locals.tf`. Present and commented
  as load-bearing, because its absence is the exact bug this e2e exists to
  catch.

## Getting a real IAP assertion JWT

The default container (`us-docker.pkg.dev/cloudrun/container/hello`) does not
echo request headers. To capture a live `x-goog-iap-jwt-assertion` and feed it to
`CruIap::TokenVerifier`, re-apply with an echo image:

```sh
terraform apply -var container_image=registry.k8s.io/echoserver:1.10
```

Then sign in through a browser and read the header out of the response body.

## Labels

Every labelable resource carries `purpose=cru-iap-e2e`, `owner=mattdrees`,
`temporary=true` via the provider's `default_labels`. Compute LB primitives
(backend services, URL maps, NEGs, proxies, forwarding rules) do not support
labels at all — those repeat the same attribution in their `description` field.

Find everything:

```sh
gcloud asset search-all-resources \
  --scope=projects/cru-mattdrees-sandbox-poc \
  --query='labels.purpose=cru-iap-e2e'
```

## Which workforce mode

`enable_workforce_federation = true` federates IAP to a workforce pool. Where that
pool comes from depends on `shared_workforce_pool`:

| | `shared_workforce_pool = ""` (create) | `shared_workforce_pool` set (borrow) |
|---|---|---|
| Plan size | 25 to add | **3 to add** — OAuth client, credential, `google_iap_settings` |
| Org-level IAM | **required** (`iam.workforcePools.create`) | none needed to render; see caveat |
| Okta side | the scratch app in `../okta` | the **shared** SAML app, org-managed |
| Cleanup | pool id reserved 30 days after destroy | nothing org-level to clean up |

Borrow mode, against Cru's shared pool:

```sh
terraform apply \
  -var enable_workforce_federation=true \
  -var shared_workforce_pool="locations/global/workforcePools/cru-workforce-preview" \
  -var okta_provider_type=saml
```

**Caveat, not yet measured:** a successful `plan` only proves Terraform can render a
pool reference — it does not prove the IAP settings API will *accept* a reference to
a pool the caller cannot read. `matt.drees@cru.org` has none of
`iam.workforcePools.{get,create,delete,update}` (measured), so an apply is the test.
If it 403s, the reference needs pool-level read and borrowing buys nothing over
creating; if it succeeds, no org IAM is needed for consuming apps at all — which is
the answer that matters for beacon and cru-bot.

### Borrowing will currently fail to sign anyone in, on purpose

The shared pool's provider is missing `google.email` in its `attribute_mapping`
(cru-terraform PR #11429 fixes it). Until that merges and applies, a login through
the shared pool produces an IAP JWT with **no email claim**, and `CruIap::TokenVerifier`
rejects it with `missing_email` — exactly the failure that cost beacon-stage two
deploy cycles. That makes borrow mode a faithful end-to-end reproduction of the bug
today, and the regression test for the fix once #11429 lands.

Note also that switching an already-applied stack into either workforce mode replaces
Google-identity sign-in on the live URL. The Google-identity path is what currently
works, so expect to lose it while testing WIF.

## Teardown

```sh
cd e2e/terraform
terraform destroy
```

That is the whole thing — 20 resources, all in the sandbox project, no manual
cleanup. Notes:

* **APIs are not disabled.** Every `google_project_service` sets
  `disable_on_destroy = false`. The sandbox hosts unrelated POCs and destroy must
  not rip Compute or Cloud Run out from under them. None of these APIs were
  enabled *by* this stack anyway — all five were already on.
* **The DNS zone survives.** `matt-sandbox.ustech.app` is pre-existing and read
  via a data source; only the `cru-iap-e2e` A record is removed.
* **Workforce pools soft-delete for 30 days.** If you ever do get the pool
  created, `terraform destroy` marks it deleted but the id `cru-iap-e2e` stays
  *reserved* for 30 days. A re-apply with the same id inside that window will
  fail (or, if you undelete instead, resurrect a pool Terraform doesn't have in
  state). Change `local.wif_pool_id` in `locals.tf` — and the matching
  `workforce_pool_id` on the Okta side — if you need to recreate sooner.
* The Okta app is **not** managed here. Tear it down via `e2e/okta/`.

## Cost

| Item | Monthly |
|---|---|
| 2 global forwarding rules (`:443`, `:80`) — GCP bills the first five as one bundle at $0.025/hr | ~$18.25 |
| Global static IP, while attached to a forwarding rule | $0 |
| Cloud Run, min instances 0 | ~$0 idle |
| Google-managed certificate | $0 |
| IAP | $0 |
| Cloud DNS record in a pre-existing zone | $0 |
| LB data processing / egress at test volumes | cents |
| **Total while running** | **~$18–19/mo** |

The LB is the entire bill and it is a fixed cost — it does not go down with
traffic. Destroy the stack when you are not actively testing.

Global external ALBs are PREMIUM network tier only; there is no Standard-tier
variant to downgrade to. A regional external ALB would be marginally cheaper but
drags in Certificate Manager for managed certs and has a different IAP support
matrix — not worth it for a stack that should be short-lived.

## Blockers

### 1. Workforce identity pool — org-level IAM (OPEN)

`var.enable_workforce_federation` defaults to `false` because **the pool cannot
be created with the credentials available.**

Workforce pools are org-level: their parent is `organizations/860158542774`
(cru.org), not the project. Measured, not assumed:

```
POST cloudresourcemanager.googleapis.com/v1/organizations/860158542774:testIamPermissions
  {"permissions": ["iam.workforcePools.create", "iam.workforcePools.get",
                   "iam.workforcePools.delete", "iam.workforcePools.update",
                   "iam.workforcePoolProviders.create"]}
→ {}          # zero of five granted
```

`iam.workforcePools.list` on the org returns `403 PERMISSION_DENIED`. Matt has
**no** org-level IAM at all in this identity — not a partial grant.

**Needed from Matt:** one of

* `roles/iam.workforcePoolAdmin` on `organizations/860158542774` for the
  principal running this stack (narrowest sufficient grant), **or**
* someone with that role creates pool `cru-iap-e2e` + provider `okta` from this
  config and Terraform imports them, **or**
* a decision that live workforce federation is out of scope and the e2e settles
  for Google-identity IAP (which still exercises the verifier — the JWT is real
  and signed, it just carries a Google `email` claim rather than an Okta-sourced
  one).

The Terraform is written and plans cleanly either way:

```sh
terraform plan -var enable_workforce_federation=true    # 25 to add, renders fine
```

Note the mode difference: with a workforce pool the `email` claim comes from
Okta through the `google.email` mapping, and *whether it arrives at all* is the
open question the gem's README flags as **Unverified**. Google-identity mode
cannot answer that question. Clearing this blocker is the only way to.

### 2. Domain / DNS — CLEARED

Not a blocker after all. `matt-sandbox.ustech.app` is a public Cloud DNS zone in
the sandbox project, delegated from `ustech.app` in Route53, and its `NS`
delegation resolves. Terraform adds an A record there and Google issues a
managed cert against it. No domain was registered or purchased.

### 3. API enablement — CLEARED

All five required APIs (`compute`, `run`, `iap`, `iam`, `dns`) were **already
enabled** in the sandbox. None were enabled by this work. They are declared in
`apis.tf` anyway so the stack is self-contained if pointed at a fresh project.

## Okta hand-off

`locals.tf` reads `../okta/outputs.json` (non-secret app details) and
`../okta/secrets.json` (client secret, gitignored) if they exist, so the two
halves of the e2e compose without copy-paste. Explicit `okta_*` variables
override the files. The pool and provider ids default to whatever
`outputs.json` declares — they must match, because the Okta app's redirect URI
embeds them:

```
https://auth.cloud.google/signin-callback/locations/global/workforcePools/cru-iap-e2e/providers/okta
```

Two details in the provider config are load-bearing and must not be tidied away:

* `additional_scopes = ["email", "profile"]`. Google requests only `openid`
  otherwise, Okta's authorization server then omits the `email` claim,
  `google.email` has nothing to map, and the IAP JWT arrives with no identity.
* `google.email = assertion.email` in the attribute mapping. Same failure if
  dropped — this is gotcha 2 in the gem's README, hit live by beacon on
  2026-07-24.

`google.subject` maps to `assertion.sub` (the immutable Okta id) rather than the
email, so an Okta rename can't break `principal://…/subject/…` bindings.

### Two-phase apply for the IAM OAuth client

Inherited from cru-terraform, and Google's documented flow rather than a
Terraform limitation: `google_iam_oauth_client.allowed_redirect_uris` has to
embed the client id the **API generates** (a UUID, not the `oauth_client_id` you
choose), which doesn't exist until after the first create.

1. Apply with `wif_oauth_client_generated_id = ""` (a placeholder URI is used).
2. Copy the `wif_oauth_client_generated_id` output into that variable.
3. Apply again.
