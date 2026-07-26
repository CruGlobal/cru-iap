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

**One workspace is live: `wif`.** The `default` workspace — the original
Google-identity stack in Matt's sandbox — was **destroyed 2026-07-25** (20 resources,
verified: A record gone, `*.run.app` 404, state empty). It was strictly superseded by
`wif`, which is the same architecture plus real Okta federation, and each LB costs
~$18/month whether or not anyone uses it.

Everything below under "Google identities" describes that destroyed stack and is kept
because the verification table is still the reference for what a correct apply looks
like. `terraform workspace select default && terraform apply` recreates it.

| | `default` (destroyed) | `wif` (live) |
|---|---|---|
| Project | `cru-mattdrees-sandbox-poc` (cru.org) | `cru-iap-e2e-lb` (test.cru.org) |
| URL | <https://cru-iap-e2e.matt-sandbox.ustech.app/> | <https://cru-iap-wif.matt-sandbox.ustech.app/> |
| IAP mode | Google identities | Workforce federation → Okta SAML |
| Pool | — | `keepzero-okta-poc` (borrowed) |
| `IAP_AUDIENCE` | `/projects/178891842216/global/backendServices/3357314301240629663` | `/projects/898330966415/global/backendServices/2605597618877293205` |

`terraform output` is the source of truth; the values here are a convenience copy.
Applying `wif` needs `-var-file=wif.tfvars` and an access token for a `test.cru.org`
principal, since ADC is a `cru.org` identity:

```sh
terraform workspace select wif
terraform apply -var-file=wif.tfvars \
  -var access_token="$(gcloud auth print-access-token --account=phillip.drees@test.cru.org)"
```

### The destroyed Google-identity stack

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

## Access-denied page — measured live, it works

**Question:** can IAP redirect somewhere friendly when a user is authenticated but not
authorized — signed in through Okta fine, but not in the group that grants access?

**Answer: yes.** `IapSettings.applicationSettings.accessDeniedPageSettings
.accessDeniedPageUri`, exposed by the terraform provider as
`application_settings { access_denied_page_settings { … } }` and wired up here behind
`var.access_denied_page_uri` (default `""` = IAP's built-in page). Proven end to end on
2026-07-25 in this stack: the scratch user's
`roles/iap.httpsResourceAccessor` binding was removed, `access_denied_page_uri` was set
to `https://example.com/cru-iap-denied`, and a real headless Okta sign-in landed on
example.com rather than IAP's error page. `e2e/okta/probe_denied.mjs` is that probe,
kept so the result is reproducible rather than a claim in a README.

Six things the test established that the docs do not say:

1. **This is the authorization path only.** An *unauthenticated* request still goes to
   `auth.cloud.google/authorize`. The custom page is reached only after a successful
   sign-in that then fails the IAM check — which is exactly the "wrong Okta group"
   case, since group membership is expressed as a
   `principalSet://…/workforcePools/<pool>/group/<okta-group>` binding.
2. **No query parameters are appended. None.** The `Location` is the bare URI, even
   with `generate_troubleshooting_uri = true` set. The custom page learns *nothing*
   about who was denied or why — so it has to be a static "you don't have access, here
   is who to ask" page, or work the identity out for itself. Plan for that; it is the
   main constraint on how useful this is.
3. **The `Accept` header is ignored.** An `Accept: application/json` request gets the
   same `302` to a cross-origin URL, not a `401`. For a SPA or an API route behind IAP
   that means `fetch` follows the redirect and dies on CORS rather than seeing a status
   it can act on. Worth knowing before pointing this at a page on another origin.
4. **The `302` still carries IAP's default "Access Denied" HTML as its body.** Clients
   that follow redirects reach the custom page; clients that don't see the old one.
5. **IAM propagation is slow — well over 5 minutes.** The first probe, run immediately
   after removing the binding, sailed straight through to the app. Do not conclude
   "denial isn't working" from an immediate retest; wait, then retest.
6. **Google documents this as part of a paid enterprise security subscription**
   (Chrome Enterprise Premium). It nevertheless applied and was honoured in
   `test.cru.org` with nothing purchased for it. Either the org is entitled or the gate
   is not enforced on this field — **confirm entitlement before depending on it in
   production**, since "works in test" is not evidence about billing.

The stack has been restored to its documented state: no `accessDeniedPageSettings`, and
both principals back in `iap_members`.

```sh
# reproduce
terraform apply -var-file=wif.tfvars -var access_token="$TOK" \
  -var access_denied_page_uri="https://example.com/cru-iap-denied" \
  -var 'iap_members=["principal://…/subject/matt.drees@cru.org"]'   # drop the scratch user
sleep 360                                    # IAM propagation, see (5)
node ../okta/probe_denied.mjs
terraform apply -var-file=wif.tfvars -var access_token="$TOK"       # restore
```

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

## Capturing a real workforce IAP assertion

The `wif` workspace runs `gcr.io/google-containers/echoserver:1.10`, which echoes
every request header into the response body. Behind IAP only a signed-in user can
reach it, so this is safe here and is how the keep-zero POC's reference payload was
captured.

1. Open https://cru-iap-wif.matt-sandbox.ustech.app/?login=true in a browser.
   IAP redirects to `auth.cloud.google/authorize` with
   `provider_name=…/workforcePools/keepzero-okta-poc/providers/okta-preview-saml`,
   which hands off to Okta (cru.oktapreview.com). Sign in as a principal that holds
   `roles/iap.httpsResourceAccessor` — `iap_members` in `wif.tfvars`.
2. In the echoed output find `x-goog-iap-jwt-assertion`. That is the real thing.
3. Feed it to the verifier:

   ```ruby
   IAP_AUDIENCE=/projects/898330966415/global/backendServices/2605597618877293205 \
     ruby -Ilib -rcru_iap -e 'p CruIap::TokenVerifier.call(ARGV[0])' -- "<paste jwt>"
   ```

   Expect `ok?` true, `reason` `"iap_jwt"`, and `email` your Okta address — because
   `keepzero-okta-poc` maps `google.email`. Against a pool WITHOUT that mapping the
   same command returns `missing_email`, which is the whole point of the exercise.

Note the audience shape: LB-fronted IAP uses
`/projects/NUMBER/global/backendServices/ID`, while IAP directly on Cloud Run uses
`/projects/NUMBER/locations/REGION/services/NAME`. Don't copy one into the other.

Swap back to the hello sample by removing `container_image` from `wif.tfvars`.
