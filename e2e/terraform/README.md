# e2e/terraform — real IAP, in a sandbox

Stands up a genuine Google IAP path so the library can be exercised against live
infrastructure instead of fixtures:

```
client ──▶ global external HTTPS LB ──▶ backend service (IAP enabled) ──▶ serverless NEG ──▶ Cloud Run
                    │                            │
              Google-managed cert          workforce pool (optional)
```

This is a **standalone, disposable** stack: it owns its own load balancer, keeps
state locally, and is meant to live in a throwaway project for as long as you are
actively testing. Nothing here has defaults pointing at a real project — copy
`wif.tfvars.example` and supply your own.

No stack is currently deployed. The findings below were measured live before the
last one was destroyed, and are kept because they are the reason this config
exists rather than a fresh guess each time.

## Usage

```sh
cp wif.tfvars.example wif.tfvars     # then edit; wif.tfvars is gitignored
terraform init
terraform apply -var-file=wif.tfvars

terraform output iap_audience        # → export IAP_AUDIENCE=…
```

Teardown has one snag: `terraform destroy` fails with *"A credential can only be
deleted if it is disabled"* on the WIF variant. Disable the OAuth client credential
first, then destroy again:

```sh
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://iam.googleapis.com/v1/projects/PROJECT/locations/global/oauthClients/CLIENT/credentials/CRED?updateMask=disabled" \
  -d '{"disabled":true}'
```

State is **local** (`terraform.tfstate`, gitignored) — nothing else reads this
stack's outputs, so a remote backend would only add a stale-lock failure mode.

Credentials are ADC for a principal with Compute / Cloud Run / IAP / DNS admin.
If the compute project and the DNS zone are in different orgs, pass
`-var access_token=…` for the compute-side identity; the DNS record always uses
ADC, via the aliased provider in `terraform.tf`. Note that a bare service
account typically **cannot** apply this — it needs `compute.backendServices.create`
and friends, so use user ADC.

The managed certificate takes ~5 min to reach `ACTIVE` and the HTTPS frontend a
further ~1–2 min to serve; `000` / `SSL_ERROR_SYSCALL` in that window is expected,
not a misconfiguration.

## Verified properties

Confirmed live against a deployed stack:

| Check | Result |
|---|---|
| `GET https://<host>/` | `302` → IdP flow — IAP, not the app |
| `GET https://<host>/?login=true` | `302` → same IdP flow |
| Same request with a forged `x-goog-iap-jwt-assertion:` header | still `302` — IAP ignores the client-supplied header; the app is never reached |
| `GET http://<host>/` | `301` → `https://` |
| `GET https://<service>.run.app/` | `404` from the Google frontend — **no IAP bypass** |

That last row is the one worth re-checking after any change:

```sh
curl -i "$(terraform output -raw cloud_run_uri)"    # → 404 from GFE, never the app
```

It holds because `cloud_run.tf` sets
`ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"`. Any other value leaves the
raw `*.run.app` URL reachable with no IAP in front.

## The audience shape

`IAP_AUDIENCE` is a backend-service **resource path**, not a URL and not a client
id. It is a terraform output and is also injected into the container as an env
var, matching the contract the real deployment module uses.

The two IAP topologies have different shapes and they are not interchangeable:

```
LB-fronted IAP:          /projects/NUMBER/global/backendServices/ID
IAP directly on Cloud Run: /projects/NUMBER/locations/REGION/services/NAME
```

## Access-denied page — measured, it works

**Question:** can IAP redirect somewhere friendly when a user is authenticated but
not authorized — signed in fine, but not in the group that grants access?

**Answer: yes.** `IapSettings.applicationSettings.accessDeniedPageSettings
.accessDeniedPageUri`, exposed by the provider as
`application_settings { access_denied_page_settings { … } }` and wired up behind
`var.access_denied_page_uri` (default `""` = IAP's built-in page). Proven end to
end: the test user's `roles/iap.httpsResourceAccessor` binding was removed,
`access_denied_page_uri` was set, and a real headless sign-in landed on the custom
page rather than IAP's error page. `e2e/okta/probe_denied.mjs` is that probe, kept
so the result is reproducible rather than a claim in a README.

Six things the test established that the docs do not say:

1. **This is the authorization path only.** An *unauthenticated* request still goes
   to `auth.cloud.google/authorize`. The custom page is reached only after a
   successful sign-in that then fails the IAM check — which is exactly the "wrong
   group" case, since group membership is expressed as a
   `principalSet://…/workforcePools/<pool>/group/<group>` binding.
2. **Hardcoded query parameters survive; IAP appends none of its own.** A bare URI
   comes back bare. A URI with `?app=foo&reason=no_group&v=1` arrives in the
   `Location` header *verbatim*, query string intact — so static context (which
   app, who to ask, which group to request) can be encoded in the URI.

   What you cannot get is anything **dynamic**. IAP adds no identity, no denial
   reason, and — despite the setting — no troubleshooting link when
   `generate_troubleshooting_uri = true`. So the custom page can say "you need
   group X, ask #it-help", but it cannot say "*you*, alice@example.com, need it".
   If the page needs the identity it has to establish it itself. Plan around that;
   it is the real constraint on how useful this is.
3. **The `Accept` header is ignored.** An `Accept: application/json` request gets
   the same `302` to a cross-origin URL, not a `401`. For a SPA or an API route
   behind IAP that means `fetch` follows the redirect and dies on CORS rather than
   seeing a status it can act on.
4. **The `302` still carries IAP's default "Access Denied" HTML as its body.**
   Clients that follow redirects reach the custom page; clients that don't see the
   old one.
5. **IAM propagation is slow — well over 5 minutes.** A probe run immediately after
   removing the binding sailed straight through to the app. Do not conclude
   "denial isn't working" from an immediate retest; wait, then retest.
6. **Google documents this as part of a paid enterprise subscription** (Chrome
   Enterprise Premium). It nevertheless applied and was honoured with nothing
   purchased for it. Either the org was entitled or the gate is not enforced on
   this field — **confirm entitlement before depending on it in production**, since
   "works in test" is not evidence about billing.

```sh
# reproduce
terraform apply -var-file=wif.tfvars \
  -var access_denied_page_uri="https://example.com/denied" \
  -var 'iap_members=[]'          # drop the user whose access you're testing
sleep 360                        # IAM propagation, see (5)
node ../okta/probe_denied.mjs
terraform apply -var-file=wif.tfvars    # restore
```

## Which workforce mode

`enable_workforce_federation = true` federates IAP to a workforce pool. Where that
pool comes from depends on `shared_workforce_pool`:

| | `shared_workforce_pool = ""` (create) | `shared_workforce_pool` set (borrow) |
|---|---|---|
| Plan size | 25 to add | **3 to add** — OAuth client, credential, `google_iap_settings` |
| Org-level IAM | **required** (`iam.workforcePools.create`) | none |
| IdP side | the scratch app in `../okta` | that pool's existing app |
| Cleanup | pool id reserved 30 days after destroy | nothing org-level to clean up |

Borrowing is the mode to reach for. Workforce pools are org-level resources —
their parent is an organization, not a project — so creating one needs org-level
IAM a sandbox identity generally does not have, whereas borrowing needs only
project-level permission to *reference* a pool by name. Borrowing was measured to
work end to end with no org-level grant at all, which is the answer that matters
for consuming apps.

One hard constraint: **the pool and the project must share an org.** That is
usually what forces the compute side into whichever org owns the pool, and it is
why `dns_project` exists separately — the DNS zone does not have to follow.

### The mapping that makes or breaks it

`google.email` in the pool provider's `attribute_mapping` is load-bearing. Without
it the IAP assertion JWT carries **no email claim anywhere** and `sub` is an opaque
token, so the verifier rejects it with `missing_email`. Two details in the provider
config must not be tidied away:

* `additional_scopes = ["email", "profile"]` (OIDC). Google requests only `openid`
  otherwise, the IdP then omits the `email` claim, `google.email` has nothing to
  map, and the JWT arrives with no identity.
* `google.email` itself in the attribute mapping. Same failure if dropped.

`google.subject` maps to the immutable IdP subject rather than the email, so a
rename upstream can't break `principal://…/subject/…` bindings. Note the
consequence for `iap_members`: in OIDC mode the binding is
`/subject/<opaque idp id>`, while in SAML mode — where NameID is typically the
email — it is `/subject/<email>`.

Switching an already-applied stack into workforce mode **replaces** Google-identity
sign-in on the live URL. Expect to lose the Google-identity path while testing WIF.

### Two-phase apply for the IAM OAuth client

Google's documented flow, not a Terraform limitation:
`google_iam_oauth_client.allowed_redirect_uris` has to embed the client id the
**API generates** (a UUID, not the `oauth_client_id` you choose), which doesn't
exist until after the first create.

1. Apply with `wif_oauth_client_generated_id = ""` (a placeholder URI is used).
2. Copy the `wif_oauth_client_generated_id` output into that variable.
3. Apply again.

## Capturing a real IAP assertion JWT

The default container (`us-docker.pkg.dev/cloudrun/container/hello`) does not echo
request headers. Set `container_image = "gcr.io/google-containers/echoserver:1.10"`,
which echoes every request header into the response body. Behind IAP only a
signed-in user can reach it, which is what makes that safe here.

1. Open `https://<host>/?login=true` in a browser and sign in as a principal that
   holds `roles/iap.httpsResourceAccessor` — see `iap_members`.
2. In the echoed output find `x-goog-iap-jwt-assertion`. That is the real thing.
3. Feed it to the verifier:

   ```sh
   IAP_AUDIENCE="$(terraform output -raw iap_audience)" \
     ruby -Ilib -rcru_iap -e 'p CruIap::TokenVerifier.call(ARGV[0])' -- "<paste jwt>"
   ```

Expect `ok?` true, `reason` `"iap_jwt"`, and `email` your address — provided the
pool maps `google.email`. Against a pool without that mapping the same command
returns `missing_email`.

`spec/fixtures/real_wif_iap_payload.json` is a decoded capture from this path, kept
as ground truth for the claim shapes the offline suite mints synthetically. The
signature is deliberately not stored.

## Okta hand-off

`locals.tf` reads `../okta/outputs.json` (non-secret app details) and
`../okta/secrets.json` (client secret, gitignored) if they exist, so the two halves
of the e2e compose without copy-paste. Explicit `okta_*` variables override the
files. The pool and provider ids default to whatever `outputs.json` declares — they
must match, because the IdP app's redirect URI embeds them:

```
https://auth.cloud.google/signin-callback/locations/global/workforcePools/<pool>/providers/<provider>
```

## Labels

Every labelable resource carries `purpose=cru-iap-e2e`, `owner=<var.owner>`,
`temporary=true` via the provider's `default_labels`. Compute LB primitives
(backend services, URL maps, NEGs, proxies, forwarding rules) do not support labels
at all — those repeat the same attribution in `description`.

Find everything:

```sh
gcloud asset search-all-resources \
  --scope=projects/YOUR_PROJECT \
  --query='labels.purpose=cru-iap-e2e'
```

## Teardown

```sh
terraform destroy -var-file=wif.tfvars
```

That is the whole thing — no manual cleanup. Notes:

* **APIs are not disabled.** Every `google_project_service` sets
  `disable_on_destroy = false`, so a destroy can't rip Compute or Cloud Run out
  from under unrelated work in a shared sandbox.
* **The DNS zone survives.** It is pre-existing and read via a data source; only
  the A record is removed.
* **Workforce pools soft-delete for 30 days.** If you created rather than borrowed
  one, `terraform destroy` marks it deleted but the id stays *reserved* for 30 days.
  A re-apply with the same id inside that window fails. Change `local.wif_pool_id`
  — and the matching `workforce_pool_id` on the Okta side — to recreate sooner.
* The IdP app is **not** managed here. Tear it down via `e2e/okta/`.

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

The LB is the entire bill and it is fixed — it does not go down with traffic.
Destroy the stack when you are not actively testing.

Global external ALBs are PREMIUM network tier only; there is no Standard-tier
variant to downgrade to. A regional external ALB would be marginally cheaper but
drags in Certificate Manager for managed certs and has a different IAP support
matrix — not worth it for a stack that should be short-lived.
