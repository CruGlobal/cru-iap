# cru-iap

Request authentication for Cru apps behind **Google Identity-Aware Proxy**, with
Okta federated in via **Workforce Identity Federation**.

Extracted from [beacon](https://github.com/CruGlobal/beacon) after its 2026-07 IAP
cutover, ahead of the same cutover in cru-bot.

**Several libraries, one repo**, because Cru's apps behind IAP are Rails *and* Node
*and* FastAPI *and* Go, and the claim-shape knowledge below was expensive enough that
maintaining four copies of it would be a mistake:

```ruby
gem "cru_iap", github: "CruGlobal/cru-iap"
```
```sh
npm install github:CruGlobal/cru-iap                    # @cruglobal/cru-iap
uv add "cru-iap @ git+https://github.com/CruGlobal/cru-iap"
go get github.com/CruGlobal/cru-iap/cruiap
```

(Underscored gem name, hyphenated repo — so `Bundler.require` resolves straight to
`lib/cru_iap.rb` without a shim file. The npm package builds on install via `prepare`,
which is why a git install works without a registry. All install from the bare repo URL,
which is why each language's manifest sits at the root rather than in a subdirectory.)

| | Ruby | TypeScript | Python | Go |
|---|---|---|---|---|
| Source | `lib/` | `src/` | `cru_iap/` | `cruiap/` |
| Tests | `spec/` | `test/` | `tests/` | `cruiap/*_test.go` |
| Runtime dep | `googleauth` | `jose` | `pyjwt[crypto]` | **none** (stdlib) |
| Entry point | `CruIap::TokenVerifier.from_request` | `verifyRequest` | `verify_request` | `VerifyRequest` |
| Shared | `e2e/` (terraform + Okta), `spec/fixtures/real_wif_iap_payload.json` | | | |

All read the same pinned capture of a real Google assertion, so they cannot quietly
drift apart about what IAP actually sends. The rejection vocabulary is checked
mechanically too: the Python suite asserts its list matches Ruby's and TypeScript's, and
the Go suite asserts its own matches all three — so whichever language you add a reason
in, at least one suite goes red until the others catch up.

Which library a given app needs is not a free choice — it follows from the app. As of
2026-07: beacon and cru-bot are Rails; bills, cru-web-campaign and pingpong are Next.js;
dgt and dse-portal are FastAPI; wormhole is Go.

## What it does

| | |
|---|---|
| `CruIap::TokenVerifier` / `verify`, `verifyRequest` / `verify`, `verify_request` | Verify the IAP assertion JWT on a request; return an email identity or a typed rejection reason |
| `CruIap::StripForwardedHost` | Drop a client-forged `X-Forwarded-Host` before anything reads `request.host` (Ruby only — see below) |

No Rails or ActiveSupport dependency — `googleauth` only. The TypeScript package
depends only on `jose`, and touches no `node:` builtin, so it runs on the Edge runtime.
The Python package depends only on `pyjwt[crypto]` and imports no web framework, which
a test enforces in a subprocess so its own imports can't mask a leak.

## What this gem is *not*

It stops just past *"who is this?"*. It does not own your `User` model, your
session, your controller concern, how you render a rejection, or authorization.

### Where the line moved (2026-07)

The original line was "only the part that does not vary between apps". At two
consumers that was right. At seven it was measurably wrong: five decisions had
been re-derived per app, and two came out broken.

So two things moved *in*, as **primitives** — pure functions with no framework
coupling — rather than as glue:

| | why it moved |
|---|---|
| [`Urls`](#the-two-iap-control-urls) — `login_url` / `logout_url` | Four apps re-typed them. Getting sign-in wrong is an infinite redirect loop; getting sign-out wrong silently re-authenticates the same person. It was a README checklist item, i.e. prose people had to re-read correctly. |
| [`DevBypass`](#the-dev-bypass) | Three apps, three incompatible shapes, one incident: a bypass whose flag defaulted to the **insecure** value, so forgetting to set it disabled auth. |

Deliberately still out: anything with a session or a rendering opinion. The
evidence says these genuinely differ — beacon serves two hosts from one process,
flightdeck is an OAuth provider with its own cookie session, dgt keeps a session
purely for CSRF. One opinionated concern would fit none of them.

The original two-consumer comparison, which is still the reason for the line: 

| | beacon | cru-bot |
|---|---|---|
| Hosts | dual; trust the header only on the admin host | single host |
| Rejection | HTML redirect | HTML redirect **+ JSON 401** |
| Authz | `BEACON_ADMINS` env var | `User#role` in the DB |
| Dev bypass | implicit stub on every request | explicit `/dev_login` route |
| Domain gate | dropped (the pool enforces it) | `hd: "cru.org"` |
| ActionCable | none | `Connection` authenticates the WS upgrade |

Generalizing any of that on a two-app sample would be guessing. Copy the wiring
below and adapt it.

## Usage (Ruby)

### 1. Configure

```ruby
# config/initializers/iap.rb
CruIap.logger = Rails.logger
```

`IAP_AUDIENCE` is read from the environment by default. It is a **resource path**, not
a URL and not a client ID, and its shape depends on how IAP is fronted:

| IAP mode | `aud` |
|---|---|
| Behind an external HTTPS load balancer | `/projects/NUMBER/global/backendServices/BACKEND_ID` |
| Directly on Cloud Run (no LB) | `/projects/NUMBER/locations/REGION/services/SERVICE_NAME` |

Both are confirmed against live services. The verifier doesn't care which — it's an
exact string compare — but a deploy that hardcodes the wrong *shape* fails with
`audience_mismatch`, which reads like a config typo rather than an architecture
mismatch.

cru-terraform sets this for you. Don't rename it with an app prefix; the terraform
module supplies it under that exact name.

**IAP directly on Cloud Run is worth knowing about**: it needs no load balancer,
no certificate, and no DNS, which takes a test or low-traffic environment from
~$18/month (the LB forwarding-rule bundle, billed regardless of traffic) to
effectively zero. Set `run.googleapis.com/iap-enabled: 'true'` on the service and
point `iapSettings` at your workforce pool.

### 2. Install the middleware

```ruby
# config/application.rb
config.middleware.insert_before 0, CruIap::StripForwardedHost
```

### 3. Verify

```ruby
result = CruIap::TokenVerifier.from_request(request)

if result.ok?
  user = User.from_iap(email: result.email, name: result.name)
else
  Rails.logger.warn("IAP auth rejected: #{result.reason}")
  nil # fail closed — never fall through to a dev stub
end
```

`from_request` takes an `ActionDispatch::Request`, a `Rack::Request`, or a bare Rack
env hash, and pulls the assertion off it — application code never names the header.
If you need the wire name for infra config or a test fixture, it's
`CruIap::TokenVerifier::HEADER`.

Both `from_request` and the lower-level `.call(token)` accept `audience:` and
`logger:` overrides if you'd rather not use the env var / global logger.

### Reference wiring (Rails controller)

```ruby
# Resolve once per request: the failure path must not re-verify the JWT and
# re-log the rejection on every current_user call site.
def current_user
  return @identity.user if defined?(@identity)
  @identity = resolve_identity
  @identity.user
end

def resolve_identity
  # Only trust the header on a host IAP actually fronts. On any other host —
  # a second backend, or a direct *.run.app hit — there is no IAP in front to
  # strip a client-supplied header, so ignore it rather than verify it.
  if iap_fronted_host? && CruIap::TokenVerifier.assertion_from(request)
    return Identity.new(user: user_from_iap(request), dev_stub: false)
  end
  return Identity.new(user: DevAuthStub.user, dev_stub: true) if Rails.env.local?

  Identity.new(user: nil, dev_stub: false)
end
```

## Usage (TypeScript)

`IAP_AUDIENCE` works exactly as above — same env var, same two shapes, same
fail-closed-if-unset rule. It is read at *call* time, not import time.

```ts
import { verifyRequest } from "@cruglobal/cru-iap";

const result = await verifyRequest(request);

if (result.ok) {
  const user = await provisionUser({ email: result.email, name: result.name });
} else {
  console.warn(`IAP auth rejected: ${result.reason}`);
  // fail closed — never fall through to a dev stub
}
```

`result` is a discriminated union, so `result.email` narrows to `string` inside the
`ok` branch and `null` outside it. `verifyRequest` accepts a Web `Request` or
`Headers` (Next.js route handlers, middleware, Edge), a Node `IncomingMessage`
(Express, a custom server), or a plain header record — application code never names
the header. `verify(token)` is the lower-level form.

Both take `{ audience, logger, jwks, clockToleranceSeconds }` overrides.

### Reference wiring (Next.js middleware)

Middleware is the right seam: one gate for every route, and it runs before any page or
route handler allocates work for a request that is about to be rejected.

```ts
// middleware.ts
import { NextResponse, type NextRequest } from "next/server";
import { verifyRequest } from "@cruglobal/cru-iap";

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };

export async function middleware(request: NextRequest) {
  // Gate on deploy config, never on the header being absent. "No header →
  // local stub" is the one fallback that must be impossible in production.
  if (!process.env.IAP_AUDIENCE) return NextResponse.next();

  const result = await verifyRequest(request);
  if (!result.ok) {
    console.warn(JSON.stringify({ message: "iap_rejected", reason: result.reason }));
    return new NextResponse("Unauthorized", { status: 401 });
  }

  // Hand the identity downstream rather than verifying again per route. These
  // are request headers we are setting on the INBOUND request, so they are not
  // client-controllable — the middleware overwrites whatever arrived.
  const headers = new Headers(request.headers);
  headers.set("x-cru-iap-email", result.email);
  return NextResponse.next({ request: { headers } });
}
```

Two Next.js-specific notes:

- **Middleware runs on the Edge runtime by default**, which has no `node:crypto` and no
  outbound support for most Node-only libraries. That is the reason this package is
  built on `jose` (WebCrypto) rather than `google-auth-library`.
- **There is no `StripForwardedHost` equivalent, deliberately.** The Rack middleware
  exists because beacon gates on `request.host` and inserts itself at position 0,
  before anything resolves it. Next.js has no comparable slot, and its host handling is
  configuration (`trustHost`, `allowedDevOrigins`) rather than a middleware you can
  precede. If your app makes a security decision from the host, make it from an
  allow-list you control, not from `x-forwarded-host`.

### Replacing Auth.js / next-auth

For an app currently doing its own Okta OIDC (bills, as of 2026-07), the IAP cutover
deletes the provider rather than reconfiguring it: no `NextAuth()` call, no
`/api/auth/[...nextauth]` route, no `OKTA_CLIENT_SECRET`, no callback URL, and no
`trustHost` (which only existed to build those callback URLs behind the ALB). What
remains is the middleware above plus whatever `provisionUser` already did on first
sign-in. Session strategy, roles, and authorization are untouched — this library stops
at *"who is this?"*.

## Usage (Python)

`IAP_AUDIENCE` works exactly as above — same env var, same two shapes, same
fail-closed-if-unset rule. It is read at *call* time, not import time.

```python
from cru_iap import verify_request

result = verify_request(request)

if result.ok:
    user = provision_user(email=result.email, name=result.name)
else:
    log.warning("IAP auth rejected: %s", result.reason)
    # fail closed — never fall through to a dev stub
```

`Result` is a frozen dataclass (so a caller can't launder a rejection into a pass by
assignment) and is truthy when `ok`, so `if verify_request(request):` reads fine too.
`verify_request` accepts a Starlette/FastAPI `Request`, a Django `HttpRequest` (via
either `.headers` or `.META`), a Flask/Werkzeug `request`, a bare WSGI `environ`, or a
plain header mapping — application code never names the header. `verify(token)` is the
lower-level form.

Both take `audience`, `jwks`, `leeway_seconds` and `log` keyword overrides.

Two Python-specific notes:

- **The verifier is synchronous**, because PyJWT and its key fetch are. In FastAPI,
  declare the dependency with `def` rather than `async def` and FastAPI runs it in a
  threadpool automatically — which is what you want, since an `async def` dependency
  would block the event loop on the once-an-hour JWKS refresh.
- **Logging follows the Python convention** rather than the gem's `CruIap.logger =`
  setter. The package logs to `logging.getLogger("cru_iap")` with a `NullHandler`
  attached, so it is silent until your app configures logging and there is no global to
  set.

### Reference wiring (FastAPI dependency)

The dependency is the right seam: one gate, applied per-router or app-wide, resolved
once per request by FastAPI's own dependency cache.

```python
# backend/auth.py
from fastapi import Depends, HTTPException, Request
from cru_iap import verify_request

def current_user(request: Request) -> User:
    # Gate the dev bypass on deploy config, never on the header being absent.
    # "No header → local stub" is the one fallback that must be impossible in
    # production.
    if not settings.iap_audience:
        return dev_stub_user()

    result = verify_request(request)
    if not result.ok:
        log.warning("iap_rejected reason=%s", result.reason)
        raise HTTPException(status_code=401, detail="Unauthorized")

    return provision_from_iap(email=result.email, name=result.name)
```

### Replacing authlib's Okta OIDC

For an app currently doing its own Okta OIDC through authlib (dgt and dse-portal, as of
2026-07), the cutover deletes the client rather than reconfiguring it: no
`oauth.register(name="okta", …)`, no `/auth/oktaoauth/login` or `/callback` route, no
`OKTA_CLIENT_SECRET`, no `OKTA_REDIRECT_URI`, and — if nothing else uses it — no
`SessionMiddleware` or `SESSION_SECRET`, since there is no longer a session cookie to
sign. What remains is the dependency above plus whatever the callback already did on
first sign-in.

One thing that does *not* survive: both apps currently reason *"any session that exists
is an allowed user, because Okta only lets assigned users complete the flow."* That
inference still holds under IAP, but the enforcement moves — it becomes the
`roles/iap.httpsResourceAccessor` binding in cru-terraform rather than the Okta app
assignment. Read gotcha 8c before assuming the group is still visible app-side; it
isn't.

## Usage (Go)

`IAP_AUDIENCE` works exactly as above — same env var, same two shapes, same
fail-closed-if-unset rule. It is read at *call* time, not package-init time.

```go
import "github.com/CruGlobal/cru-iap/cruiap"

result := cruiap.VerifyRequest(ctx, request)

if result.OK {
    user, err := provisionUser(ctx, result.Email, result.Name)
} else {
    logger.Warn("IAP auth rejected", "reason", result.Reason)
    // fail closed — never fall through to a dev stub
}
```

`Verify` and `VerifyRequest` **never return an error and never panic** — every path
returns a `Result`, and a `recover` backstop turns an unanticipated panic into
`unexpected_error`. That is deliberate: an authentication check must not become a panic
that a recover middleware renders as a 500, or that some upstream error path swallows
into a pass. Options are `WithAudience`, `WithKeySource`, `WithLogger`,
`WithClockTolerance` and `WithClock`.

### This one is stdlib-only, unlike its siblings

The other three lean on their ecosystem's JWT library. This one deliberately does not:

- **wormhole**, the only consumer as of 2026-07, already contains a stdlib-only OIDC
  verifier (`internal/oidcverify`) that makes and documents the same choice. Adding a
  dependency here to replace a dependency-free implementation there would be a net loss.
- **ES256 verification is genuinely small in Go** — base64url and JSON for the envelope,
  `crypto/ecdsa` for the signature. Nothing here implements a cryptographic primitive.
- **The reason vocabulary is better served without a translation layer.** Each sibling
  had to reverse-engineer its library's error taxonomy, and two of the uglier notes in
  this README exist because of it: jose reporting a non-200 JWKS as its base error class,
  `PyJWKClient` using one error type for two unrelated faults separable only by message.
  Here every condition is raised where it is detected, so the mapping is exact.

The tradeoff, stated plainly: the JWS envelope parsing and claim checks are this
package's own rather than a widely-audited library's. That is why the suite pins the
failure modes a JWT library would otherwise be trusted for — alg confusion across six
`alg` values including `none`, a truncated and an over-long signature, a public key that
is not on the curve, and an `exp` that is absent rather than merely past.

Two Go-specific notes:

- **JWS ES256 signatures are the fixed-width `r||s` form** (RFC 7515 A.3), 32 bytes
  each — *not* the ASN.1 DER encoding `ecdsa.VerifyASN1` expects and most non-JOSE
  tooling produces. Getting this wrong fails closed, which is the safe direction, but it
  is the single most common mistake in a hand-written JWS verifier.
- **`bad_iss:` is unreachable here, by construction.** The siblings get an issuer check
  from their JWT library and then re-assert, emitting `bad_iss:` if the library ever
  stopped checking. There is no library to distrust, so the single check emits
  `issuer_mismatch`. A test records that, so the gap reads as a decision rather than an
  oversight.

### Reference wiring (net/http middleware)

```go
func RequireIAP(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Gate the dev bypass on deploy config, never on the header being absent.
        if os.Getenv("IAP_AUDIENCE") == "" {
            next.ServeHTTP(w, r.WithContext(withUser(r.Context(), devStubUser())))
            return
        }

        result := cruiap.VerifyRequest(r.Context(), r)
        if !result.OK {
            slog.Warn("iap_rejected", "reason", result.Reason, "path", r.URL.Path)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r.WithContext(withEmail(r.Context(), result.Email)))
    })
}
```

## Primitives

Two pure functions, in all four languages, that every consumer was otherwise
re-deriving. Neither touches a request, a session, or a framework — so they
compose into whatever wiring an app already has, in one line.

### The two IAP control URLs

```ruby
CruIap.login_url                      # => "/?login=true"
CruIap.login_url("/dashboard?tab=1")  # => "/dashboard?tab=1&login=true"
CruIap.logout_url("/bye")             # => "/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE"
```

```ts
import { loginUrl, logoutUrl } from "@cruglobal/cru-iap";
```

```python
from cru_iap import login_url, logout_url
```

```go
cruiap.LoginURL("/dashboard")  // "/dashboard?login=true"
cruiap.LogoutURL("")           // "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE"
```

Why not an interpolated string at the call site — every one of these is a real
mistake someone has made or would:

- **Bare `/` for sign-in loops forever.** IAP sends `/` to the IdP, the IdP sends
  it back to `/`. The most-reported IAP footgun at Cru.
- **Sign-out without the cookie-clear mode doesn't sign anyone out.** The app's
  session goes away, IAP's federated login cookie does not, and the next request
  signs the same person straight back in.
- **A fragment must stay last.** `"/a#b"` with `"?login=true"` appended naively
  gives `"/a#b?login=true"`, where the param is inside the fragment and never
  reaches the server.
- The separator depends on whether a query is already there, and both helpers are
  idempotent.

The two query literals are Google's, and a typo in one language is a silent
failure in that language only — so they are cross-checked across all four by a
test (`cruiap/vocabulary_test.go`).

### The dev bypass

```sh
CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org bin/rails server
```

Compose it in front of the real verify. One line, no branch:

```ruby
result = CruIap.dev_bypass || CruIap::TokenVerifier.from_request(request)
```

```ts
const result = devBypass() ?? (await verifyRequest(request, { audience }));
```

```python
result = dev_bypass() or verify_request(request, audience=audience)
```

```go
result, bypassed := cruiap.DevBypass()
if !bypassed {
    result = cruiap.VerifyRequest(ctx, r, cruiap.WithAudience(audience))
}
```

Putting it first is safe, which is the whole design:

**There is no boolean.** A flag has a wrong default, and `AUTH_ENABLED` defaulting
to the open value is exactly the incident this replaces. An identity-carrying
variable has no wrong default — either you name a developer to be, or you don't,
and *unset can only mean no bypass*. There is also no `dev_bypass_enabled = true`
setter, because anything an app can set in a config file, an app can set in
production config.

**Two independent guards**, neither depending on the app being written correctly:

1. `IAP_AUDIENCE` set → refuse. cru-terraform injects it into every IAP-fronted
   container, so the bypass cannot coexist with the config that means "this is a
   real IAP environment".
2. A cloud-runtime marker (`K_SERVICE`, `K_REVISION`, `GAE_ENV`,
   `FUNCTION_TARGET`) → refuse. The platform sets these; nobody has to remember
   to, which is what makes them trustworthy.

They are independent on purpose: a deploy that somehow lost `IAP_AUDIENCE` is
still refused on Cloud Run.

It returns `dev_bypass`, a reason in the [shared vocabulary](#rejection-reasons),
so a bypassed request is queryable in Datadog rather than invisible. The
configured address must pass the same shape gate as a real identity — including a
rejection of namespaced values like `sts.google.com:you@cru.org`, which are a
copy-paste out of a JWT rather than an address. And it warns on **every**
activation: a bypass that logs once is a bypass someone forgets is on.

### Host resolution per framework

`StripForwardedHost` exists because **Rails resolves `request.host` from
`X-Forwarded-Host` before `Host`**. GCLB preserves `Host` and never sets
`X-Forwarded-Host`, so a present value is always client-forged. Any app keying
behaviour off `request.host` — "only trust the IAP header on the host IAP fronts",
host-constrained routes — can otherwise be steered by a header.

It is **not** a universal need. Checked per runtime:

| | prefers `X-Forwarded-Host`? | action |
|---|---|---|
| Rails | **yes** (`ActionDispatch::Http::URL#raw_host_with_port`) | `CruIap::StripForwardedHost` at position 0 |
| Next.js | **yes** — `parseHostHeader` prefers it for the Server Actions CSRF check, and `base-server` sets it with `??=`, so a client value survives (verified in Next 16.2) | strip at the edge, and/or set `serverActions.allowedOrigins` |
| FastAPI / Starlette | no — host comes from the ASGI scope; uvicorn's proxy handling covers `X-Forwarded-For`/`-Proto`, not Host | none needed |
| Go `net/http` | no — `r.Host` comes from the request line / `Host` header | none needed |

Identity is never forgeable this way — the assertion is signed — so this protects
the routing layer, not authentication.

## Deployment checklist

- [ ] `IAP_AUDIENCE` set from the terraform module output
- [ ] Cloud Run ingress restricted to the load balancer. **At Cru this is terraform's
      job, not the deploy's** — `cru-terraform-modules gcp/cloudrun/app` derives it
      from `load_balancer_strategy`, and the default (`"shared"`) already gives you
      `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` + `default_uri_disabled = true`. There
      is no `--ingress` flag anywhere in the deploy chain to set, so don't go looking
      for one. Verify the deployed service rather than assuming either way; if
      `load_balancer_strategy = "run.app"`, ingress is `INGRESS_TRAFFIC_ALL` and the
      raw `*.run.app` URL reaches the app with **no IAP in front**.
- [ ] Regardless of ingress, every route must fail closed on a missing header, and a
      "no header → dev stub" fallback must be impossible in production. Use
      [`DevBypass`](#the-dev-bypass) rather than a hand-rolled flag — it has no
      boolean to get backwards, and refuses in any managed runtime.
- [ ] `CruIap::StripForwardedHost` inserted at position 0 (Rails), or the equivalent
      for Next.js — see [host resolution](#host-resolution-per-framework). Go and
      FastAPI need nothing.
- [ ] Sign-in CTA built with `login_url` — **not** a hand-written `/`. Bare `/` loops.
- [ ] Sign-out built with `logout_url`, so IAP clears the federated login cookie
- [ ] Production logs emitted as JSON with a `severity` field, or Cloud Run drops
      Rails' stdout from the log sink and you'll debug the cutover blind
- [ ] Every surface that authenticates *itself* is listed in the module's `bypass_paths`,
      not just exempted in app code — see below
- [ ] Decide what an *authorized-but-not-permitted* user sees — see below

## Surfaces that authenticate themselves need `bypass_paths`

An app-side exemption is **not enough on its own**, and this is the constraint most
likely to take a cutover down. IAP rejects at the load balancer, before your gate runs:
a webhook, a cron POST, or an OAuth token endpoint never reaches the middleware that
would have waved it through. It gets IAP's 401 or a 302 to an Okta sign-in page it
cannot complete, because there is nobody at a browser.

So each one needs a path prefix in `bypass_paths` on
`cru-terraform-modules gcp/cloudrun/app`, which routes it to the public backend service
and skips both IAP and the sign-in redirect:

```hcl
iap = {
  members      = ["principalSet://…/group/Flightdeck:Users"]
  bypass_paths = ["/api/", "/oauth/", "/.well-known/", "/up"]
}
```

The two halves are not redundant — they answer different questions. `bypass_paths`
decides *what reaches the app*; the app-side exemption decides *what the app does with
what arrives*, since a bypassed path gets no assertion header and must fall back to its
own credential (a PAT, a signing secret, an OIDC token it verifies itself). Omit the
terraform half and the surface is unreachable; omit the app half and it is unauthenticated.

Worth enumerating deliberately, because the list is longer than it first looks. Bills
had nine: SCIM, the MCP OAuth authorization server, its metadata document, the MCP
transport, Slack, Cloud Scheduler, the public API, the health probe, and
`/bill/<token>` for external recipients. Flightdeck has a comparable set — a Doorkeeper
OIDC provider, a PAT-authenticated API, and Slack callbacks. A useful way to find them:
every route your *old* auth already skipped is a candidate, and so is every client that
holds a credential rather than a session.

## The access-denied page (authenticated, but not authorized)

IAP can redirect a user who signed in successfully but holds no
`roles/iap.httpsResourceAccessor` binding — the "you're at Cru, but you're not in the
right Okta group" case — to a page you control, instead of its own bare error page.
Set `applicationSettings.accessDeniedPageSettings.accessDeniedPageUri`; in terraform,
`google_iap_settings` exposes it as
`application_settings { access_denied_page_settings { access_denied_page_uri = … } }`.

**Proven live** on 2026-07-25 against a real Okta → WIF → IAP sign-in; see
`e2e/terraform/README.md` for the reproduction. Five constraints the docs don't
mention, all measured rather than assumed:

| | |
|---|---|
| Scope | **Authz only.** An unauthenticated request still goes to `auth.cloud.google/authorize`; this page is only reached after a successful sign-in that fails the IAM check. |
| Parameters | **Yours survive; IAP adds none of its own.** A URI with `?app=bills&reason=no_group` arrives verbatim in the `Location`, so you can encode the app, a support contact, or the group to request. What you cannot get is anything *dynamic* — no identity, no reason, and no troubleshooting link even with `generate_troubleshooting_uri = true`. Static context only. |
| `Accept` | **Ignored.** An XHR asking for JSON gets the same cross-origin `302`, so `fetch` follows it and fails on CORS rather than seeing a status it can handle. |
| Body | The `302` still carries IAP's default "Access Denied" HTML, for clients that don't follow redirects. |
| Entitlement | Google documents this as part of a paid enterprise subscription. It worked in `test.cru.org` with nothing bought for it — **confirm before relying on it in production.** |

And one operational note that will waste your afternoon otherwise: **IAP IAM changes
take well over five minutes to propagate.** A binding you just removed will still let
the user straight through. Wait before concluding the denial path is broken.



## Gotchas this gem encodes

Notes from beacon's cutover, kept here because they cost real deploy cycles:

1. **`email` is the identity in every mode. `sub` never is.** Confirmed 2026-07-24
   from a captured live payload (keep-zero POC echoserver) and from beacon-stage logs
   on both sides of the attribute-mapping fix:

   | | `email` claim | `sub` claim |
   |---|---|---|
   | Plain IAP (Google/Cloud Identity) | bare address, no prefix | `accounts.google.com:<opaque id>` |
   | WIF, `google.email` mapped | bare address | `sts.google.com:<opaque STS token>` |
   | WIF, mapping absent | **absent entirely** | `sts.google.com:<opaque STS token>` |

   There is no mode in which `sub` yields a usable identity, so a `sub` fallback buys
   nothing and costs diagnostic clarity — see the next item.

2. **A workforce JWT with no `email` means a missing `google.email` attribute
   mapping** on the pool provider (and upstream of that, a missing `email` attribute
   statement on the Okta app). Nothing app-side can recover the address — `sub`
   carries none. Report it as `missing_email`, which names the actual remedy. Beacon
   shipped a `sub` fallback during its cutover and it downgraded that accurate
   diagnosis into a misleading `malformed_subject`, sending the next reader hunting a
   principal shape that does not exist.

3. **`principal://…` is NOT in `email` or `sub`.** The workforce principal URI is
   real, but it lives in the nested `workforce_identity.iam_principal` claim — it is
   the string IAM bindings match, not an identity. A verifier that unwraps it out of
   `email`/`sub` is handling a shape IAP never emits, and is *accepting* a value it
   would otherwise correctly reject. The WIF payload also carries
   `identity_source: "WORKFORCE_IDENTITY"` if you need to branch on federated vs.
   Google sessions.

4. **Split on the first colon; never match a literal prefix.** A real email never
   contains one, so a leading `<prefix>:` is always the IAP namespace. Observed
   prefixes: `accounts.google.com:`, `sts.google.com:`, and Identity Platform's
   `securetoken.google.com/<project>/<tenant>:`.

5. **`URI::MailTo::EMAIL_REGEXP` is not a sufficient shape gate on its own.** RFC 5322
   permits `/` in a local part, so a URI-shaped value ending in an address would be
   persisted as a user whose email is that entire string. Reject anything containing a
   slash as well.

   Worth being precise about the interaction with gotcha 4, because it is the part
   that surprises: the *raw* `principal://iam.googleapis.com/.../subject/alice@cru.org`
   fails the regexp, but only because of the `principal:` scheme colon — and the
   verifier strips everything up to the first colon before validating, since that is
   how it removes the `accounts.google.com:` namespace. What survives that strip,
   `//iam.googleapis.com/.../subject/alice@cru.org`, **does** match. Each guard looks
   redundant on its own; together they are not. There is a test in each language
   asserting exactly this, with the regexp match as a negative control.

6. **Keep `malformed_subject` and `missing_email` distinct.** Nothing arrived, vs.
   something arrived that is not an address: different root causes, different fixes.

7. **Fail closed when `IAP_AUDIENCE` is unset** rather than skipping the audience
   check.

8. **Require `exp`; don't just validate it.** The `jwt` gem's `verify_expiration` is a
   no-op when the claim is *absent*, and googleauth adds no freshness floor — so a
   validly signed assertion carrying no `exp` is accepted forever by the rest of the
   stack. Not attacker-reachable (minting one needs Google's IAP signing key), but the
   verifier shouldn't depend on IAP always setting it. Same class of trap as gotcha 5:
   a validator that silently passes on missing input.

   **`jose` and `PyJWT` have the identical hole** — both skip the expiry check when `exp`
   is absent rather than failing — so the TypeScript side passes
   `requiredClaims: ["exp"]` and the Python side `options={"require": ["exp"]}`. That is
   now **three independent JWT libraries in three languages making the same choice**,
   which stops being a coincidence and starts being the default you should expect.
   Assume the next one does too, and check rather than trust: each language's suite
   carries a negative-control test that verifies the token *without* the requirement and
   asserts it is accepted, so the guard is provably load-bearing rather than decorative.

8b. **Don't coerce the `email` claim to a string in JavaScript.**
   `String(["alice@cru.org"])` is `"alice@cru.org"`, so a multi-address array claim
   would coerce into a single accepted identity. Ruby's `Array#to_s` renders the
   brackets and rejects, which is why the Ruby verifier can safely `.to_s` and the
   TypeScript one cannot. Python's `str()` renders the brackets like Ruby's, so it would
   also have rejected — but the Python verifier still checks `isinstance(raw, str)`
   explicitly, because relying on `repr()` for a security decision is a coincidence
   rather than a design. A shape gate is only as good as what it is handed.

8c. **The assertion carries no group membership.** There is no `groups` claim, and
   nothing in the payload from which one can be derived — see
   `spec/fixtures/real_wif_iap_payload.json`, whose entire top-level claim set is
   `aud`, `azp`, `email`, `exp`, `iat`, `identity_source`, `iss`, `sub`, and the nested
   `workforce_identity`. This is the single most expensive difference from an Okta OIDC
   `id_token`, because a `groups` claim is how most of Cru's apps currently answer
   *"may this person be here?"*:

   | app | how it gated before IAP | what it must use after |
   |---|---|---|
   | flightdeck | `OKTA_REQUIRED_GROUP=Flightdeck:Users` from a `groups` claim | a DB or env authz source |
   | dgt, dse-portal | Okta app assignment — *"any session that exists is allowed"* | the IAP IAM binding, same reasoning |
   | beacon | `BEACON_ADMINS` env var | unchanged |
   | cru-bot | `User#role` in the DB | unchanged |

   The mitigation is that the *coarse* gate moves into infrastructure rather than
   disappearing: `roles/iap.httpsResourceAccessor` accepts
   `principalSet://…/group/<okta-group>`, so "must be in `Flightdeck:Users`" becomes an
   IAM binding in cru-terraform and IAP enforces it before the app is reached. What you
   cannot do app-side is make a *finer* decision from the group — read a role, branch on
   department, show a different nav — because the app can no longer see the membership
   that got the request through the door. Apps that need that must keep their own store.

   Note the failure mode is silent and open, not closed: `claims["groups"]` is simply
   `nil`, so a port that keeps its old `required_group.in?(claims["groups"])` check
   rejects everyone, while one that keeps `claims["groups"]&.include?` or an
   `unless groups.blank?` guard admits everyone. Grep for the group claim by name during
   a cutover rather than trusting the tests to catch it.

9. **Load-balancer 302s masquerade as Rails redirects** when you are reading logs
   during a cutover. Check which layer actually issued them.

10. **Get logs flowing before you theorize.** Two of the wrong turns above were guesses
   written while Rails stdout was not reaching Datadog at all — the commit claiming a
   shape was "observed live" predated log visibility by 25 minutes. Fixing the
   telemetry is cheaper than a deploy cycle.

## Rejection reasons

`CruIap::TokenVerifier::REASONS` / `REASONS` is the shared vocabulary — shared across
*every language here*, so every app behind IAP files the same Datadog queries whether it
is Rails, Node, FastAPI or Go. Entries ending in `:` carry a variable suffix.

`missing_token` · `missing_audience_config` · `bad_iss:` · `missing_exp` ·
`missing_email` · `malformed_subject` · `signature_error:` · `audience_mismatch` ·
`expired_token` · `issuer_mismatch` · `verification_error:` · `unexpected_error` ·
`iap_jwt` · `dev_bypass`

Two reasons are successes: `iap_jwt` (a verified assertion) and `dev_bypass`
([the dev bypass](#the-dev-bypass), unreachable in a managed runtime). Everything
else is a rejection. `dev_bypass` is in the vocabulary precisely so a bypassed
request shows up in the same Datadog queries as a real one instead of being
invisible.

A test in each language asserts its verifier can only produce listed reasons, so the
vocabulary can't drift silently within a language. Across languages, the **Python suite
parses the Ruby and TypeScript lists out of their source and asserts all three are
identical**, and the **Go suite checks all three against its own** — so a reason added
in one place and forgotten in another fails there. The comparison is
element-by-element, so add a reason in every language at once, **in the same
position**.

These mappings are worth knowing because the underlying libraries differ:

| condition | Ruby (googleauth) | TypeScript (jose) | Python (PyJWT) | Go (stdlib) |
|---|---|---|---|---|
| token's `kid` not in the JWKS | `signature_error:Token not verified as issued by Google` | `signature_error:no_matching_key` | `signature_error:no_matching_key` | `signature_error:no_matching_key` |
| JWKS unreachable / non-200 / unparseable | `verification_error:KeySourceError` | `verification_error:KeySourceError` | `verification_error:KeySourceError` | `verification_error:KeySourceError` |
| wrong `iss` | `issuer_mismatch`, or `bad_iss:` from the re-assert | same | same | `issuer_mismatch` only — see the Go section |

PyJWT needs the same care as jose here for the same reason: `PyJWKClient` raises the
plain base `PyJWKClientError` for two unrelated conditions — no matching `kid`, and a
JWKS that fetched but wouldn't parse — distinguishable only by message. The connection
case has its own subclass (`PyJWKClientConnectionError`), so only those two share a
class, and the message check that separates them is pinned by a test.

jose reports a non-200 JWKS response as its *base* `JOSEError` class. Keying off that
looks alarmingly broad, so it was checked: those are the only two sites in the whole
library that throw the bare base class (jose 6.2), and both are this exact condition.

## Logging

The verifier is silent except for two `warn`s: `malformed_subject` (which dumps the
full JWT payload, so an unexpected principal shape is diagnosable without
re-deploying instrumentation) and the fail-closed catch-all. The payload is identity
claims, not credentials — the same sensitivity as the emails already in your request
logs. It defaults to a null logger until you set `CruIap.logger` / pass `logger:` /
pass `log=`; in Python it logs to `logging.getLogger("cru_iap")` with a `NullHandler`
attached, so configuring logging in your app is the only step needed.

## Development

```sh
# Ruby
bundle install
bundle exec rake              # unit + integration, separate processes

# TypeScript
npm install
npm test                      # unit only — offline, no credentials
npm run typecheck
npm run test:e2e              # LIVE: real Okta sign-in through real IAP

# Python
uv sync --group dev
uv run pytest                 # offline, no credentials

# Go
go test ./cruiap/             # offline, no credentials, no dependencies
go vet ./...
```

No default suite touches the network. `npm run test:e2e` does — see below.

Counts as of 2026-07-26: Ruby 68, TypeScript 99, Python 82, Go 103.

### End-to-end against live IAP

`e2e/` is language-neutral: terraform stands up an IAP-fronted Cloud Run service
federated to Okta over Workforce Identity Federation, and `e2e/okta` drives a headless
sign-in through it. Both languages' e2e suites consume the same captured assertion.

`test/e2e/live-iap.test.ts` skips itself with a reason when the stack or the Okta
scratch credentials are absent, rather than failing. When it does run it proves the
thing no offline suite can: that a correctly configured workforce pool emits an `email`
claim, and that the verifier accepts the token Google actually mints — checked against
Google's real JWKS over the real network. It also asserts the pass is not vacuous
(tampered payload, wrong audience, no audience, re-signed with our own key) and that
the freshly captured claims still match `spec/fixtures/real_wif_iap_payload.json`, so
production Google changing shape shows up as a failing test rather than a surprise.

See `e2e/terraform/README.md` for standing the stack up, its ~$18/month cost, and
teardown.
