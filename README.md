# cru-iap

Request authentication for applications behind **Google Identity-Aware Proxy**, including
IAP fronted by an external identity provider via **Workforce Identity Federation**.

This library verifies the IAP assertion JWT on an incoming request and returns either an
email identity or a typed rejection reason. It is built for Cru's internal applications,
but nothing in it is Cru-specific.

**Four libraries, one repository.** The applications behind IAP are Rails, Next.js,
FastAPI and Go, and the claim-shape knowledge documented below was expensive enough to
learn that maintaining four divergent copies of it would be a mistake.

```ruby
gem "cru_iap", github: "CruGlobal/cru-iap"
```
```sh
npm install @cruglobal/cru-iap
uv add cru-iap
go get github.com/CruGlobal/cru-iap/cruiap
```

| | Ruby | TypeScript | Python | Go |
|---|---|---|---|---|
| Source | `lib/` | `src/` | `cru_iap/` | `cruiap/` |
| Tests | `spec/` | `test/` | `tests/` | `cruiap/*_test.go` |
| Runtime dependency | `googleauth` | `jose` | `pyjwt[crypto]` | **none** (stdlib) |
| Entry point | `CruIap::TokenVerifier.from_request` | `verifyRequest` | `verify_request` | `VerifyRequest` |

The npm package and the Python package are published to their registries; the gem is
installed from git and the Go package needs no registry at all, since `go get` resolves
the version straight from the tag. Every language's manifest sits at the repository root,
so a bare-repository-URL install still works for all four — which is how you install an
unreleased commit:

```sh
npm install github:CruGlobal/cru-iap
uv add "cru-iap @ git+https://github.com/CruGlobal/cru-iap"
```

The gem name is underscored while the repository is hyphenated, so `Bundler.require`
resolves straight to `lib/cru_iap.rb`; the npm package builds on install via `prepare`,
which is what makes a git install work without a registry.

All four read the same pinned capture of a real Google assertion
(`spec/fixtures/real_wif_iap_payload.json`), so they cannot quietly drift apart about
what IAP actually sends. The rejection vocabulary is cross-checked mechanically too —
see [Rejection reasons](#rejection-reasons).

## Scope

The library stops just past *"who is this?"*. It does not own your user model, your
session, your controller concern, how you render a rejection, or authorization.

Two things are in scope beyond verification, as pure functions with no framework
coupling: the [two IAP control URLs](#the-two-iap-control-urls) and the
[dev bypass](#the-dev-bypass). Both are cases where getting it wrong is silent and
security-relevant, and where every consumer was otherwise re-deriving the same answer.

The one framework-coupled surface is the same case: three Next.js apps hand-rolled the
same middleware gate, and one of them ordered a header strip wrongly in a way that
bypassed authentication outright. It lives behind the separate
[`@cruglobal/cru-iap/next`](#nextjs-middleware--cruglobalcru-iapnext) entry point, so
`next` stays an optional peer.

There is no Rails or ActiveSupport dependency. The TypeScript package touches no `node:`
builtin, so it runs on the Edge runtime. The Python package imports no web framework,
which a test enforces in a subprocess so its own imports cannot mask a leak.

## Configuration

`IAP_AUDIENCE` is read from the environment by default, at call time rather than at
import time, in all four languages. It is a **resource path** — not a URL and not a
client ID — and its shape depends on how IAP is fronted:

| IAP mode | `aud` |
|---|---|
| Behind an external HTTPS load balancer | `/projects/NUMBER/global/backendServices/BACKEND_ID` |
| Directly on Cloud Run (no load balancer) | `/projects/NUMBER/locations/REGION/services/SERVICE_NAME` |

Both are confirmed against live services. The verifier does not care which — it is an
exact string compare — but a deploy that hardcodes the wrong *shape* fails with
`audience_mismatch`, which reads like a config typo rather than an architecture
mismatch.

If your Terraform sets this for you, do not rename it with an application prefix.

**IAP directly on Cloud Run** is worth knowing about: it needs no load balancer, no
certificate and no DNS, which takes a test or low-traffic environment from roughly
\$18/month — the load balancer forwarding-rule bundle, billed regardless of traffic —
to effectively zero. Set `run.googleapis.com/iap-enabled: 'true'` on the service and
point `iapSettings` at your workforce pool.

## Usage (Ruby)

```ruby
# config/initializers/iap.rb
CruIap.logger = Rails.logger
```

```ruby
# config/application.rb
config.middleware.insert_before 0, CruIap::StripForwardedHost
```

```ruby
result = CruIap::TokenVerifier.from_request(request)

if result.ok?
  user = User.from_iap(email: result.email, name: result.name)
else
  Rails.logger.warn("IAP auth rejected: #{result.reason}")
  nil # fail closed — never fall through to a dev stub
end
```

`from_request` accepts an `ActionDispatch::Request`, a `Rack::Request`, or a bare Rack
env hash, and pulls the assertion off it — application code never names the header. If
you need the wire name for infrastructure config or a test fixture, it is
`CruIap::TokenVerifier::HEADER`.

Both `from_request` and the lower-level `.call(token)` accept `audience:` and `logger:`
overrides.

### Reference wiring (Rails controller)

```ruby
# Resolve once per request: the failure path must not re-verify the JWT and
# re-log the rejection at every current_user call site.
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

`result` is a discriminated union, so `result.email` narrows to `string` inside the `ok`
branch and `null` outside it. `verifyRequest` accepts a Web `Request` or `Headers`
(route handlers, middleware, Edge), a Node `IncomingMessage` (Express, a custom server),
or a plain header record. `verify(token)` is the lower-level form. Both take
`{ audience, logger, jwks, clockToleranceSeconds }`.

### Next.js middleware — `@cruglobal/cru-iap/next`

Middleware is the right seam: one gate for every route, running before any page or route
handler allocates work for a request that is about to be rejected. Three apps wrote that
gate by hand and got three different answers, so it ships as a factory:

```ts
// middleware.ts (or proxy.ts on Next 16 — the same function serves as either)
import { createIapProxy } from "@cruglobal/cru-iap/next";

// App-owned, and it has to be: Next requires the matcher to be a statically
// analyzable literal in this file.
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };

export default createIapProxy({
  // Exact-or-prefix match. Note the trailing slash on a directory prefix:
  // "/api/" leaves /apiary gated, where a bare "/api" would not.
  publicPrefixes: ["/health", "/api/webhooks/"],
});
```

The gate **fails closed**: no assertion and no `CRU_IAP_DEV_BYPASS_EMAIL` is a 401, in
every environment. The two shapes that reach for a shortcut here — opening the gate when
`IAP_AUDIENCE` is unset, and a boolean bypass flag — are exactly the incidents this
package exists to prevent. Locally you get an identity, never an open gate:

```sh
CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org npm run dev
```

Options: `publicPrefixes`, `audience`, `logger`, `env`. A rejection logs one line of
`{"severity":"WARNING","message":"iap_rejected","reason":…,"path":…}` and answers 401 —
never a redirect, because IAP owns sign-in and has already run, so bouncing the browser
only loops.

**Anything in `publicPrefixes` (or excluded by the matcher) must ALSO be in the
module's `iap.bypass_paths`.** Otherwise the load balancer 401s the request before your
app ever runs, and the exemption is invisible. See
[bypass_paths](#surfaces-that-authenticate-themselves-need-bypass_paths).

### The identity headers

The gate stamps the verified identity onto the request it forwards, so downstream code
reads it instead of re-verifying per route:

| Header | |
| --- | --- |
| `x-cru-iap-email` | the identity; always present |
| `x-cru-iap-name` | display name; absent when the assertion carries no `name` claim |
| `x-cru-iap-issued-at` | the assertion's `iat`, decimal; absent under the dev bypass |

```ts
import { identityFrom } from "@cruglobal/cru-iap";

const identity = identityFrom(await headers()); // { email, name, issuedAt } | null
```

What makes these trustworthy is not the names: it is that the gate **strips all three
before anything else**, including before the public-path check. Strip after that early
return and every exempt path becomes an injection point —
`curl -H 'x-cru-iap-email: admin@cru.org' /health` — for every reader downstream. If you
hand-roll a gate, use `stripIdentity` / `stampIdentity` in that order; `IDENTITY_HEADERS`
holds the wire names.

Two Next.js-specific notes:

- **Middleware runs on the Edge runtime by default**, which has no `node:crypto`. That
  is why this package is built on `jose` (WebCrypto) rather than `google-auth-library`.
- **There is no `StripForwardedHost` equivalent, deliberately.** Next.js has no
  comparable pre-routing slot, and its host handling is configuration (`trustHost`,
  `allowedDevOrigins`) rather than a middleware you can precede. If your app makes a
  security decision from the host, make it from an allow-list you control, not from
  `x-forwarded-host`. See [host resolution](#host-resolution-per-framework).

## Usage (Python)

```python
from cru_iap import verify_request

result = verify_request(request)

if result.ok:
    user = provision_user(email=result.email, name=result.name)
else:
    log.warning("IAP auth rejected: %s", result.reason)
    # fail closed — never fall through to a dev stub
```

`Result` is a frozen dataclass — so a caller cannot launder a rejection into a pass by
assignment — and is truthy when `ok`, so `if verify_request(request):` reads fine too.
`verify_request` accepts a Starlette/FastAPI `Request`, a Django `HttpRequest` (via
either `.headers` or `.META`), a Flask/Werkzeug `request`, a bare WSGI `environ`, or a
plain header mapping. `verify(token)` is the lower-level form. Both take `audience`,
`jwks`, `leeway_seconds` and `log`.

Two Python-specific notes:

- **The verifier is synchronous**, because PyJWT and its key fetch are. In FastAPI,
  declare the dependency with `def` rather than `async def` and it runs in a threadpool
  automatically — which is what you want, since an `async def` dependency would block
  the event loop on the hourly JWKS refresh.
- **Logging follows the Python convention** rather than a global setter: the package
  logs to `logging.getLogger("cru_iap")` with a `NullHandler` attached, so it is silent
  until your application configures logging.

### Reference wiring (FastAPI dependency)

```python
# backend/auth.py
from fastapi import Depends, HTTPException, Request
from cru_iap import verify_request

def current_user(request: Request) -> User:
    # Gate the dev bypass on deploy config, never on the header being absent.
    if not settings.iap_audience:
        return dev_stub_user()

    result = verify_request(request)
    if not result.ok:
        log.warning("iap_rejected reason=%s", result.reason)
        raise HTTPException(status_code=401, detail="Unauthorized")

    return provision_from_iap(email=result.email, name=result.name)
```

## Usage (Go)

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
that a recover middleware renders as a 500, or that an upstream error path swallows into
a pass. Options are `WithAudience`, `WithKeySource`, `WithLogger`, `WithClockTolerance`
and `WithClock`.

### Stdlib-only, unlike its siblings

ES256 verification is small in Go — base64url and JSON for the envelope, `crypto/ecdsa`
for the signature — and skipping a JWT library means the reason vocabulary needs no
translation layer, so every condition is raised where it is detected.

The tradeoff, stated plainly: the JWS envelope parsing and claim checks are this
package's own rather than a widely-audited library's. That is why the suite pins the
failure modes a JWT library would otherwise be trusted for — alg confusion across six
`alg` values including `none`, a truncated and an over-long signature, a public key not
on the curve, and an `exp` that is absent rather than merely past.

Two Go-specific notes:

- **JWS ES256 signatures are the fixed-width `r||s` form** (RFC 7515 A.3), 32 bytes
  each — *not* the ASN.1 DER encoding `ecdsa.VerifyASN1` expects and most non-JOSE
  tooling produces. Getting this wrong fails closed, which is the safe direction, but it
  is the single most common mistake in a hand-written JWS verifier.
- **`bad_iss:` is unreachable here, by construction.** The siblings re-assert the issuer
  in case their JWT library ever stops checking; there is no library to distrust here, so
  the single check emits `issuer_mismatch`. A test records this, so the gap reads as a
  decision rather than an oversight.

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

## Migrating from application-level OIDC

If an application currently runs its own Okta OIDC — Auth.js/next-auth, authlib, or
similar — moving behind IAP *deletes* the provider rather than reconfiguring it. What
goes away: the provider registration, the login and callback routes, the client secret,
the redirect/callback URLs, and any `trustHost`-style setting that existed only to build
those callback URLs. If nothing else needs it, the signed session cookie and its secret
go too. What remains is the wiring above, plus whatever the callback already did on
first sign-in.

One inference does *not* survive. Applications relying on *"any session that exists is
an allowed user, because the IdP only lets assigned users complete the flow"* still have
that property, but its enforcement moves out of the application and into the
`roles/iap.httpsResourceAccessor` IAM binding. Read
[gotcha 10](#gotchas-this-library-encodes) before assuming group membership is still
visible application-side — it is not.

## The two IAP control URLs

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

Why not interpolate a string at the call site — each of these is a real mistake:

- **A bare `/` for sign-in loops forever.** IAP sends `/` to the IdP, the IdP sends it
  back to `/`.
- **Sign-out without the cookie-clear mode signs nobody out.** The application session
  goes away; IAP's federated login cookie does not, and the next request signs the same
  person straight back in.
- **A fragment must stay last.** `"/a#b"` with `"?login=true"` appended naively gives
  `"/a#b?login=true"`, where the parameter sits inside the fragment and never reaches
  the server.
- The separator depends on whether a query string is already present. Both helpers are
  idempotent.

The two query literals are Google's, and a typo in one language would be a silent
failure in that language only — so they are cross-checked across all four by a test.

## The dev bypass

```sh
CRU_IAP_DEV_BYPASS_EMAIL=you@example.com bin/rails server
```

Compose it in front of the real verify:

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

**There is no boolean.** A flag has a wrong default. An identity-carrying variable does
not — either you name a developer to be, or you don't, and *unset can only mean no
bypass*. There is also no `dev_bypass_enabled = true` setter, because anything an
application can set in a config file, it can set in production config.

**Two independent guards**, neither depending on the application being written
correctly:

1. `IAP_AUDIENCE` is set → refuse. The bypass cannot coexist with the configuration
   that means "this is a real IAP environment".
2. A cloud-runtime marker (`K_SERVICE`, `K_REVISION`, `GAE_ENV`, `FUNCTION_TARGET`) is
   present → refuse. The platform sets these; nobody has to remember to.

They are independent on purpose: a deploy that somehow lost `IAP_AUDIENCE` is still
refused on Cloud Run.

It returns `dev_bypass`, a reason in the [shared vocabulary](#rejection-reasons), so a
bypassed request is queryable rather than invisible. The configured address must pass
the same shape gate as a real identity — including rejection of namespaced values like
`sts.google.com:you@example.com`, which are a copy-paste out of a JWT rather than an
address. It warns on **every** activation: a bypass that logs once is a bypass someone
forgets is on.

## Host resolution per framework

`StripForwardedHost` (Ruby) exists because **Rails resolves `request.host` from
`X-Forwarded-Host` before `Host`**. Google's load balancer preserves `Host` and never
sets `X-Forwarded-Host`, so a present value is always client-forged. Any application
keying behaviour off `request.host` can otherwise be steered by a header.

It is **not** a universal need:

| | Prefers `X-Forwarded-Host`? | Action |
|---|---|---|
| Rails | **yes** (`ActionDispatch::Http::URL#raw_host_with_port`) | `CruIap::StripForwardedHost` at position 0 |
| Next.js | **yes** — `parseHostHeader` prefers it for the Server Actions CSRF check, and `base-server` sets it with `??=`, so a client value survives (verified in Next 16.2) | strip at the edge, and/or set `serverActions.allowedOrigins` |
| FastAPI / Starlette | no — host comes from the ASGI scope | none needed |
| Go `net/http` | no — `r.Host` comes from the request line | none needed |

Identity is never forgeable this way, since the assertion is signed. This protects the
routing layer, not authentication.

## Deployment checklist

- [ ] `IAP_AUDIENCE` set from the Terraform module output
- [ ] Cloud Run ingress restricted to the load balancer. Verify the deployed service
      rather than assuming — if ingress is `INGRESS_TRAFFIC_ALL`, the raw `*.run.app`
      URL reaches the application with **no IAP in front**. If your Terraform module
      derives this from a load-balancer strategy input, there may be no `--ingress`
      flag in the deploy chain to set, so check the module rather than the deploy.
- [ ] Regardless of ingress, every route fails closed on a missing header, and a
      "no header → dev stub" fallback is impossible in production. Use
      [the dev bypass](#the-dev-bypass) rather than a hand-rolled flag.
- [ ] `CruIap::StripForwardedHost` inserted at position 0 (Rails), or the equivalent for
      Next.js. Go and FastAPI need nothing.
- [ ] Sign-in built with `login_url` — **not** a hand-written `/`, which loops
- [ ] Sign-out built with `logout_url`, so IAP clears the federated login cookie
- [ ] Every surface that authenticates *itself* is listed in the IAP
      [`bypass_paths`](#surfaces-that-authenticate-themselves-need-bypass_paths), not just
      exempted in application code
- [ ] Decide what an authenticated-but-unauthorized user sees — see
      [the access-denied page](#the-access-denied-page)

## Surfaces that authenticate themselves need `bypass_paths`

An application-side exemption is **not enough on its own**, and this is the constraint
most likely to take a cutover down. IAP rejects at the load balancer, before your gate
runs: a webhook, a cron POST, or an OAuth token endpoint never reaches the middleware
that would have waved it through. It gets IAP's 401, or a 302 to a sign-in page it
cannot complete because there is nobody at a browser.

So each one needs a path prefix in the IAP configuration's `bypass_paths`, routing it to
a public backend service and skipping both IAP and the sign-in redirect:

```hcl
iap = {
  members      = ["principalSet://…/group/YourGroup"]
  bypass_paths = ["/api/", "/oauth/", "/.well-known/", "/up"]
}
```

The two halves are not redundant — they answer different questions. `bypass_paths`
decides *what reaches the application*; the application-side exemption decides *what the
application does with what arrives*, since a bypassed path gets no assertion header and
must fall back to its own credential (a PAT, a signing secret, an OIDC token it verifies
itself). Omit the Terraform half and the surface is unreachable; omit the application
half and it is unauthenticated.

Enumerate deliberately — the list is longer than it first looks. Every route your *old*
auth already skipped is a candidate, and so is every client that holds a credential
rather than a session. Real applications have needed nine or more: SCIM, an OAuth
authorization server and its metadata document, an MCP transport, Slack callbacks, a
scheduler, a public API, a health probe, and tokenized links for external recipients.

## The access-denied page

IAP can redirect a user who signed in successfully but holds no
`roles/iap.httpsResourceAccessor` binding to a page you control, instead of its own bare
error page. Set `applicationSettings.accessDeniedPageSettings.accessDeniedPageUri`; in
Terraform, `google_iap_settings` exposes it as
`application_settings { access_denied_page_settings { access_denied_page_uri = … } }`.

Verified against a live Okta → WIF → IAP sign-in. Five constraints the documentation
does not mention, all measured:

| | |
|---|---|
| Scope | **Authorization only.** An unauthenticated request still goes to `auth.cloud.google/authorize`; this page is reached only after a successful sign-in that fails the IAM check. |
| Parameters | **Yours survive; IAP adds none of its own.** A URI with `?app=foo&reason=no_group` arrives verbatim in the `Location`, so you can encode the application, a support contact, or the group to request. What you cannot get is anything *dynamic* — no identity, no reason, and no troubleshooting link even with `generate_troubleshooting_uri = true`. |
| `Accept` | **Ignored.** An XHR asking for JSON gets the same cross-origin `302`, so `fetch` follows it and fails on CORS rather than seeing a status it can handle. |
| Body | The `302` still carries IAP's default "Access Denied" HTML, for clients that do not follow redirects. |
| Entitlement | Google documents this as part of a paid enterprise subscription, yet it applied with nothing purchased for it. **Confirm entitlement before relying on it in production.** |

One operational note: **IAP IAM changes take well over five minutes to propagate.** A
binding you just removed will still let the user through. Wait before concluding the
denial path is broken.

## Gotchas this library encodes

1. **`email` is the identity in every mode. `sub` never is.**

   | | `email` claim | `sub` claim |
   |---|---|---|
   | Plain IAP (Google / Cloud Identity) | bare address, no prefix | `accounts.google.com:<opaque id>` |
   | WIF, `google.email` mapped | bare address | `sts.google.com:<opaque STS token>` |
   | WIF, mapping absent | **absent entirely** | `sts.google.com:<opaque STS token>` |

   There is no mode in which `sub` yields a usable identity, so a `sub` fallback buys
   nothing and costs diagnostic clarity.

2. **A workforce JWT with no `email` means a missing `google.email` attribute mapping**
   on the pool provider, and upstream of that a missing `email` attribute statement on
   the IdP application. Nothing application-side can recover the address. Report it as
   `missing_email`, which names the actual remedy — a `sub` fallback downgrades that
   accurate diagnosis into a misleading `malformed_subject`, sending the next reader
   hunting a principal shape that does not exist.

3. **`principal://…` is in neither `email` nor `sub`.** The workforce principal URI is
   real, but it lives in the nested `workforce_identity.iam_principal` claim — it is the
   string IAM bindings match, not an identity. A verifier that unwraps it out of
   `email`/`sub` is handling a shape IAP never emits, and is *accepting* a value it
   would otherwise correctly reject. The WIF payload also carries
   `identity_source: "WORKFORCE_IDENTITY"` if you need to branch on federated versus
   Google sessions.

4. **Split on the first colon; never match a literal prefix.** A real email never
   contains one, so a leading `<prefix>:` is always the IAP namespace. Observed
   prefixes: `accounts.google.com:`, `sts.google.com:`, and Identity Platform's
   `securetoken.google.com/<project>/<tenant>:`.

5. **An email regexp is not a sufficient shape gate on its own.** RFC 5322 permits `/`
   in a local part, so a URI-shaped value ending in an address would be persisted as a
   user whose email is that entire string. Reject anything containing a slash as well.

   The interaction with gotcha 4 is the surprising part. The *raw*
   `principal://iam.googleapis.com/.../subject/alice@example.com` fails an email regexp,
   but only because of the `principal:` scheme colon — and the verifier strips everything
   up to the first colon before validating, since that is how it removes the namespace.
   What survives that strip, `//iam.googleapis.com/.../subject/alice@example.com`,
   **does** match. Each guard looks redundant alone; together they are not.

6. **Keep `malformed_subject` and `missing_email` distinct.** Nothing arrived, versus
   something arrived that is not an address: different root causes, different fixes.

7. **Fail closed when `IAP_AUDIENCE` is unset** rather than skipping the audience check.

8. **Require `exp`; do not merely validate it.** The `jwt` gem's `verify_expiration` is
   a no-op when the claim is *absent*, and googleauth adds no freshness floor — so a
   validly signed assertion carrying no `exp` would be accepted forever. Not
   attacker-reachable, since minting one needs Google's IAP signing key, but the
   verifier should not depend on IAP always setting it.

   **`jose` and PyJWT have the identical hole**, so the TypeScript side passes
   `requiredClaims: ["exp"]` and the Python side `options={"require": ["exp"]}`. Three
   independent JWT libraries making the same choice is the default to expect — assume the
   next one does too, and check rather than trust.

9. **Do not coerce the `email` claim to a string in JavaScript.**
   `String(["a@example.com"])` is `"a@example.com"`, so a multi-address array claim
   would coerce into a single accepted identity. Ruby's `Array#to_s` renders the
   brackets and rejects, which is why the Ruby verifier can safely `.to_s` and the
   TypeScript one cannot. Python's `str()` also renders brackets, but the Python
   verifier still checks `isinstance(raw, str)` explicitly, because relying on `repr()`
   for a security decision is a coincidence rather than a design.

10. **The assertion carries no group membership.** There is no `groups` claim and
    nothing from which one can be derived — the entire top-level claim set is `aud`,
    `azp`, `email`, `exp`, `iat`, `identity_source`, `iss`, `sub`, and the nested
    `workforce_identity`. This is the most expensive difference from an OIDC `id_token`,
    because a `groups` claim is how many applications answer *"may this person be
    here?"*.

    The coarse gate moves into infrastructure rather than disappearing:
    `roles/iap.httpsResourceAccessor` accepts `principalSet://…/group/<group>`, so
    "must be in group X" becomes an IAM binding that IAP enforces before the
    application is reached. What you cannot do application-side is make a *finer*
    decision from the group — read a role, branch on department, vary navigation —
    because the application can no longer see the membership that got the request
    through the door. Applications needing that must keep their own store.

    The failure mode is silent and **open**, not closed: the claim is simply absent, so a
    port keeping `required_group.in?(claims["groups"])` rejects everyone, while one
    keeping `claims["groups"]&.include?` or an `unless groups.blank?` guard admits
    everyone. Grep for the group claim by name during a cutover rather than trusting
    tests to catch it.

11. **Load-balancer 302s look like application redirects** in logs. Check which layer
    issued them.

## Rejection reasons

`REASONS` is a single vocabulary shared across all four languages, so every application
behind IAP can file the same queries regardless of stack. Entries ending in `:` carry a
variable suffix.

`missing_token` · `missing_audience_config` · `bad_iss:` · `missing_exp` ·
`missing_email` · `malformed_subject` · `signature_error:` · `audience_mismatch` ·
`expired_token` · `issuer_mismatch` · `verification_error:` · `unexpected_error` ·
`iap_jwt` · `dev_bypass`

Two are successes: `iap_jwt` (a verified assertion) and `dev_bypass`. Everything else is
a rejection. `dev_bypass` is in the vocabulary precisely so a bypassed request appears
in the same queries as a real one instead of being invisible.

A test in each language asserts its verifier can only produce listed reasons. Across
languages, the Python suite parses the Ruby and TypeScript lists out of their source and
asserts all three are identical, and the Go suite checks all three against its own — so
a reason added in one place and forgotten in another fails there. The comparison is
element-by-element, so add a reason in every language at once, **in the same position**.

These mappings differ because the underlying libraries do:

| Condition | Ruby (googleauth) | TypeScript (jose) | Python (PyJWT) | Go (stdlib) |
|---|---|---|---|---|
| token's `kid` not in the JWKS | `signature_error:Token not verified as issued by Google` | `signature_error:no_matching_key` | `signature_error:no_matching_key` | `signature_error:no_matching_key` |
| JWKS unreachable / non-200 / unparseable | `verification_error:KeySourceError` | same | same | same |
| wrong `iss` | `issuer_mismatch`, or `bad_iss:` from the re-assert | same | same | `issuer_mismatch` only |

Two library quirks are pinned by tests rather than trusted. `PyJWKClient` raises the
plain base `PyJWKClientError` for two unrelated conditions — no matching `kid`, and a
JWKS that fetched but would not parse — separable only by message; the connection case
has its own subclass. And `jose` reports a non-200 JWKS response as its *base*
`JOSEError`; keying off that looks alarmingly broad, so it was checked — those are the
only two sites in the library that throw the bare base class (jose 6.2), and both are
this exact condition.

## What the library logs

The verifier is silent except for two warnings: `malformed_subject`, which dumps the
full JWT payload so an unexpected principal shape is diagnosable without redeploying
instrumentation, and the fail-closed catch-all. The payload is identity claims, not
credentials — the same sensitivity as the email addresses already in your request logs.

It defaults to a null logger until you set `CruIap.logger`, pass `logger:` / `log=`, or
configure logging in Python.

## Development

```sh
# Ruby
bundle install
bundle exec rake              # unit + integration, separate processes

# TypeScript
npm install
npm test                      # unit only — offline, no credentials
npm run typecheck

# Python
uv sync --group dev
uv run pytest                 # offline, no credentials

# Go
go test ./cruiap/             # offline, no credentials, no dependencies
go vet ./...
```

No default suite touches the network. The end-to-end suites, which verify against real
Google infrastructure, are gated separately in each language — see [`e2e/`](e2e/).

### Releases

All four libraries share one version and one tag. Releases are cut by
[release-please](https://github.com/googleapis/release-please), which keeps a standing
`chore(main): release X.Y.Z` pull request on `main` built from
[conventional-commit](https://www.conventionalcommits.org/) subjects — this repo scopes
them by language (`feat(ts):`, `fix(ruby):`, `docs(python):`).

Merging that PR is the whole release:

1. It bumps the version in all four declared places — `package.json` (+
   `package-lock.json`), `pyproject.toml`, `cru_iap/__init__.py` and
   `lib/cru_iap/version.rb`. It has to move all four:
   `tests/test_package.py::test_the_four_declared_versions_agree` fails the build
   otherwise.
2. It writes the new `CHANGELOG.md` section above the previous one.
3. release-please tags `vX.Y.Z` and publishes a GitHub Release. The tag is what `go get`
   resolves, so Go needs nothing further.
4. That Release triggers [`release.yml`](.github/workflows/release.yml), which re-runs the
   checks and publishes `@cruglobal/cru-iap` to npm and `cru-iap` to PyPI. Both use
   trusted publishing (OIDC) — there is no registry token in this repository.

The generated changelog entry is terse by design. **Edit the release PR before merging**
when a change deserves the kind of writeup the 0.1.0 and 0.2.0 entries have — the PR body
and `CHANGELOG.md` are both editable in place, and the prose is the point of that file.

Pre-1.0, features move the minor and breaking changes are capped at minor. The gem is not
pushed to RubyGems; its version moves only to stay in step.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
