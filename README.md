# cru-iap

Request authentication for Cru apps behind **Google Identity-Aware Proxy**, with
Okta federated in via **Workforce Identity Federation**.

Extracted from [beacon](https://github.com/CruGlobal/beacon) after its 2026-07 IAP
cutover, ahead of the same cutover in cru-bot.

**Two libraries, one repo**, because Cru's apps behind IAP are Rails *and* Node and the
claim-shape knowledge below was expensive enough that maintaining two copies of it
would be a mistake:

```ruby
gem "cru_iap", github: "CruGlobal/cru-iap"
```
```sh
npm install github:CruGlobal/cru-iap    # @cruglobal/cru-iap
```

(Underscored gem name, hyphenated repo — so `Bundler.require` resolves straight to
`lib/cru_iap.rb` without a shim file. The npm package builds on install via `prepare`,
which is why a git install works without a registry.)

| | Ruby | TypeScript |
|---|---|---|
| Source | `lib/` | `src/` |
| Tests | `spec/` | `test/` |
| Runtime dep | `googleauth` | `jose` |
| Shared | `e2e/` (terraform + Okta), `spec/fixtures/real_wif_iap_payload.json` | |

Both read the same pinned capture of a real Google assertion, so the two cannot quietly
drift apart about what IAP actually sends.

## What it does

| | |
|---|---|
| `CruIap::TokenVerifier` / `verify`, `verifyRequest` | Verify the IAP assertion JWT on a request; return an email identity or a typed rejection reason |
| `CruIap::StripForwardedHost` | Drop a client-forged `X-Forwarded-Host` before anything reads `request.host` (Ruby only — see below) |

No Rails or ActiveSupport dependency — `googleauth` only. The TypeScript package
depends only on `jose`, and touches no `node:` builtin, so it runs on the Edge runtime.

## What this gem is *not*

It stops at *"who is this?"*. It does not own your `User` model, your session, your
controller concern, how you render a rejection, your dev/test bypass, or
authorization.

That boundary is deliberate and evidence-based. Comparing the first two consumers,
every one of these diverged:

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
      "no header → dev stub" fallback must be impossible in production. Gate the dev
      bypass on deploy config (e.g. `IAP_AUDIENCE` being unset), not on the header
      being absent.
- [ ] `CruIap::StripForwardedHost` inserted at position 0
- [ ] Sign-in CTA links **`/?login=true`**, not `/`. Bare `/` loops.
- [ ] Sign-out redirects to **`/?gcp-iap-mode=CLEAR_LOGIN_COOKIE`** so IAP clears the
      federated login cookie
- [ ] Production logs emitted as JSON with a `severity` field, or Cloud Run drops
      Rails' stdout from the log sink and you'll debug the cutover blind

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

   **`jose` has the identical hole** — it skips the expiry check when `exp` is absent
   rather than failing — so the TypeScript side passes `requiredClaims: ["exp"]`. Two
   independent JWT libraries in two languages made the same choice; assume the next one
   does too and check rather than trust.

8b. **Don't coerce the `email` claim to a string in JavaScript.**
   `String(["alice@cru.org"])` is `"alice@cru.org"`, so a multi-address array claim
   would coerce into a single accepted identity. Ruby's `Array#to_s` renders the
   brackets and rejects, which is why the Ruby verifier can safely `.to_s` and the
   TypeScript one cannot. A shape gate is only as good as what it is handed.

9. **Load-balancer 302s masquerade as Rails redirects** when you are reading logs
   during a cutover. Check which layer actually issued them.

10. **Get logs flowing before you theorize.** Two of the wrong turns above were guesses
   written while Rails stdout was not reaching Datadog at all — the commit claiming a
   shape was "observed live" predated log visibility by 25 minutes. Fixing the
   telemetry is cheaper than a deploy cycle.

## Rejection reasons

`CruIap::TokenVerifier::REASONS` / `REASONS` is the shared vocabulary — shared across
*both languages*, so every app behind IAP files the same Datadog queries whether it is
Rails or Node. Entries ending in `:` carry a variable suffix.

`missing_token` · `missing_audience_config` · `bad_iss:` · `missing_exp` ·
`missing_email` · `malformed_subject` · `signature_error:` · `audience_mismatch` ·
`expired_token` · `issuer_mismatch` · `verification_error:` · `unexpected_error` ·
`iap_jwt` (the only `ok?` reason)

A test in each language asserts its verifier can only produce listed reasons, so the
vocabulary can't drift silently. Nothing mechanically enforces that the *two lists*
match — if you add a reason, add it in both places.

Two mappings are worth knowing because the underlying libraries differ:

| condition | Ruby (googleauth) | TypeScript (jose) |
|---|---|---|
| token's `kid` not in the JWKS | `signature_error:Token not verified as issued by Google` | `signature_error:no_matching_key` |
| JWKS unreachable / non-200 / unparseable | `verification_error:KeySourceError` | `verification_error:KeySourceError` |

jose reports a non-200 JWKS response as its *base* `JOSEError` class. Keying off that
looks alarmingly broad, so it was checked: those are the only two sites in the whole
library that throw the bare base class (jose 6.2), and both are this exact condition.

## Logging

The verifier is silent except for two `warn`s: `malformed_subject` (which dumps the
full JWT payload, so an unexpected principal shape is diagnosable without
re-deploying instrumentation) and the fail-closed catch-all. The payload is identity
claims, not credentials — the same sensitivity as the emails already in your request
logs. It defaults to a null logger until you set `CruIap.logger` / pass `logger:`.

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
```

Neither default suite touches the network. `npm run test:e2e` does — see below.

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
