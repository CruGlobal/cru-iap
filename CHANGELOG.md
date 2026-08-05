# Changelog

This repo now ships **four** libraries from one source of truth: the `cru_iap` Ruby gem,
the `@cruglobal/cru-iap` npm package, the `cru-iap` Python package, and the
`github.com/CruGlobal/cru-iap/cruiap` Go package. All four share one version and one tag.

Which library an entry applies to is called out per entry. The two hand-written releases
below use `[ruby]` / `[ts]` / `[python]` / `[go]` / `[docs]` / `[all]` markers; from 0.3.0
on, release-please generates entries from conventional-commit scopes and renders the same
distinction as **`ts:`**, **`ruby:`**, and so on. See
[Releases](https://github.com/CruGlobal/cru-iap#releases) for how a release is cut.

## [0.2.0] - 2026-08-03

Ruby, Python and Go are unchanged in this release; their versions move only to stay in
step with the npm package, which a test enforces.

### Added — `[ts]` `@cruglobal/cru-iap/next` — the Next.js gate, as a factory

Three Next.js apps hand-rolled the same IAP middleware — bills, cru-web-campaign,
pingpong (per-route, no gate at all yet) — and the diffs between them were not stylistic:

- bills strips the inbound identity headers **before** its public-path early return.
  Doing it after is a full authentication bypass: every exempt path becomes an
  `x-cru-iap-email: admin@cru.org` injection point for everything downstream.
- cru-web-campaign opened the gate entirely when `IAP_AUDIENCE` was unset, and both apps
  carried a boolean bypass flag — the same two shapes as the `AUTH_ENABLED` incident
  below. `createIapProxy` **fails closed**: no assertion and no
  `CRU_IAP_DEV_BYPASS_EMAIL` is a 401, in every environment.

```ts
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
export default createIapProxy({ publicPrefixes: ["/health", "/api/webhooks/"] });
```

The matcher stays app-owned, and has to: Next requires it to be a statically analyzable
literal in the middleware file, and cru-web-campaign's asset-exemption regex shows the
intricacy an app legitimately needs there. `publicPrefixes` covers the flat case, with
bills' exact-or-prefix semantics — which is why a directory prefix is written `"/api/"`,
so `/apiary` stays gated. Rejections answer 401 rather than redirecting (IAP owns
sign-in and has already run; bouncing the browser only loops) and log one line of
`{"severity":"WARNING","message":"iap_rejected","reason":…,"path":…}`.

A separate entry point, so `next` is an **optional** peer (`>=15.3.0`) and the core stays
importable from Express, route handlers and plain Node. `src/next.ts` is the only module
in the package that imports `next/server`, which a packaging test pins.

### Added — `[ts]` a standardized identity-header contract

`IDENTITY_HEADERS` / `stampIdentity` / `stripIdentity` / `identityFrom`, framework-free
and exported from the main entry point. The three names — `x-cru-iap-email`,
`x-cru-iap-name`, `x-cru-iap-issued-at` — are cru-web-campaign's, already in production,
so they are frozen rather than configurable.

Verifying once at the edge and stamping the result is what lets downstream code skip
re-verification. What makes the headers trustworthy is `stripIdentity` running first —
not the naming — so `stampIdentity` deletes-then-sets name and issued-at rather than
setting only when present: the real workforce assertion usually has no `name` claim and
the dev bypass has no payload at all, and in neither case may a client-supplied value
survive as the identity.

## [0.1.0] - 2026-07-27

**First tagged release.** Nothing in this repo was ever tagged before, so `0.1.0`
contains everything: the initial Ruby extraction from beacon (originally written up as
0.1.0 and dated 2026-07-24, now the last section here) plus the three sibling
libraries, CI for all four, the live end-to-end suites, and two primitives.

Consumers should pin `v0.1.0` rather than a branch or a bare default branch. `dgt` and
`dse-portal` currently pin the `add-python-and-go` branch **by name** and must be
repinned before it is deleted.

### Added — `[all]` `login_url` / `logout_url`

The two IAP control URLs, in all four languages. Both were README checklist items —
prose that four apps had to re-read correctly, and three of them re-typed the strings by
hand instead.

- Bare `/` for sign-in is an **infinite redirect**: IAP sends `/` to the IdP, the IdP
  sends it back to `/`. The most-reported IAP footgun at Cru.
- Sign-out without `?gcp-iap-mode=CLEAR_LOGIN_COOKIE` **does not sign anyone out**. The
  app's session goes away, IAP's federated login cookie does not, and the next request
  signs the same person straight back in.

Pure string builders, so they compose into whatever wiring an app already has. They
handle the cases a hand-written template gets wrong: a fragment must stay last (`"/a#b"`
appended naively puts the param *inside* the fragment, where it never reaches the
server), the separator depends on an existing query, and both are idempotent. The two
query literals are Google's, so they are cross-checked across all four languages.

### Added — `[all]` a dev bypass that cannot be enabled in production by accident

Three consumers had grown three incompatible bypasses, and one shipped an incident:
`AUTH_ENABLED` defaulted to the **insecure** value, so forgetting to set it disabled
authentication.

**There is no boolean** — that is the design. A flag has a wrong default; an
identity-carrying variable does not, because "unset" can only mean "no bypass". So the
opt-in *is* the identity: `CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org`. There is no
`dev_bypass_enabled=` setter either, because anything an app can set in a config file it
can set in production config.

Two guards on top, independent so neither depends on the app being written correctly:
`IAP_AUDIENCE` being set (cru-terraform injects it into every IAP-fronted container),
and the presence of any cloud-runtime marker (`K_SERVICE`, `K_REVISION`, `GAE_ENV`,
`FUNCTION_TARGET` — set by the platform, so nobody has to remember to). A deploy that
somehow lost `IAP_AUDIENCE` is still refused on Cloud Run.

Adds **`dev_bypass`** to `REASONS` in all four languages, so a bypassed request lands in
the same Datadog queries as a real one rather than being invisible. Additive: consumers
use `is_known_reason` as a predicate, not an enumeration.

### Added — `[all]` live end-to-end verification in every language

Previously only TypeScript verified a real Google-minted assertion, so the claim-shape
drift detector protected four languages but *ran* in one.

The browser login is the expensive, fragile part and is entirely language-agnostic, so
it now runs **once** and all four suites verify that one assertion (`e2e/run_all.sh`).
Twelve checks each: the assertion is genuinely live, it verifies against Google's real
JWKS, the pass is not vacuous (the same token with exactly one thing broken — edited
payload, wrong backend service, no audience, re-signed with our own key), and the claim
shape still matches the pinned capture. Each suite is gated idiomatically so none run by
accident, and `run_all.sh` refuses to proceed on an unusable capture rather than letting
four skipped suites report four passes.

### Added — `[all]` CI for all four languages

Python and Go had no CI at all — not even unit. Both now run on a floor-plus-current
matrix, and Go additionally asserts `go mod tidy` is a no-op, since a dependency
appearing in a stdlib-only package is a real regression.

Plus a secret-free smoke job on every PR checking that Google's IAP key endpoint still
serves ES256/P-256 — the one external contract all four libraries share, where a change
breaks every one of them at once and no offline suite notices.

### Added — `[ts]` a TypeScript sibling of the gem

`@cruglobal/cru-iap`, for Cru's Node apps (bills first). Same rejection vocabulary,
same claim-shape decisions, same pinned real-capture fixture — so the two languages
cannot quietly disagree about what IAP emits.

- `verify(assertion, {audience, jwks, logger, clockToleranceSeconds})` and
  `verifyRequest(source, …)`, which accepts a Web `Request`/`Headers` (Next.js App
  Router, Edge runtime), a Node `IncomingMessage`, or a plain header record.
- `assertionFrom`, `HEADER`, `REASONS`, `isKnownReason`, `IAP_ISSUER`, `IAP_JWKS_URL`.
- Async, because WebCrypto verification is. There is no sync path.

Built on **jose**, not `google-auth-library`, for three measured reasons:
`getIapPublicKeys` has no cache at all (the Ruby `googleauth` memoizes for an hour), so
per-request use would put a gstatic.com round-trip in front of every authenticated
request; it reports every failure as a bare `Error` with a prose message, which would
leave the shared reason vocabulary matched on substrings; and it is Node-only, whereas
jose runs in Next.js middleware on the Edge runtime — where an IAP gate wants to live.

Two behaviours differ from the Ruby by necessity, both covered by tests:
- A **non-string `email` claim** is rejected outright rather than coerced.
  `String(["alice@cru.org"])` is `"alice@cru.org"`, so coercing would turn a
  multi-address array into an accepted single identity. Ruby's `Array#to_s` renders the
  brackets and rejects; JS would not.
- A **repeated assertion header** is treated as absent rather than resolved to one of
  the values, so the request fails closed instead of the library guessing.

### Added — `[docs]` the IAP access-denied page, proven live

IAP *can* redirect an authenticated-but-unauthorized user (signed in through Okta, not
in the group that grants access) to a page you control:
`applicationSettings.accessDeniedPageSettings.accessDeniedPageUri`. Verified end to end
on 2026-07-25 with a real Okta → WIF → IAP sign-in; `e2e/okta/probe_denied.mjs` is the
reproduction. Five constraints the docs omit — **hardcoded query parameters survive
verbatim but IAP appends nothing of its own** (no identity, no reason, and no
troubleshooting link even with `generate_troubleshooting_uri`, so the page can carry
static context only), the `Accept` header is ignored so XHRs get a cross-origin 302
rather than a 401, the 302 still carries IAP's default HTML body, it covers the authz
path only, and Google documents it as a paid-subscription feature though it applied
without one here. Plus: IAP IAM changes take **well over five minutes** to propagate,
which cost one false "the denial path doesn't work" reading.

### Added — `[go]` a Go sibling, for wormhole

`github.com/CruGlobal/cru-iap/cruiap`, for wormhole's dashboard. Same rejection
vocabulary, same claim-shape decisions, same pinned real-capture fixture.

- `Verify(ctx, assertion, opts…)` and `VerifyRequest(ctx, *http.Request, opts…)`, with
  `WithAudience`, `WithKeySource`, `WithLogger`, `WithClockTolerance`, `WithClock`.
- `AssertionFrom`, `AssertionFromHeader`, `Header`, `Reasons`, `IsKnownReason`, `Result`,
  `IAPIssuer`, `IAPJWKSURL`, `ParseJWKS`, `NewRemoteKeySource`, `ErrUnknownKid`.
- Neither function returns an error nor panics — every path returns a `Result`, with a
  `recover` backstop mapping an unanticipated panic to `unexpected_error`. An
  authentication check must not become a panic that a recover middleware renders as a
  500, or that an upstream error path swallows into a pass.

**Stdlib-only**, unlike the other three. wormhole — the only consumer — already contains
a stdlib-only OIDC verifier (`internal/oidcverify`) making and documenting the same
choice, so adding a dependency here to replace a dependency-free implementation there
would be a net loss. ES256 verification is small in Go (base64url and JSON for the
envelope, `crypto/ecdsa` for the signature; no primitive is implemented here). And the
reason vocabulary is *better* served without a translation layer: each sibling had to
reverse-engineer its library's error taxonomy, which is where two of the uglier README
notes came from — jose reporting a non-200 JWKS as its base error class, `PyJWKClient`
using one type for two faults separable only by message. Here every condition is raised
where it is detected.

The tradeoff is that the envelope parsing and claim checks are ours rather than a
widely-audited library's, so the suite pins what a JWT library would otherwise be trusted
for: alg confusion across six `alg` values including `none` and a lowercase `es256`, a
truncated *and* an over-long signature, a public key that is not on the curve (via
`ecdsa.ParseUncompressedPublicKey`, which validates that — the deprecated
`elliptic.Unmarshal` would not have), and an `exp` that is absent rather than merely past.

Two Go-specific notes now in the README: JWS ES256 signatures are the fixed-width `r||s`
form rather than the ASN.1 DER `ecdsa.VerifyASN1` wants (the most common mistake in a
hand-written JWS verifier, and it fails closed, which is why it can go unnoticed); and
`bad_iss:` is unreachable in Go by construction, because there is no third-party issuer
check to double-check. A test records that so the gap reads as a decision.

103 tests, offline, zero dependencies. One of them parses `REASONS` out of the Ruby,
TypeScript **and** Python sources and asserts all four lists are identical — so combined
with the Python-side check added below, a reason added in any one language turns at least
one suite red. Verified by injecting a bogus reason and confirming all three comparisons
failed.

### Added — `[python]` a Python sibling, for the FastAPI apps

`cru-iap` on PyPI-style install from the bare repo
(`uv add "cru-iap @ git+https://github.com/CruGlobal/cru-iap"`), for Cru's FastAPI apps —
dgt and dse-portal, both of which run authlib Okta OIDC today. Same rejection
vocabulary, same claim-shape decisions, same pinned real-capture fixture.

- `verify(assertion, audience=…, jwks=…, leeway_seconds=…, log=…)` and
  `verify_request(source, …)`, which accepts a Starlette/FastAPI `Request`, a Django
  `HttpRequest` (via `.headers` or `.META`), a Flask/Werkzeug `request`, a bare WSGI
  `environ`, or a plain header mapping.
- `assertion_from`, `HEADER`, `WSGI_ENVIRON_KEY`, `REASONS`, `is_known_reason`,
  `Result`, `IAP_ISSUER`, `IAP_JWKS_URL`, `reset_jwks_cache`.
- `Result` is a frozen dataclass, so a caller cannot launder a rejection into a pass by
  assignment, and is truthy when `ok`.

Built on **PyJWT**, not `google-auth` or authlib. `google.oauth2.id_token` raises
`ValueError` with a prose message for a bad audience, a bad issuer and an expired token
alike, which would leave the shared reason vocabulary matched on substrings; PyJWT has
one exception class per condition. authlib was the other candidate — both consumers
already depend on it — but its JWK handling has no caching client, whereas
`PyJWKClient(lifespan=3600)` matches the Ruby googleauth key source's one hour, so this
can be called per request without a gstatic.com round-trip each time.

Three deliberate divergences, all documented in the module:
- **Synchronous**, because PyJWT and its key fetch are. FastAPI consumers should declare
  the dependency with `def` rather than `async def` so it runs in a threadpool — an
  `async def` would block the event loop on the hourly JWKS refresh.
- **Logging follows the Python convention** rather than the gem's `CruIap.logger =`
  setter: `logging.getLogger("cru_iap")` with a `NullHandler`, so there is no global to
  set and the library is silent until the app configures logging.
- A non-string `email` claim is **rejected explicitly** even though Python's `str()`
  renders list brackets and so would have failed the shape gate anyway (as Ruby's does,
  unlike JavaScript's). Relying on `repr()` for a security decision is a coincidence,
  not a design.

**PyJWT has the same missing-`exp` hole as jose and the Ruby jwt gem** — it skips the
expiry check when the claim is absent rather than failing — so the verifier passes
`options={"require": ["exp"]}`. That makes three independent JWT libraries in three
languages with identical behaviour, which is no longer a coincidence but the default to
expect; gotcha 8 now says so. Each language's suite carries a negative-control test that
verifies the same token *without* the requirement and asserts it is accepted, so the
guard is provably load-bearing rather than decorative.

82 tests, offline. One of them parses `REASONS` out of `lib/cru_iap/token_verifier.rb`
**and** `src/reasons.ts` and asserts all three lists are identical — the first
mechanical check that the shared Datadog vocabulary hasn't drifted between languages,
which until now was maintained by hand and by hope.

### Added — `[docs]` two gaps found while surveying the remaining Cloud Run apps

Surveying the twelve apps still to cut over turned up two facts the README stated
nowhere, both of which cost a deploy cycle to learn rather than to read.

**The assertion carries no group membership** (gotcha 8c). No `groups` claim, and
nothing to derive one from — the pinned real capture's whole top-level claim set is
`aud`, `azp`, `email`, `exp`, `iat`, `identity_source`, `iss`, `sub`, and the nested
`workforce_identity`. This is the most expensive difference from an Okta OIDC
`id_token`, because a `groups` claim is how several apps currently decide *"may this
person be here?"* — flightdeck reads `OKTA_REQUIRED_GROUP`, and dgt and dse-portal both
reason from Okta app assignment. The coarse gate survives by moving into IAM
(`principalSet://…/group/<okta-group>` on `roles/iap.httpsResourceAccessor`, enforced
before the app is reached); what cannot survive app-side is a *finer* decision made from
the group, because the app can no longer see the membership that admitted the request.
The failure mode is silent and direction-dependent: a kept `required_group.in?(groups)`
rejects everyone, while a kept `groups&.include?` admits everyone.

**Surfaces that authenticate themselves need `bypass_paths`, not just an app-side
exemption.** IAP rejects at the load balancer, before the gate runs, so a webhook or a
cron POST never reaches the middleware that would have waved it through. The two halves
are not redundant: `bypass_paths` decides what reaches the app, the app-side exemption
decides what the app does with a request that arrives carrying no assertion. Omit the
terraform half and the surface is unreachable; omit the app half and it is
unauthenticated. Bills had nine such surfaces and flightdeck has a comparable set, so
the checklist now says to enumerate them deliberately.

### Removed — `[ruby]` two behaviors inherited from beacon that were based on a wrong theory

Investigation on 2026-07-25 recovered a captured live IAP payload (keep-zero POC
echoserver) and beacon-stage's Datadog logs on both sides of the cru-terraform
`google.email` attribute-mapping fix. Together they establish:

| mode | `email` | `sub` |
|---|---|---|
| plain IAP | bare address | `accounts.google.com:<opaque>` |
| WIF, mapping present | bare address | `sts.google.com:<opaque STS token>` |
| WIF, mapping absent | absent | `sts.google.com:<opaque STS token>` |

- **Removed `WORKFORCE_PRINCIPAL`.** The `principal://…/subject/<email>` URI is real
  but lives in the nested `workforce_identity.iam_principal` claim, which is what IAM
  bindings match — it never appears in `email` or `sub`. The commit that introduced
  the unwrapping claimed the shape was "observed live"; it was written 25 minutes
  before Rails logs first reached Datadog, so nothing had been observed. The regex was
  not neutral: it *accepted* a value the shape gate would otherwise have rejected.
- **Removed the `sub` fallback.** `sub` is an opaque namespaced token in every mode
  and can never yield an identity. Its only effect was to convert an accurate
  `missing_email` (= fix the pool's attribute mapping) into a misleading
  `malformed_subject`.

### Fixed
- `[ruby]` **`URI::MailTo::EMAIL_REGEXP` was not a sufficient shape gate.** RFC 5322 permits
  `/` in a local part, so `principal://iam.googleapis.com/.../subject/alice@cru.org`
  matches it in full and would have been persisted as a user whose email is that
  entire string. Found when removing the unwrapping regex above, which had been
  masking it. Values containing `/` or `\` are now rejected as `malformed_subject`.

### Added — `[ruby]` the initial extraction from beacon (2026-07-24)

Written up as 0.1.0 at the time but never tagged, so it is folded into this release
rather than being a version of its own. Followed beacon's IAP + Workforce Identity
Federation cutover, and preceded the same cutover in cru-bot.

- `CruIap::TokenVerifier` — verifies the IAP assertion JWT and extracts an email
  identity. Handles both IAP identity shapes: a plain `email` claim (plain IAP, where
  `sub` is a useless numeric id), and the WIF workforce principal URI in `sub` (all a
  workforce JWT carries — it has no `email` claim). Typed rejection reasons for
  telemetry.
- `TokenVerifier.from_request` — takes an `ActionDispatch::Request`, `Rack::Request`,
  or bare Rack env, so application code never names the header. `HEADER` /
  `RACK_ENV_KEY` are exposed for infra config and fixtures.
- `CruIap::StripForwardedHost` — Rack middleware that drops a client-forged
  `X-Forwarded-Host` before anything resolves `request.host`.
- `CruIap::TokenVerifier::REASONS` — the shared rejection vocabulary, asserted
  complete by a spec so it can't drift.
- `CruIap.logger` — null by default.

#### Changed from the beacon originals
- No Rails/ActiveSupport dependency; `googleauth` only, so it works in a plain Rack
  app.
- `audience:` is a keyword argument defaulting to `ENV["IAP_AUDIENCE"]`, rather than
  an unconditional env read.
- `logger:` is injected rather than hardcoded to `Rails.logger`.

Behavior is otherwise identical to `Beacon::IapTokenVerifier`; all of beacon's specs
were ported and pass unchanged in substance.

[0.1.0]: https://github.com/CruGlobal/cru-iap/releases/tag/v0.1.0
