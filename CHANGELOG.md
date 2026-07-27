# Changelog

This repo now ships **two** libraries from one source of truth: the `cru_iap` Ruby gem
and the `@cruglobal/cru-iap` npm package. Entries below are marked `[ruby]`, `[ts]`, or
`[both]`.

## [Unreleased]

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

## [0.1.0] - 2026-07-24

Initial extraction from beacon, following its IAP + Workforce Identity Federation
cutover and ahead of the same cutover in cru-bot.

### Added
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

### Changed from the beacon originals
- No Rails/ActiveSupport dependency; `googleauth` only, so it works in a plain Rack
  app.
- `audience:` is a keyword argument defaulting to `ENV["IAP_AUDIENCE"]`, rather than
  an unconditional env read.
- `logger:` is injected rather than hardcoded to `Rails.logger`.

Behavior is otherwise identical to `Beacon::IapTokenVerifier`; all of beacon's specs
were ported and pass unchanged in substance.

[Unreleased]: https://github.com/CruGlobal/cru-iap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CruGlobal/cru-iap/releases/tag/v0.1.0
