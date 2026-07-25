# cru-iap

Request authentication for Cru apps behind **Google Identity-Aware Proxy**, with
Okta federated in via **Workforce Identity Federation**.

Extracted from [beacon](https://github.com/CruGlobal/beacon) after its 2026-07 IAP
cutover, ahead of the same cutover in cru-bot.

```ruby
gem "cru_iap", github: "CruGlobal/cru-iap"
```

(Underscored gem name, hyphenated repo — so `Bundler.require` resolves straight to
`lib/cru_iap.rb` without a shim file.)

## What it does

Two things, both of which are identical in every app behind IAP:

| | |
|---|---|
| `CruIap::TokenVerifier` | Verify the IAP assertion JWT on a request; return an email identity or a typed rejection reason |
| `CruIap::StripForwardedHost` | Drop a client-forged `X-Forwarded-Host` before anything reads `request.host` |

No Rails or ActiveSupport dependency — `googleauth` only.

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

## Usage

### 1. Configure

```ruby
# config/initializers/iap.rb
CruIap.logger = Rails.logger
```

`IAP_AUDIENCE` is read from the environment by default. It is the **backend-service
resource path** (`/projects/NUMBER/global/backendServices/ID`), not a URL or a client
ID — cru-terraform sets it. Don't rename it with an app prefix; the terraform module
supplies it under that exact name.

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
   permits `/` in a local part, so a URI-shaped value ending in an address —
   `principal://iam.googleapis.com/.../subject/alice@cru.org` — *matches* it, and
   would be persisted as a user whose email is that entire string. Reject anything
   containing a slash as well.

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

9. **Load-balancer 302s masquerade as Rails redirects** when you are reading logs
   during a cutover. Check which layer actually issued them.

10. **Get logs flowing before you theorize.** Two of the wrong turns above were guesses
   written while Rails stdout was not reaching Datadog at all — the commit claiming a
   shape was "observed live" predated log visibility by 25 minutes. Fixing the
   telemetry is cheaper than a deploy cycle.

## Rejection reasons

`CruIap::TokenVerifier::REASONS` is the shared vocabulary, so every app behind IAP
files the same Datadog queries. Entries ending in `:` carry a variable suffix.

`missing_token` · `missing_audience_config` · `bad_iss:` · `missing_exp` ·
`missing_email` · `malformed_subject` · `signature_error:` · `audience_mismatch` ·
`expired_token` · `issuer_mismatch` · `verification_error:` · `unexpected_error` ·
`iap_jwt` (the only `ok?` reason)

A spec asserts every reason the verifier can produce is listed, so the vocabulary
can't drift silently.

## Logging

The verifier is silent except for two `warn`s: `malformed_subject` (which dumps the
full JWT payload, so an unexpected principal shape is diagnosable without
re-deploying instrumentation) and the fail-closed catch-all. The payload is identity
claims, not credentials — the same sensitivity as the emails already in your request
logs. It defaults to a null logger until you set `CruIap.logger`.

## Development

```sh
bundle install
bundle exec rspec
```
