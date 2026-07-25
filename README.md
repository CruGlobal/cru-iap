# cru-iap

Request authentication for Cru apps behind **Google Identity-Aware Proxy**, with
Okta federated in via **Workforce Identity Federation**.

Extracted from [beacon](https://github.com/CruGlobal/beacon) after its 2026-07 IAP
cutover, ahead of the same cutover in cru-bot.

```ruby
gem "cru-iap", github: "CruGlobal/cru-iap"
```

## What it does

Two things, both of which are identical in every app behind IAP:

| | |
|---|---|
| `Cru::Iap::TokenVerifier` | Verify the `x-goog-iap-jwt-assertion` JWT; return an email identity or a typed rejection reason |
| `Cru::Iap::StripForwardedHost` | Drop a client-forged `X-Forwarded-Host` before anything reads `request.host` |

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
Cru::Iap.logger = Rails.logger
```

`IAP_AUDIENCE` is read from the environment by default. It is the **backend-service
resource path** (`/projects/NUMBER/global/backendServices/ID`), not a URL or a client
ID — cru-terraform sets it. Don't rename it with an app prefix; the terraform module
supplies it under that exact name.

### 2. Install the middleware

```ruby
# config/application.rb
config.middleware.insert_before 0, Cru::Iap::StripForwardedHost
```

### 3. Verify

```ruby
result = Cru::Iap::TokenVerifier.call(request.headers["x-goog-iap-jwt-assertion"])

if result.ok?
  user = User.from_iap(email: result.email, name: result.name)
else
  Rails.logger.warn("IAP auth rejected: #{result.reason}")
  nil # fail closed — never fall through to a dev stub
end
```

`.call` accepts `audience:` and `logger:` overrides if you'd rather not use the
env var / global logger.

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
  if iap_fronted_host?
    jwt = request.headers["x-goog-iap-jwt-assertion"]
    return Identity.new(user: user_from_iap(jwt), dev_stub: false) if jwt.present?
  end
  return Identity.new(user: DevAuthStub.user, dev_stub: true) if Rails.env.local?

  Identity.new(user: nil, dev_stub: false)
end
```

## Deployment checklist

- [ ] `IAP_AUDIENCE` set from the terraform module output
- [ ] Cloud Run `--ingress=internal-and-cloud-load-balancing`. Otherwise the raw
      `*.run.app` URL reaches the app with **no IAP in front**. Identity still can't
      be forged (the JWT is signed), but every route must fail closed on a missing
      header — and a "no header → dev stub" fallback would be catastrophic there.
- [ ] `Cru::Iap::StripForwardedHost` inserted at position 0
- [ ] Sign-in CTA links **`/?login=true`**, not `/`. Bare `/` loops.
- [ ] Sign-out redirects to **`/?gcp-iap-mode=CLEAR_LOGIN_COOKIE`** so IAP clears the
      federated login cookie
- [ ] Production logs emitted as JSON with a `severity` field, or Cloud Run drops
      Rails' stdout from the log sink and you'll debug the cutover blind

## Gotchas this gem encodes

Notes from beacon's cutover, kept here because they cost real deploy cycles:

1. **A workforce IAP JWT has no `email` claim at all.** The identity is `sub`, a
   `principal://iam.googleapis.com/locations/global/workforcePools/<pool>/subject/<subject>`
   URI. The verifier prefers `email`, falls back to `sub`.
2. **The root cause of that is usually a missing `google.email` attribute mapping**
   on the workforce pool provider. Fixing the pool is better than relying on the
   `sub` fallback — but keep the fallback.
3. **Unwrap the workforce URI before the generic `prefix:` split.** The URI contains
   colons; splitting first mangles it to `//iam.googleapis.com/…`.
4. **The subject is percent-encoded** — `alice%40cru.org`.
5. **Reject anything not email-shaped after unwrapping** (`malformed_subject`), and
   keep that reason distinct from `missing_email`. Different root causes, different
   fixes: a pool attribute-mapping gap vs. an unanticipated principal shape (group
   `principalSet://`, opaque subjects). Without the shape gate you persist garbage
   user rows.
6. **Fail closed when `IAP_AUDIENCE` is unset** rather than skipping the audience
   check.
7. **Load-balancer 302s masquerade as Rails redirects** when you're reading logs
   during a cutover. Check which layer actually issued them.

## Rejection reasons

`Cru::Iap::TokenVerifier::REASONS` is the shared vocabulary, so every app behind IAP
files the same Datadog queries. Entries ending in `:` carry a variable suffix.

`missing_token` · `missing_audience_config` · `bad_iss:` · `missing_email` ·
`malformed_subject` · `signature_error:` · `audience_mismatch` · `expired_token` ·
`issuer_mismatch` · `verification_error:` · `unexpected_error` · `iap_jwt` (the only
`ok?` reason)

A spec asserts every reason the verifier can produce is listed, so the vocabulary
can't drift silently.

## Logging

The verifier is silent except for two `warn`s: `malformed_subject` (which dumps the
full JWT payload, so an unexpected principal shape is diagnosable without
re-deploying instrumentation) and the fail-closed catch-all. The payload is identity
claims, not credentials — the same sensitivity as the emails already in your request
logs. It defaults to a null logger until you set `Cru::Iap.logger`.

## Development

```sh
bundle install
bundle exec rspec
```
