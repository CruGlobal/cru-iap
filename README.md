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
- [ ] Cloud Run `--ingress=internal-and-cloud-load-balancing`. Otherwise the raw
      `*.run.app` URL reaches the app with **no IAP in front**. Identity still can't
      be forged (the JWT is signed), but every route must fail closed on a missing
      header — and a "no header → dev stub" fallback would be catastrophic there.
- [ ] `CruIap::StripForwardedHost` inserted at position 0
- [ ] Sign-in CTA links **`/?login=true`**, not `/`. Bare `/` loops.
- [ ] Sign-out redirects to **`/?gcp-iap-mode=CLEAR_LOGIN_COOKIE`** so IAP clears the
      federated login cookie
- [ ] Production logs emitted as JSON with a `severity` field, or Cloud Run drops
      Rails' stdout from the log sink and you'll debug the cutover blind

## Gotchas this gem encodes

Notes from beacon's cutover, kept here because they cost real deploy cycles:

1. **The identity claim differs by IAP mode, so the verifier reads both.**

   | | `email` claim | `sub` claim |
   |---|---|---|
   | Plain IAP (Google/Cloud Identity) | the identity | `accounts.google.com:<numeric id>` — useless |
   | WIF (what beacon-stage receives) | **absent entirely** | `principal://iam.googleapis.com/locations/global/workforcePools/<pool>/subject/<email>` |

   Hence `email` first, `sub` as fallback: that single ordering is correct in both
   modes. In plain-IAP mode a fallback to `sub` would yield a numeric string, which
   fails the email-shape gate and rejects — the right outcome.

2. **A workforce JWT missing its identity entirely usually means a missing
   `google.email` attribute mapping** on the pool provider. Fix the pool rather than
   leaning on the fallback.

   ⚠️ **Unverified:** whether a workforce pool *with* `google.email` correctly mapped
   then emits an `email` claim in the IAP JWT. Beacon has never run that
   configuration — every observation above comes from a pool without the mapping. If
   you get a correctly-mapped pool working, please confirm or correct this line.
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

`CruIap::TokenVerifier::REASONS` is the shared vocabulary, so every app behind IAP
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
logs. It defaults to a null logger until you set `CruIap.logger`.

## Development

```sh
bundle install
bundle exec rspec
```
