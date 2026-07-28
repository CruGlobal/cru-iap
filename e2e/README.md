# e2e — verifying against real Google infrastructure

The offline suites in all four languages mint their own tokens, so none of them can
answer the question that matters most:

> Does a correctly configured workforce pool emit an `email` claim, and does this
> library accept the token Google actually mints?

These suites answer it. A real Okta sign-in federates through a real workforce identity
pool into a real IAP-fronted Cloud Run service; the assertion IAP injected is fed to each
library's verifier, which fetches Google's live JWKS to check the real signature.

> **No stack is currently deployed.** Both the Cloud infrastructure and the scratch Okta
> objects have been torn down. Standing this up again means creating both — see
> [Prerequisites](#prerequisites).

## Layout

| Path | What |
|---|---|
| `run_all.sh` | Capture once, verify in all four languages. The normal entry point. |
| `smoke.mjs` | Secret-free, browser-free checks. |
| `okta/` | Scratch IdP objects and the Playwright capture driver. |
| `terraform/` | The IAP stack the capture signs in to. |

## Prerequisites

1. **The IAP stack.** See [`terraform/README.md`](terraform/README.md) — it costs about
   \$18/month while running, so destroy it when you are not testing.
2. **The IdP objects.** See [`okta/README.md`](okta/README.md) for what to create and
   how to tear it down again.
3. **`okta/secrets.json`** — test-user password and TOTP shared secret. Gitignored,
   mode 0600.
4. **Playwright** — `npm --prefix e2e/okta install` (installs its own Chromium).
5. **Network egress** to your IdP, the load balancer, and `gstatic.com`.

## Quick start

```sh
e2e/run_all.sh                 # capture, then Ruby + Python + Go + TypeScript
e2e/run_all.sh --no-capture    # reuse the existing artifact (it lives ~10 min)
e2e/run_all.sh --only go,ts    # subset
e2e/run_all.sh --help
```

The browser login runs **once** and all four suites verify that one string. It is the
expensive, fragile part — three redirect chains and a TOTP challenge, one to three
minutes — and it is entirely language-agnostic, so four suites each driving their own
login would cost four times the wall clock and four independent chances to flake for no
additional coverage.

`run_all.sh` resolves the audience from `CRU_IAP_E2E_AUDIENCE` if set, and otherwise
from `terraform output -raw iap_audience`.

## Running one suite

Against an existing capture artifact:

```sh
bundle exec rake e2e
uv run pytest -m e2e
go test -tags e2e -count=1 ./cruiap/...
npm run test:e2e
```

None of these run under `rake default`, `uv run pytest`, `go test ./...`, or `npm test`.
Each is gated idiomatically for its language: a separate rake task, a deselected pytest
marker, a build tag, and a separate vitest project.

## Smoke checks

Neither needs a capture or any credential:

```sh
node e2e/smoke.mjs jwks                                   # runs in CI on every PR
node e2e/smoke.mjs iap-front --url https://your-host/ [--provider <substring>]
```

`jwks` checks that Google's key endpoint still serves ES256/P-256 — the one external
contract all four libraries share, so it gets the cheapest check on the most frequent
trigger. `iap-front` checks that a given host really is behind IAP, and needs a standing
stack.

## Environment overrides

Honoured by all four suites:

| Variable | Purpose |
|---|---|
| `CRU_IAP_E2E_CAPTURE` | Path to the capture artifact (default `e2e/okta/capture.json`) |
| `CRU_IAP_E2E_AUDIENCE` | The `IAP_AUDIENCE` to verify against |
| `CRU_IAP_E2E_EMAIL` | Expected signed-in address |
| `CRU_IAP_E2E_URL` | Sign-in URL the capture and probe scripts drive |

**No infrastructure values are hardcoded anywhere here.** Audience, expected email and
sign-in URL all resolve from the environment, the capture artifact, or
`terraform output` — and otherwise cause a clean error or a skip. Moving the stack to
another project touches no code.

`run_all.sh` fills in `CRU_IAP_E2E_AUDIENCE` from `terraform output -raw iap_audience`
and `CRU_IAP_E2E_URL` from `terraform output -raw login_url` when they are unset,
validating the shape of each so that Terraform's "no outputs found" warning cannot be
mistaken for a value.

## The capture artifact

`node e2e/okta/capture_assertion.mjs --json` writes `e2e/okta/capture.json`, gitignored
and mode 0600, because the assertion is a live credential for about ten minutes:

```json
{
  "captured_at": 1785170640,
  "url": "https://your-host/?login=true",
  "assertion": "eyJhbGciOiJFUzI1NiIs...",
  "claims": { "aud": "...", "email": "...", "exp": 1785171240, "...": "..." },
  "audience": "/projects/NUMBER/global/backendServices/BACKEND_ID",
  "expected_email": "your-test-user@example.com",
  "iap_headers": { "x-goog-authenticated-user-email": "sts.google.com:..." },
  "navigation_trail": ["https://...", "..."]
}
```

Two rules the loaders enforce, worth knowing if you are debugging a skip:

- **Staleness is keyed on the `exp` claim**, not on `captured_at`. `exp` is what actually
  decides whether a verify can succeed, and it comes from Google rather than from our
  clock. A capture within 30 seconds of expiry is refused.
- **The audience is configuration and is never read off the token.** Taking it from the
  `aud` claim would turn every positive verify into "does `aud` equal `aud`".

## A green run can mean "verified nothing"

Each suite **skips with a reason** when the artifact is absent, stale, or has no
audience. That is right for a developer with no stack, but it means four skipped suites
would otherwise print four passes and exit 0.

`run_all.sh` therefore preflights the artifact and **stops** if it is unusable. Anything
running these in CI needs the same property — assert the preflight ran, or a nightly
green is worthless.

## What the suites check

Twelve checks per language, in four groups:

1. **The assertion is genuinely live** — `iat` within 600 seconds, `exp` in the future.
   This guards everything else: a stale or hand-copied token fails here rather than
   quietly turning the suite into a re-test of the offline fixtures.
2. **It verifies** — against Google's live JWKS, and off a request object the way an
   application would.
3. **The pass is not vacuous** — the same genuine token with exactly one thing broken:
   edited payload, wrong backend service, no audience configured, and the same claims
   re-signed with a key of our own. Without these, "it verified" could mean the verifier
   accepts anything.
4. **The claim shape** — bare `email`, opaque `sub`, `principal://` only in the nested
   `workforce_identity` claim, and a key-for-key drift check against
   `spec/fixtures/real_wif_iap_payload.json`. That last one is the highest-value test
   here: if Google changes the shape, the offline suites in all four languages are
   modelling a fiction, and this is what says so.

## Contributing

Four loaders read the capture artifact and must stay in step:
`test/support/capture.ts`, `spec/support/live_capture.rb`, `tests/support/capture.py`,
and the one inside `cruiap/live_iap_e2e_test.go`.

Prefer adding a shared check to `smoke.mjs` over duplicating it four times. Keeping the
expected pool and provider ids in one place stops them rotting in four test files the day
the stack moves.

Note the current shape of this: it needs a developer to stand up a stack and drive a
browser. Moving it onto CI-owned, on-demand infrastructure is not done yet, so treat a
standing stack as a temporary thing you create and destroy rather than shared
infrastructure to depend on.
