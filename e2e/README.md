# e2e — verifying against real Google infrastructure

The offline suites in all four languages mint their own tokens. Nothing in them
can answer the question that actually matters:

> does a correctly configured workforce pool emit an `email` claim, and does
> this library accept the token Google actually mints?

That is what lives here. A real Okta sign-in federates through a real workforce
identity pool into a real IAP-fronted Cloud Run service, and the assertion IAP
injected is fed to each library's verifier, which fetches Google's real JWKS
over the real network to check the real signature.

## Layout

| Path | What |
|---|---|
| `smoke.mjs` | Secret-free, browser-free checks. `jwks` runs on every PR; `iap-front` needs a standing stack. |
| `run_all.sh` | Capture once, verify in all four languages. The normal entry point. |
| `okta/` | The scratch Okta objects and the Playwright capture driver. |
| `terraform/` | The IAP stack the capture signs in to. |

## The one-capture rule

The browser login is the expensive, fragile part — three redirect chains and a
TOTP challenge, 1–3 minutes on a good day. It is also entirely
language-agnostic: it produces one string.

So it runs **once**, and the four suites all verify that one string. Four suites
each driving their own login would be ~12 minutes and four independent chances
to flake, for no additional coverage.

```sh
e2e/run_all.sh                 # capture, then Ruby + Python + Go + TypeScript
e2e/run_all.sh --no-capture    # reuse the existing artifact (it lives ~10 min)
e2e/run_all.sh --only go,ts    # subset
```

Individual suites, against an existing artifact:

```sh
bundle exec rake e2e
uv run pytest -m e2e
go test -tags e2e -count=1 ./cruiap/...
npm run test:e2e
```

None of these run under `rake default`, `uv run pytest`, `go test ./...`, or
`npm test`. Each is gated a way that is idiomatic for its language: a separate
rake task, a deselected pytest marker, a build tag, a vitest project.

## The capture artifact

`node e2e/okta/capture_assertion.mjs --json` writes `e2e/okta/capture.json`
(gitignored, mode 0600 — the assertion is a live credential for ~10 minutes):

```json
{
  "captured_at": 1785170640,
  "url": "https://.../?login=true",
  "assertion": "eyJhbGciOiJFUzI1NiIs...",
  "claims": { "aud": "...", "email": "...", "exp": 1785171240, "...": "..." },
  "audience": "/projects/898330966415/global/backendServices/2605597618877293205",
  "expected_email": "cru-iap-e2e-test@example.invalid",
  "iap_headers": { "x-goog-authenticated-user-email": "sts.google.com:..." },
  "navigation_trail": ["https://...", "..."]
}
```

Four loaders read it and apply the same rules — `test/support/capture.ts`,
`spec/support/live_capture.rb`, `tests/support/capture.py`, and the one inside
`cruiap/live_iap_e2e_test.go`. Keep them in step:

- **Staleness is keyed on the `exp` claim**, not on `captured_at`. `exp` is what
  actually decides whether a verify can succeed, and it comes from Google rather
  than from our clock. A capture within 30s of expiry is refused.
- **`audience` is configuration and is never read off the token.** Taking it
  from the `aud` claim would turn every positive verify into "does `aud` equal
  `aud`". It comes from `terraform output -raw iap_audience`, via the
  `--audience` flag or `CRU_IAP_E2E_AUDIENCE`.
- **No infrastructure values are hardcoded in test code.** Audience and expected
  email resolve from the environment or the artifact, and otherwise cause a
  skip. Moving the stack to another project touches no test file.

Overrides, honoured by all four: `CRU_IAP_E2E_CAPTURE`,
`CRU_IAP_E2E_AUDIENCE`, `CRU_IAP_E2E_EMAIL`.

## Skipping vs failing

Each suite **skips with a reason** when the artifact is absent, stale, or has no
audience. That is right for a developer with no stack — but it means a green run
can mean "verified nothing".

`run_all.sh` therefore preflights the artifact and **stops** if it is unusable,
rather than letting four skipped suites print four passes and exit 0. Anything
running these in CI needs the same property: assert the preflight ran, or a
nightly green is worthless.

## What each suite covers

Twelve checks per language, in four groups:

1. **The assertion is genuinely live** — `iat` within 600s, `exp` in the future.
   Guards everything else: a stale or hand-copied token fails here rather than
   quietly turning the suite into a re-test of the offline fixtures.
2. **It verifies** — against Google's live JWKS, and off a request object the way
   an app would.
3. **The pass is not vacuous** — the same genuine token with exactly one thing
   broken: edited payload, wrong backend service, no audience configured, and
   the same claims re-signed with a key of our own. Without these, "it verified"
   could mean the verifier accepts anything.
4. **The claim shape** — bare `email`, opaque `sub`, `principal://` only in the
   nested `workforce_identity` claim, and a key-for-key drift check against
   `spec/fixtures/real_wif_iap_payload.json`. That last one is the highest-value
   test here: if Google changes the shape, the offline suites in all four
   languages are modelling a fiction, and this is what says so.

Two things deliberately live in `smoke.mjs` rather than being duplicated four
times:

- **Is IAP actually in front of the host** (`iap-front`) — needs no capture, and
  keeping the expected pool/provider id in one place stops it rotting in four
  test files the day the stack moves.
- **Does Google's key endpoint still serve ES256/P-256** (`jwks`) — wired into
  CI on every PR. It is the one external contract all four libraries share, so
  it gets the cheapest possible check on the most frequent trigger. Each
  library's own URL constant is pinned offline in its unit suite.

## Prerequisites

- `e2e/okta/secrets.json` — test-user password + TOTP shared secret (gitignored)
- `npm --prefix e2e/okta install` — Playwright and its chromium
- A standing IAP stack; see `terraform/README.md`
- Network egress to `cru.oktapreview.com`, the LB, and `gstatic.com`

See `../docs/e2e-durable-stack.md` for the plan to move this off the current
`test.cru.org` sandbox onto CI-owned, on-demand infrastructure in `cru.org`.
