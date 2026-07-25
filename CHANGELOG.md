# Changelog

## [Unreleased]

## [0.1.0] - 2026-07-24

Initial extraction from beacon, following its IAP + Workforce Identity Federation
cutover and ahead of the same cutover in cru-bot.

### Added
- `Cru::Iap::TokenVerifier` — verifies the `x-goog-iap-jwt-assertion` JWT and
  extracts an email identity. Handles both IAP identity shapes: a plain `email`
  claim, and the WIF workforce principal URI in `sub` (which is all a workforce JWT
  carries — it has no `email` claim). Typed rejection reasons for telemetry.
- `Cru::Iap::StripForwardedHost` — Rack middleware that drops a client-forged
  `X-Forwarded-Host` before anything resolves `request.host`.
- `Cru::Iap::TokenVerifier::REASONS` — the shared rejection vocabulary, asserted
  complete by a spec so it can't drift.
- `Cru::Iap.logger` — null by default.

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
