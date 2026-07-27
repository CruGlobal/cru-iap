"""The rejection vocabulary, shared verbatim with the Ruby gem
(``CruIap::TokenVerifier::REASONS``) and the TypeScript package
(``src/reasons.ts``), so every Cru app behind IAP — Rails, Node, or Python —
files the same Datadog queries.

Entries ending in ``:`` carry a variable suffix.

If you add one here, add it to the other three too. A test in each language
asserts its own verifier can only emit listed reasons; nothing mechanically
enforces that the lists match each other, so keep them in step by hand.
"""

from __future__ import annotations

REASONS: tuple[str, ...] = (
    "missing_token",  #           header absent/blank
    "missing_audience_config",  # IAP_AUDIENCE unset — deploy misconfig
    "bad_iss:",  #                + the offending iss
    "missing_exp",  #             signed but with no expiry — never goes stale
    "missing_email",  #           no email claim — IAP/pool config gap
    "malformed_subject",  #       present but not an address
    "signature_error:",  #        + the underlying detail
    "audience_mismatch",
    "expired_token",
    "issuer_mismatch",
    "verification_error:",  #     + the PyJWT error name
    "unexpected_error",  #        fail-closed catch-all
    "iap_jwt",  #                 the only ok is True reason
)


def is_known_reason(reason: str) -> bool:
    """True if ``reason`` is a member of the shared vocabulary.

    Exact match for the plain entries, prefix match for the ones ending in
    ``:``.
    """
    return any(
        reason.startswith(known) if known.endswith(":") else reason == known
        for known in REASONS
    )
