"""The rejection vocabulary, shared verbatim with the Ruby gem
(``CruIap::TokenVerifier::REASONS``) and the TypeScript package
(``src/reasons.ts``), so every Cru app behind IAP — Rails, Node, or Python —
files the same Datadog queries.

Entries ending in ``:`` carry a variable suffix.

If you add one here, add it to the other three too — in the same ORDER, since
the cross-language tests compare them element by element (``tests/test_package.py``
checks Ruby and TypeScript against this list; ``cruiap/vocabulary_test.go`` checks
all three against Go's). A test in each language additionally asserts its own
verifier can only emit listed reasons.
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
    "iap_jwt",  #                 ok is True — a verified IAP assertion
    "dev_bypass",  #              ok is True — dev_bypass(), never in production
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
