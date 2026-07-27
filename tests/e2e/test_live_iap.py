"""End-to-end against LIVE Google infrastructure.

Nothing here is stubbed. A real Okta sign-in federates through a real workforce
identity pool into a real IAP-fronted Cloud Run service, and the assertion
Google actually injected is fed to the verifier — which fetches Google's real
JWKS over the real network to check the real signature.

The Python sibling of test/e2e/live-iap.test.ts, verifying the SAME captured
assertion. The capture is not driven from here; see tests/support/capture.py.

    e2e/run_all.sh                 # capture once, run all four languages
    uv run pytest -m e2e           # this suite alone, against an existing capture

Deselected by default via `-m "not e2e"` in pyproject.toml, so `uv run pytest`
stays offline.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest

from cru_iap import HEADER, verify, verify_request
from tests.support.capture import load_capture
from tests.support.iap_jwt import SigningKey

_loaded = load_capture()
# Module-level skip: without a capture there is nothing for any test here to say.
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(isinstance(_loaded, str), reason=str(_loaded)),
]


@pytest.fixture(scope="module")
def capture():
    return _loaded


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class TestTheRealAssertion:
    def test_was_minted_by_google_minutes_ago(self, capture):
        """Guards the whole module.

        Every assertion below is only meaningful if the capture really drove a
        live sign-in. A stale or hand-copied token fails here rather than
        silently making the rest of the suite a re-test of the offline fixtures.
        """
        age = int(time.time()) - int(capture.claims["iat"])

        assert age >= 0
        assert age < 600, "assertion is stale — did the capture actually run?"
        assert int(capture.claims["exp"]) > int(time.time())

    def test_verifies_against_googles_live_jwks(self, capture):
        # No `jwks` argument: this goes over the wire to
        # https://www.gstatic.com/iap/verify/public_key-jwk and checks the
        # signature Google produced with a key we have never seen.
        result = verify(capture.assertion, audience=capture.audience)

        assert result.ok
        assert result.reason == "iap_jwt"
        assert result.email == capture.expected_email

    def test_verifies_straight_off_a_request_carrying_the_header(self, capture):
        result = verify_request({HEADER: capture.assertion}, audience=capture.audience)

        assert result.ok
        assert result.email == capture.expected_email

    def test_has_no_name_claim(self, capture):
        """Display names must fall back to the email local part."""
        result = verify(capture.assertion, audience=capture.audience)

        assert result.name is None


class TestThePassIsNotVacuous:
    """Each of these takes the SAME genuine token and breaks exactly one thing.

    Without them, "it verified" could mean the verifier accepts anything.
    """

    def test_rejects_the_genuine_token_once_its_payload_is_edited(self, capture):
        header, payload, signature = capture.assertion.split(".")
        claims = json.loads(_b64url_decode(payload))
        claims["email"] = "attacker@evil.example"
        tampered = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        forged = ".".join([header, tampered, signature])

        result = verify(forged, audience=capture.audience)

        assert not result.ok
        assert result.reason.startswith("signature_error:")
        assert result.email is None

    def test_rejects_the_genuine_token_against_a_different_backend_service(self, capture):
        # Same project, different backend-service id: the shape is right and
        # only the value is wrong, which is the realistic misconfiguration.
        other = capture.audience.rsplit("/", 1)[0] + "/1111111111111111111"
        assert other != capture.audience

        result = verify(capture.assertion, audience=other)

        assert not result.ok
        assert result.reason == "audience_mismatch"

    def test_rejects_the_genuine_token_when_no_audience_is_configured(self, capture):
        result = verify(capture.assertion, audience="")

        assert not result.ok
        assert result.reason == "missing_audience_config"

    def test_rejects_the_same_claims_re_signed_by_a_key_of_our_own(self, capture):
        # Proof that the JWKS fetch is load-bearing: identical payload, valid
        # ES256 signature, key Google never published.
        now = int(time.time())
        ours = SigningKey(kid="not-googles-key")
        forged = ours.sign({**capture.claims, "iat": now - 30, "exp": now + 600})

        result = verify(forged, audience=capture.audience)

        assert not result.ok
        assert result.reason == "signature_error:no_matching_key"


class TestTheClaimShapeProductionActuallyEmits:
    def test_puts_a_bare_address_in_email(self, capture):
        """No namespace prefix — the prefix is on the sibling header, not here."""
        assert capture.claims["email"] == capture.expected_email
        assert ":" not in capture.claims["email"]

    def test_puts_an_opaque_sts_token_in_sub_which_is_not_an_identity(self, capture):
        assert str(capture.claims["sub"]).startswith("sts.google.com:")
        assert "@" not in str(capture.claims["sub"])

    def test_puts_principal_uri_only_in_the_nested_workforce_identity_claim(self, capture):
        workforce = capture.claims["workforce_identity"]

        assert workforce["iam_principal"].startswith("principal://iam.googleapis.com/")
        assert "principal://" not in str(capture.claims["sub"])
        assert "principal://" not in str(capture.claims["email"])

    def test_still_matches_the_pinned_capture_claim_for_claim(self, capture):
        """Drift detector against production Google.

        If this fails, the offline suites in ALL FOUR languages are modelling a
        shape that no longer exists — re-capture and update
        spec/fixtures/real_wif_iap_payload.json.
        """
        fixture = (
            Path(__file__).resolve().parents[2]
            / "spec"
            / "fixtures"
            / "real_wif_iap_payload.json"
        )
        pinned = json.loads(fixture.read_text())["claims"]

        assert sorted(capture.claims.keys()) == sorted(pinned.keys())
