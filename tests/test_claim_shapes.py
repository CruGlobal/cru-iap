"""The claim shapes IAP actually emits, each as a really-signed token.

The contents here mirror ``test/unit/claim-shapes.test.ts`` and
``spec/integration/claim_shapes_spec.rb`` example for example. All three suites
are anchored to the same pinned capture of a real Google assertion, so if the
languages ever disagree about what IAP sends, one of them goes red.
"""

from __future__ import annotations

import json

import pytest

from cru_iap import verify
from tests.support.iap_jwt import (
    AUDIENCE,
    FIXTURE_PATH,
    iap_claims,
    real_capture_claims,
    wif_claims,
)


@pytest.fixture
def run(key, jwks):
    def _run(claims):
        return verify(key.sign(claims), audience=AUDIENCE, jwks=jwks)

    return _run


class TestPlainIap:
    """A Google / Cloud Identity session."""

    def test_takes_identity_from_the_bare_email_claim(self, run):
        result = run(iap_claims())

        assert result.ok is True
        assert result.email == "alice@cru.org"

    def test_ignores_the_opaque_accounts_google_com_sub(self, run):
        result = run(iap_claims(sub="accounts.google.com:104291823410293841029"))

        assert result.ok is True
        assert result.email == "alice@cru.org"

    def test_rejects_with_missing_email_however_good_sub_looks(self, run):
        assert run(iap_claims(email=None)).reason == "missing_email"


class TestWorkforceIdentityFederation:
    def test_accepts_a_realistic_wif_payload_and_takes_identity_from_email(self, run):
        result = run(wif_claims())

        assert result.ok is True
        assert result.email == "alice@cru.org"
        assert result.payload["identity_source"] == "WORKFORCE_IDENTITY"

    def test_ignores_the_nested_iam_principal_even_when_it_names_someone_else(self, run):
        claims = wif_claims()
        claims["workforce_identity"]["iam_principal"] = (
            "principal://iam.googleapis.com/locations/global/workforcePools/p/"
            "subject/someone-else@cru.org"
        )

        assert run(claims).email == "alice@cru.org"

    def test_rejects_an_unmapped_pool_as_missing_email_not_malformed_subject(self, run):
        # A pool whose provider lacks `google.email` in its attribute_mapping.
        # The remedy is in terraform, and only missing_email names it.
        assert run(wif_claims(email=None)).reason == "missing_email"

    def test_does_not_recover_an_address_from_the_principal_uri(self, run):
        # The nested principal carries a perfectly good subject. Unwrapping it
        # would be accepting a value IAP never offered as an identity claim.
        claims = wif_claims(email=None)

        assert "okta-user-9f31c0" in claims["workforce_identity"]["iam_principal"]
        assert run(claims).email is None

    def test_the_assertion_carries_no_group_membership(self, run):
        # Gotcha 8c, asserted rather than left as prose: there is no groups
        # claim and nothing to derive one from. This is why the coarse authz
        # gate has to move into an IAM binding for flightdeck, dgt and
        # dse-portal, none of which can read a group app-side any more.
        result = run(wif_claims())

        assert "groups" not in result.payload
        assert not [claim for claim in result.payload if "group" in claim.lower()]


class TestThePinnedRealCapture:
    """Ground truth: verbatim claims from a live Google IAP assertion, captured
    2026-07-25 through a headless Okta sign-in. See the fixture's _provenance."""

    def test_verifies_when_re_signed_and_takes_identity_from_email(self, run):
        result = run(real_capture_claims())

        assert result.ok is True
        assert result.reason == "iap_jwt"
        assert result.email == "cru-iap-e2e-test@example.invalid"
        # The real WIF payload carries no name claim at all — the email
        # local-part fallback is the production path, not the exception.
        assert result.name is None

    def test_still_verifies_with_the_nested_workforce_identity_claim_removed(self, run):
        assert run(real_capture_claims(workforce_identity=None)).ok is True

    def test_rejects_the_real_payload_with_its_email_stripped(self, run):
        assert run(real_capture_claims(email=None)).reason == "missing_email"

    def test_keeps_the_synthetic_wif_helper_faithful_to_the_real_claim_set(self):
        # If Google adds or renames a top-level claim, this fails and the rest
        # of the suite stops silently testing a fiction. It earned its keep on
        # the Ruby side immediately by catching a missing `azp`.
        fixture = json.loads(FIXTURE_PATH.read_text())
        synthetic = set(wif_claims())
        missing = [claim for claim in fixture["claims"] if claim not in synthetic]

        assert missing == [], f"real payload has claims the synthetic helper lacks: {missing}"

    def test_agrees_with_the_other_languages_about_what_the_real_payload_means(self, run):
        # All four languages read this same fixture and must reach the same
        # verdict. Stated as an explicit assertion rather than left implicit,
        # because the fixture is the only shared artefact between the suites.
        result = run(real_capture_claims())

        assert (result.ok, result.reason, result.email, result.name) == (
            True,
            "iap_jwt",
            "cru-iap-e2e-test@example.invalid",
            None,
        )
