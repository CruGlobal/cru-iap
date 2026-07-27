"""The verifier's behaviour, one example per decision it makes.

Mirrors ``test/unit/verifier.test.ts`` and the Ruby unit spec. Every token here
is really signed with ES256 and really verified — the only thing stubbed is
*whose* key it is.
"""

from __future__ import annotations

import logging
import time

import jwt
import pytest

from cru_iap import Result, is_known_reason, verify, verify_request
from tests.support.iap_jwt import AUDIENCE, LocalJwks, SigningKey, iap_claims


#: Distinguishes "no token argument, mint one" from "the token IS None", which
#: is itself a case worth covering — a header lookup that missed returns None.
_MINT = object()


@pytest.fixture
def run(key: SigningKey, jwks: LocalJwks):
    def _run(claims=None, *, token=_MINT, **options):
        if token is _MINT:
            token = key.sign(iap_claims() if claims is None else claims)
        options.setdefault("audience", AUDIENCE)
        options.setdefault("jwks", jwks)
        return verify(token, **options)

    return _run


class TestTheHappyPath:
    def test_accepts_a_valid_assertion_and_returns_the_email(self, run):
        result = run()

        assert result.ok is True
        assert result.reason == "iap_jwt"
        assert result.email == "alice@cru.org"

    def test_is_truthy_so_callers_can_branch_on_the_result_itself(self, run):
        assert bool(run()) is True

    def test_exposes_the_full_payload_for_callers_that_need_another_claim(self, run):
        result = run()

        assert result.payload is not None
        assert result.payload["sub"] == "accounts.google.com:104291823410293841029"

    def test_downcases_the_email(self, run):
        assert run(iap_claims(email="Alice@Cru.ORG")).email == "alice@cru.org"

    def test_strips_surrounding_whitespace_from_the_email(self, run):
        assert run(iap_claims(email="  alice@cru.org  ")).email == "alice@cru.org"

    def test_returns_the_name_claim_when_present(self, run):
        assert run(iap_claims(name="Alice Anderson")).name == "Alice Anderson"

    def test_degrades_a_blank_name_to_none(self, run):
        assert run(iap_claims(name="   ")).name is None

    def test_degrades_a_non_string_name_to_none_without_rejecting(self, run):
        # `name` is decoration, not identity — the caller falls back to the
        # email local part. The real WIF payload has no name claim at all.
        result = run(iap_claims(name=["Alice", "Anderson"]))

        assert result.ok is True
        assert result.name is None


class TestFailingClosed:
    def test_rejects_a_missing_token(self, run):
        assert run(token="").reason == "missing_token"

    def test_rejects_a_whitespace_only_token(self, run):
        assert run(token="   ").reason == "missing_token"

    def test_rejects_a_none_token(self, run):
        assert run(token=None).reason == "missing_token"

    def test_rejects_when_no_audience_is_configured(self, key, jwks, monkeypatch):
        # Fail closed rather than skipping the audience check — a misconfigured
        # deploy must never accept unaudienced tokens.
        monkeypatch.delenv("IAP_AUDIENCE", raising=False)
        result = verify(key.sign(iap_claims()), jwks=jwks)

        assert result.reason == "missing_audience_config"

    def test_rejects_a_blank_audience_env_var(self, key, jwks, monkeypatch):
        monkeypatch.setenv("IAP_AUDIENCE", "   ")

        assert verify(key.sign(iap_claims()), jwks=jwks).reason == "missing_audience_config"

    def test_reads_the_audience_from_the_environment_at_call_time(
        self, key, jwks, monkeypatch
    ):
        monkeypatch.setenv("IAP_AUDIENCE", AUDIENCE)

        assert verify(key.sign(iap_claims()), jwks=jwks).ok is True

    def test_rejects_a_token_signed_by_someone_else(self, run, jwks):
        stranger = SigningKey()

        result = run(token=stranger.sign(iap_claims()))

        assert result.ok is False
        assert result.reason.startswith("signature_error:")

    def test_rejects_a_kid_that_is_not_in_the_key_set(self, run, key):
        result = run(token=key.sign(iap_claims(), kid="not-a-real-kid"))

        assert result.reason == "signature_error:no_matching_key"

    def test_rejects_a_tampered_payload(self, run, key):
        token = key.sign(iap_claims())
        head, payload, signature = token.split(".")
        tampered = key.sign(iap_claims(email="attacker@evil.example"))
        forged = f"{head}.{tampered.split('.')[1]}.{signature}"

        result = run(token=forged)

        assert result.ok is False
        assert result.reason.startswith("signature_error:")

    def test_rejects_the_wrong_audience(self, run):
        assert run(iap_claims(aud="/projects/1/global/backendServices/2")).reason == (
            "audience_mismatch"
        )

    def test_rejects_the_wrong_issuer(self, run):
        assert run(iap_claims(iss="https://accounts.google.com")).reason == "issuer_mismatch"

    def test_rejects_an_expired_token(self, run):
        now = int(time.time())

        assert run(iap_claims(iat=now - 1200, exp=now - 600)).reason == "expired_token"

    def test_honours_a_leeway_for_a_just_expired_token(self, run):
        now = int(time.time())

        assert run(iap_claims(exp=now - 5), leeway_seconds=60).ok is True

    def test_rejects_an_assertion_with_no_expiry_at_all(self, run):
        assert run(iap_claims(exp=None)).reason == "missing_exp"

    def test_pyjwt_alone_would_have_accepted_the_expiryless_token(self, key, jwks):
        # The negative control for the test above, and the reason the `require`
        # option is there at all: PyJWT SKIPS the expiry check when `exp` is
        # absent rather than failing — the same hole jose and the Ruby jwt gem
        # both have. Without options={"require": ["exp"]} this token verifies,
        # and would keep verifying forever. Three independent JWT libraries in
        # three languages made the same choice; assume the next one does too.
        claims = iap_claims(exp=None)
        signing_key = jwks.get_signing_key_from_jwt(key.sign(claims))

        accepted = jwt.decode(
            key.sign(claims),
            signing_key.key,
            algorithms=["ES256"],
            audience=AUDIENCE,
            issuer="https://cloud.google.com/iap",
            options={"verify_exp": True},
        )

        assert "exp" not in accepted, "PyJWT accepted a token carrying no expiry"

    def test_rejects_an_hmac_signed_token_however_well_formed(self, run):
        # ES256 is pinned, so a key set that also published an HMAC or RSA key
        # could not be used to talk the verifier into a weaker check. The key is
        # oversized only to keep PyJWT's short-key warning out of the output.
        forged = jwt.encode(iap_claims(), "x" * 32, algorithm="HS256")

        result = run(token=forged)

        assert result.ok is False
        assert result.reason != "iap_jwt"


class TestTheEmailClaim:
    def test_rejects_a_missing_email_as_missing_email(self, run):
        assert run(iap_claims(email=None)).reason == "missing_email"

    def test_rejects_a_blank_email_as_missing_email(self, run):
        assert run(iap_claims(email="   ")).reason == "missing_email"

    def test_never_falls_back_to_sub(self, run):
        # `sub` is an opaque namespaced token in every IAP mode. A fallback
        # turns an accurate missing_email (go fix the pool's attribute_mapping)
        # into a misleading malformed_subject.
        result = run(iap_claims(email=None, sub="accounts.google.com:alice@cru.org"))

        assert result.reason == "missing_email"
        assert result.email is None

    def test_strips_the_accounts_google_com_namespace(self, run):
        assert run(iap_claims(email="accounts.google.com:alice@cru.org")).email == (
            "alice@cru.org"
        )

    def test_strips_the_sts_google_com_namespace(self, run):
        assert run(iap_claims(email="sts.google.com:alice@cru.org")).email == "alice@cru.org"

    def test_strips_an_identity_platform_namespace_containing_slashes(self, run):
        # securetoken.google.com/<project>/<tenant>: — the reason we split on
        # the first colon rather than matching a literal prefix list.
        claims = iap_claims(email="securetoken.google.com/proj/tenant:alice@cru.org")

        assert run(claims).email == "alice@cru.org"

    def test_rejects_a_value_that_is_not_an_address(self, run):
        assert run(iap_claims(email="not-an-address")).reason == "malformed_subject"

    def test_rejects_a_raw_principal_uri(self, run):
        principal = (
            "principal://iam.googleapis.com/locations/global/workforcePools/p/"
            "subject/alice@cru.org"
        )

        assert run(iap_claims(email=principal)).reason == "malformed_subject"

    def test_rejects_the_principal_uri_that_survives_the_colon_strip(self, run):
        # This is the interaction worth pinning. The RAW principal fails the
        # email regexp only because of the `principal:` scheme colon — but the
        # verifier strips everything up to the first colon before validating,
        # since that is how it removes the namespace. What survives,
        # "//iam.googleapis.com/.../subject/alice@cru.org", DOES match the
        # regexp: RFC 5322 permits "/" in a local part. Only the slash guard
        # rejects it. Each guard looks redundant alone; together they are not.
        survives = "//iam.googleapis.com/locations/global/workforcePools/p/subject/alice@cru.org"
        import re

        from cru_iap.verifier import _EMAIL_REGEXP

        assert _EMAIL_REGEXP.match(survives), "negative control: the regexp alone accepts this"

        assert run(iap_claims(email=f"principal:{survives}")).reason == "malformed_subject"

    def test_rejects_an_email_containing_a_backslash(self, run):
        assert run(iap_claims(email="cru\\alice@cru.org")).reason == "malformed_subject"

    def test_rejects_a_list_email_claim_rather_than_coercing_it(self, run):
        # Python's str(["a@cru.org"]) renders the brackets, so the shape gate
        # would have caught this anyway — unlike JavaScript, where
        # String(["a@cru.org"]) is "a@cru.org". Rejected explicitly regardless:
        # relying on repr() for a security decision is a coincidence.
        result = run(iap_claims(email=["alice@cru.org", "attacker@evil.example"]))

        assert result.reason == "malformed_subject"
        assert result.email is None

    def test_rejects_a_dict_email_claim(self, run):
        assert run(iap_claims(email={"address": "alice@cru.org"})).reason == (
            "malformed_subject"
        )

    def test_rejects_an_integer_email_claim(self, run):
        assert run(iap_claims(email=42)).reason == "malformed_subject"


class TestTheIssuerReassertion:
    def test_rejects_an_issuer_pyjwt_would_have_accepted(self, key, jwks, monkeypatch):
        # Belt and braces: PyJWT already checked `iss`. This proves the second
        # check is load-bearing by disabling the first — so a future refactor
        # that drops the `issuer=` argument can't silently widen who we trust.
        monkeypatch.setattr(
            "cru_iap.verifier.jwt.decode",
            lambda token, k, **kwargs: {
                **iap_claims(iss="https://evil.example"),
                "exp": int(time.time()) + 600,
            },
        )
        result = verify(key.sign(iap_claims()), audience=AUDIENCE, jwks=jwks)

        assert result.reason == "bad_iss:https://evil.example"


class TestKeySourceFailures:
    def test_reports_an_unreachable_key_set_as_a_key_source_error(self, run, key):
        class Unreachable:
            def get_signing_key_from_jwt(self, token):
                raise jwt.exceptions.PyJWKClientConnectionError("fetch failed")

        result = run(token=key.sign(iap_claims()), jwks=Unreachable())

        assert result.reason == "verification_error:KeySourceError"

    def test_reports_an_unparseable_key_set_as_a_key_source_error(self, run, key):
        class Garbage:
            def get_signing_key_from_jwt(self, token):
                raise jwt.exceptions.PyJWKClientError("Failed to decode the JWKS document")

        result = run(token=key.sign(iap_claims()), jwks=Garbage())

        assert result.reason == "verification_error:KeySourceError"


class TestTheFailClosedBackstop:
    def test_returns_unexpected_error_rather_than_raising(self, run, key):
        class Exploding:
            def get_signing_key_from_jwt(self, token):
                raise RuntimeError("something nobody anticipated")

        result = run(token=key.sign(iap_claims()), jwks=Exploding())

        assert result.ok is False
        assert result.reason == "unexpected_error"

    def test_survives_a_logger_that_raises(self, run, key):
        class BadLogger(logging.Logger):
            def warning(self, *args, **kwargs):
                raise RuntimeError("logging is broken")

        class Exploding:
            def get_signing_key_from_jwt(self, token):
                raise RuntimeError("something nobody anticipated")

        result = run(
            token=key.sign(iap_claims()),
            jwks=Exploding(),
            log=BadLogger("bad"),
        )

        assert result.reason == "unexpected_error"

    def test_never_returns_ok_on_any_failure_path(self, run, key):
        # Sweep: whatever goes wrong, `ok` is False and there is no email. This
        # is the invariant every caller depends on.
        failures = [
            {"token": ""},
            {"claims": iap_claims(email=None)},
            {"claims": iap_claims(email="not-an-address")},
            {"claims": iap_claims(aud="/wrong")},
            {"claims": iap_claims(exp=None)},
            {"token": SigningKey().sign(iap_claims())},
        ]
        for case in failures:
            result = run(**case)
            assert result.ok is False, case
            assert result.email is None, case
            assert result.payload is None, case


class TestTheReasonVocabulary:
    def test_every_reason_the_verifier_can_emit_is_in_the_shared_list(self, run, key):
        # The vocabulary is shared across four languages so Datadog queries
        # match. This catches a new reason invented in Python and nowhere else.
        cases = [
            {"token": ""},
            {"claims": iap_claims(email=None)},
            {"claims": iap_claims(email="not-an-address")},
            {"claims": iap_claims(aud="/wrong")},
            {"claims": iap_claims(iss="https://accounts.google.com")},
            {"claims": iap_claims(exp=None)},
            {"claims": iap_claims(exp=int(time.time()) - 600, iat=int(time.time()) - 1200)},
            {"token": SigningKey().sign(iap_claims())},
            {"token": key.sign(iap_claims(), kid="unknown")},
            {},
        ]
        for case in cases:
            reason = run(**case).reason
            assert is_known_reason(reason), f"{reason!r} is not in REASONS ({case})"

    def test_rejects_an_unknown_reason(self):
        assert is_known_reason("something_invented") is False

    def test_accepts_a_prefixed_reason_with_its_suffix(self):
        assert is_known_reason("signature_error:whatever the library said") is True


class TestVerifyRequest:
    def test_pulls_the_assertion_off_a_header_mapping(self, key, jwks):
        token = key.sign(iap_claims())

        result = verify_request(
            {"x-goog-iap-jwt-assertion": token}, audience=AUDIENCE, jwks=jwks
        )

        assert result.email == "alice@cru.org"

    def test_reports_missing_token_when_the_request_carries_no_header(self, jwks):
        result = verify_request({}, audience=AUDIENCE, jwks=jwks)

        assert result.reason == "missing_token"


def test_result_is_immutable():
    # Frozen so a caller can't launder a rejection into a pass by assignment.
    result = Result(ok=False, reason="missing_token")

    with pytest.raises(Exception):
        result.ok = True  # type: ignore[misc]
