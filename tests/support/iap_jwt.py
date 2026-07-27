"""Minting real ES256-signed IAP assertions offline.

The mirror of ``test/support/iap-jwt.ts`` and the Ruby suite's equivalent: a
locally generated key, a JWKS served from it, and claim builders for each shape
IAP actually emits. Nothing here touches the network — the tokens are really
signed and really verified, just against our own key rather than Google's.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

AUDIENCE = "/projects/123456789/global/backendServices/9876543210"

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "spec" / "fixtures" / "real_wif_iap_payload.json"
)


class SigningKey:
    """A locally minted ES256 keypair, plus the JWKS that publishes it."""

    def __init__(self, kid: str = "test-key-1") -> None:
        self.kid = kid
        self._private = ec.generate_private_key(ec.SECP256R1())

    def sign(self, claims: dict[str, Any], *, kid: str | None = None) -> str:
        return jwt.encode(
            claims,
            self._private,
            algorithm="ES256",
            headers={"kid": kid if kid is not None else self.kid},
        )

    @property
    def jwk_set(self) -> dict[str, Any]:
        from jwt.algorithms import ECAlgorithm

        jwk = json.loads(ECAlgorithm.to_jwk(self._private.public_key()))
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}


class LocalJwks:
    """A stand-in for :class:`jwt.PyJWKClient` backed by an in-memory key set.

    Matches the one method the verifier calls, so the production code path is
    exercised without a network fetch. Deliberately not a PyJWKClient subclass:
    the point is to prove the verifier depends only on this narrow interface.
    """

    def __init__(self, key: SigningKey) -> None:
        self._key = key
        self._jwks = jwt.PyJWKSet.from_dict(key.jwk_set)

    def get_signing_key_from_jwt(self, token: str) -> Any:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        for candidate in self._jwks.keys:
            if candidate.key_id == kid:
                return candidate
        raise jwt.exceptions.PyJWKClientError(
            f'Unable to find a signing key that matches: "{kid}"'
        )


def iap_claims(**overrides: Any) -> dict[str, Any]:
    """A plain-IAP assertion: a Google/Cloud Identity session, bare email claim.

    Pass ``email=None`` to drop the claim entirely (the unmapped-pool case),
    rather than to set it to null.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "https://cloud.google.com/iap",
        "aud": AUDIENCE,
        "azp": AUDIENCE,
        "sub": "accounts.google.com:104291823410293841029",
        "email": "alice@cru.org",
        "iat": now - 30,
        "exp": now + 600,
    }
    return _apply(claims, overrides)


def wif_claims(**overrides: Any) -> dict[str, Any]:
    """A Workforce Identity Federation assertion, shaped like the real capture.

    Kept faithful to ``spec/fixtures/real_wif_iap_payload.json`` by a test that
    diffs the two claim sets — it caught a missing ``azp`` on the Ruby side.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "https://cloud.google.com/iap",
        "aud": AUDIENCE,
        "azp": AUDIENCE,
        "sub": "sts.google.com:AAFTZtu4HH_YB5N-0PKpuRFXZj-ziDJSvJCIhth-IjORtiSFUzzGWOVy",
        "email": "alice@cru.org",
        "iat": now - 30,
        "exp": now + 600,
        "identity_source": "WORKFORCE_IDENTITY",
        "workforce_identity": {
            "iam_principal": (
                "principal://iam.googleapis.com/locations/global/workforcePools/"
                "keepzero-okta-poc/subject/okta-user-9f31c0@cru.org"
            ),
            "workforce_pool_name": "locations/global/workforcePools/keepzero-okta-poc",
        },
    }
    return _apply(claims, overrides)


def real_capture_claims(**overrides: Any) -> dict[str, Any]:
    """The pinned real capture, re-timed and re-audienced.

    The captured signature is deliberately not stored and the pair expired 600s
    after capture, so specs re-sign these claims with the local key.
    """
    fixture = json.loads(FIXTURE_PATH.read_text())
    now = int(time.time())
    claims = dict(fixture["claims"])
    claims.update({"iat": now - 30, "exp": now + 600, "aud": AUDIENCE})
    return _apply(claims, overrides)


def _apply(claims: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    for key, value in overrides.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    return claims
