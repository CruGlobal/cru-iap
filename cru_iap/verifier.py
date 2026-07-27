"""Verify the Google-signed JWT that Identity-Aware Proxy injects on every
request it lets through to a backend, and extract an email identity.

A direct port of ``CruIap::TokenVerifier`` (lib/cru_iap/token_verifier.rb) and
``src/verifier.ts``. All three share a rejection vocabulary and every
claim-shape decision; keep them in step. The differences are deliberate and
noted below:

- **PyJWT** rather than ``google-auth`` or authlib. ``google.oauth2.id_token``
  has no typed exception per failure mode — it raises ``ValueError`` with a
  prose message for a bad audience, a bad issuer, and an expired token alike,
  which would leave the shared reason vocabulary matched on substrings. PyJWT
  gives one exception class per condition, and ``PyJWKClient`` caches the key
  set (``lifespan``) the way Ruby's googleauth memoizes for an hour, so this can
  be called per request without a gstatic.com round-trip each time. authlib was
  the other candidate — the two FastAPI consumers already depend on it — but
  its JWK handling has no caching client at all.

- **Synchronous.** PyJWT and its key fetch are blocking. The two known
  consumers (dgt, dse-portal) are async FastAPI apps, so their dependency
  should call this in a threadpool — FastAPI does that automatically for a
  ``def`` (not ``async def``) dependency, which is the recommended wiring in
  the README.

- **Logging follows the Python convention** rather than the gem's
  ``CruIap.logger =`` setter: this module logs to ``logging.getLogger("cru_iap")``
  with a :class:`~logging.NullHandler` attached, so it is silent until the
  application configures logging, and there is no global to set.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import jwt
from jwt import PyJWKClient

from .request import assertion_from

__all__ = [
    "IAP_ISSUER",
    "IAP_JWKS_URL",
    "Result",
    "reset_jwks_cache",
    "verify",
    "verify_request",
]

IAP_ISSUER = "https://cloud.google.com/iap"

#: Google's IAP JWKS. Note the ``-jwk`` suffix: the bare
#: ``.../iap/verify/public_key`` endpoint serves a PEM map instead, which is not
#: parseable as a JWK set.
IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk"

#: IAP signs with ES256. Pinning it means a future key set that also published
#: an RSA or HMAC key could not be used to talk us into a weaker verification.
_IAP_ALGORITHMS = ["ES256"]

#: How long PyJWKClient may serve the key set from cache, matching the Ruby
#: googleauth key source's one hour.
_JWKS_LIFESPAN_SECONDS = 3600

#: ``URI::MailTo::EMAIL_REGEXP``, ported character-for-character from Ruby so
#: all three verifiers accept and reject exactly the same strings.
_EMAIL_REGEXP = re.compile(
    r"\A[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\Z"
)

#: ``_EMAIL_REGEXP`` alone is not a sufficient shape gate. RFC 5322 permits "/"
#: in a local part, so a URI-shaped value ending in an address — e.g.
#: ``principal://iam.googleapis.com/.../subject/alice@cru.org`` — MATCHES it,
#: and would be persisted as a user whose email is that entire string. No real
#: Okta or Google identity contains a slash or a backslash, so treat either as
#: proof we are looking at a URI or principal rather than an address.
_NEVER_IN_AN_EMAIL = re.compile(r"[/\\]")

logger = logging.getLogger("cru_iap")
logger.addHandler(logging.NullHandler())


@dataclass(frozen=True)
class Result:
    """The outcome of a verification.

    ``ok`` is the only thing a caller must branch on; ``reason`` is for
    telemetry and is drawn from the vocabulary shared with the Ruby, TypeScript
    and Go siblings. ``email`` and ``name`` are populated only when ``ok``.
    """

    ok: bool
    reason: str
    email: str | None = None
    name: str | None = None
    payload: dict[str, Any] | None = field(default=None, repr=False)

    def __bool__(self) -> bool:
        return self.ok


def _reject(reason: str) -> Result:
    return Result(ok=False, reason=reason)


_jwks_client: PyJWKClient | None = None


def _shared_jwks() -> PyJWKClient:
    # Lazily constructed: building it at import time would fire a network
    # request from any module that merely imports this package.
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            IAP_JWKS_URL, cache_keys=True, lifespan=_JWKS_LIFESPAN_SECONDS
        )
    return _jwks_client


def reset_jwks_cache() -> None:
    """Drop the cached key set.

    Only useful in tests, where a stubbed key client must not be served from a
    cache populated by a previous example — the mirror of googleauth's
    ``Google::Auth::IDTokens.forget_sources!``.
    """
    global _jwks_client
    _jwks_client = None


def verify_request(
    source: Any,
    *,
    audience: str | None = None,
    jwks: Any = None,
    leeway_seconds: float = 0,
    log: logging.Logger | None = None,
) -> Result:
    """Preferred entry point: pulls the assertion off the request itself, so
    application code never has to name the header.

    ``source`` may be a Starlette/FastAPI ``Request``, a Django
    ``HttpRequest``, a Flask/Werkzeug ``request``, a WSGI ``environ``, or a
    plain header mapping. See :func:`cru_iap.request.assertion_from`.
    """
    return verify(
        assertion_from(source),
        audience=audience,
        jwks=jwks,
        leeway_seconds=leeway_seconds,
        log=log,
    )


def verify(
    assertion: str | None,
    *,
    audience: str | None = None,
    jwks: Any = None,
    leeway_seconds: float = 0,
    log: logging.Logger | None = None,
) -> Result:
    """Verify a raw assertion JWT.

    Never raises — every path returns a :class:`Result`. The outer ``except`` is
    the fail-closed backstop: a caller's logger raising, or a PyJWT version
    raising something unanticipated, must not turn an authentication check into
    an exception that some framework's error handler renders as a 500 (or worse,
    that a bare ``except`` upstream swallows into a pass).

    :param audience: backend-service resource path. Defaults to
        ``os.environ["IAP_AUDIENCE"]``, read at call time so a test can set it
        per-example.
    :param jwks: key source, anything exposing
        ``get_signing_key_from_jwt(token).key``. Defaults to a module-level
        :class:`~jwt.PyJWKClient` over :data:`IAP_JWKS_URL`, shared across calls
        so its cache is actually a cache.
    :param leeway_seconds: clock tolerance for ``exp``/``nbf``. Defaults to 0.
    :param log: defaults to the ``cru_iap`` logger.
    """
    active_log = log if log is not None else logger
    try:
        return _attempt_verify(
            assertion,
            audience=audience,
            jwks=jwks,
            leeway_seconds=leeway_seconds,
            log=active_log,
        )
    except BaseException as error:  # noqa: BLE001 — fail-closed backstop
        try:
            active_log.warning(
                "[cru-iap] unexpected %s: %s", type(error).__name__, error
            )
        except Exception:  # pragma: no cover — a logger that raises is the case this exists for
            pass
        return _reject("unexpected_error")


def _attempt_verify(
    assertion: str | None,
    *,
    audience: str | None,
    jwks: Any,
    leeway_seconds: float,
    log: logging.Logger,
) -> Result:
    resolved_audience = (
        audience if audience is not None else os.environ.get("IAP_AUDIENCE", "")
    ).strip()
    token = (assertion or "").strip()

    if not token:
        return _reject("missing_token")
    # Fail closed if unset, so a misconfigured deploy never accepts unaudienced
    # tokens.
    if not resolved_audience:
        return _reject("missing_audience_config")

    key_source = jwks if jwks is not None else _shared_jwks()

    try:
        signing_key = key_source.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=_IAP_ALGORITHMS,
            audience=resolved_audience,
            issuer=IAP_ISSUER,
            leeway=leeway_seconds,
            # PyJWT treats `exp` as optional and simply skips the expiry check
            # when it is absent — the same trap the Ruby jwt gem and jose both
            # have. Require it, so a validly signed assertion carrying no expiry
            # can never be accepted forever. IAP always sets one; this just
            # removes the dependency on that staying true.
            options={"require": ["exp"]},
        )
    except Exception as error:  # noqa: BLE001 — mapped to the vocabulary below
        return _reject(_reason_for_error(error))

    # Belt-and-braces: PyJWT already enforced `issuer` above. Re-assert so a
    # future change that drops that argument can't silently widen who we trust.
    iss = payload.get("iss")
    if iss != IAP_ISSUER:
        return _reject(f"bad_iss:{'' if iss is None else iss}")

    raw_email = payload.get("email")
    # A non-string `email` is something that arrived and is not an address, so
    # it belongs in malformed_subject alongside the other bad shapes — not in
    # missing_email. Rejected outright rather than coerced. Python's
    # str(["a@cru.org"]) renders the brackets and so would have been caught by
    # the shape gate anyway (as in Ruby, unlike JavaScript, where
    # String(["a@cru.org"]) is "a@cru.org" and a multi-address array claim would
    # coerce into a single accepted identity) — but relying on repr() for a
    # security decision is a coincidence, not a design.
    if raw_email is not None and not isinstance(raw_email, str):
        log.warning(
            "[cru-iap] malformed subject: email claim is %s payload=%s",
            type(raw_email).__name__,
            _describe(payload),
        )
        return _reject("malformed_subject")

    email = _normalize_email(raw_email)
    # Two distinct failure reasons on purpose. `missing_email` = the pool never
    # sent one, which is an infrastructure fix (see _normalize_email).
    # `malformed_subject` = something arrived that isn't an address. Different
    # fixes — keep them distinguishable in Datadog.
    if not email:
        return _reject("missing_email")

    if not _EMAIL_REGEXP.match(email) or _NEVER_IN_AN_EMAIL.search(email):
        # Log the raw claims so a rejection is diagnosable without re-deploying
        # instrumentation. Identity claims, not credentials — same sensitivity
        # as the emails already in request logs.
        log.warning(
            "[cru-iap] malformed subject: normalized=%r payload=%s",
            email,
            _describe(payload),
        )
        return _reject("malformed_subject")

    # String-only, for the same reason as `email`. A non-string here is not
    # worth rejecting the whole request over — `name` is decoration, not
    # identity — so it degrades to None and the caller's local-part fallback
    # takes over. (The real WIF payload has no `name` claim at all, so that
    # fallback is the production path anyway.)
    raw_name = payload.get("name")
    name = raw_name.strip() if isinstance(raw_name, str) else ""
    return Result(
        ok=True,
        reason="iap_jwt",
        email=email,
        name=name or None,
        payload=payload,
    )


def _reason_for_error(error: Exception) -> str:
    """Map a PyJWT failure onto the shared vocabulary.

    PyJWT's typed exceptions are the main reason this package doesn't use
    ``google-auth``, which reports a bad audience, a bad issuer and an expired
    token all as ``ValueError`` with a prose message.

    Ordering matters: ``MissingRequiredClaimError``, ``InvalidAudienceError``
    and the rest all subclass ``InvalidTokenError``, and
    ``PyJWKClientConnectionError`` subclasses ``PyJWKClientError``.
    """
    if isinstance(error, jwt.ExpiredSignatureError):
        return "expired_token"

    if isinstance(error, jwt.MissingRequiredClaimError):
        # Only reachable via options={"require": [...]} above — an exp that is
        # present but past raises ExpiredSignatureError instead.
        claim = getattr(error, "claim", None)
        if claim == "exp":
            return "missing_exp"
        return f"verification_error:ClaimValidationFailed_{claim}"

    if isinstance(error, jwt.InvalidAudienceError):
        return "audience_mismatch"

    if isinstance(error, jwt.InvalidIssuerError):
        return "issuer_mismatch"

    if isinstance(error, jwt.InvalidAlgorithmError):
        return "verification_error:AlgNotAllowed"

    if isinstance(error, jwt.InvalidSignatureError):
        return f"signature_error:{error}"

    # Couldn't reach or parse Google's key set. Matches the Ruby and TypeScript
    # sides' `verification_error:KeySourceError`, which is the same condition —
    # the reason names the fault, not the library's class name, so all three
    # agree.
    if isinstance(error, jwt.exceptions.PyJWKClientConnectionError):
        return "verification_error:KeySourceError"

    if isinstance(error, jwt.exceptions.PyJWKClientError):
        # PyJWKClient raises the plain base class for two unrelated conditions,
        # distinguishable only by message: no key in the JWKS matches the
        # token's `kid`, and a JWKS that fetched but wouldn't parse. The Ruby
        # side surfaces the former as a SignatureError ("Token not verified as
        # issued by Google") and the TypeScript side as
        # `signature_error:no_matching_key`, so keep it in that bucket rather
        # than splitting the Datadog query.
        if "signing key" in str(error).lower():
            return "signature_error:no_matching_key"
        return "verification_error:KeySourceError"

    if isinstance(error, jwt.DecodeError):
        return f"signature_error:{error}"

    if isinstance(error, jwt.InvalidTokenError):
        return f"verification_error:{type(error).__name__}"

    # Anything else is not a PyJWT failure at all — let the fail-closed backstop
    # in `verify` log and classify it, so there is exactly one place that decides
    # what "unexpected" means.
    raise error


def _describe(payload: dict[str, Any]) -> str:
    try:
        return json.dumps(payload, default=str, sort_keys=True)
    except Exception:  # pragma: no cover — defensive; a payload is JSON by construction
        return repr(payload)


def _normalize_email(raw: Any) -> str:
    """Pull an email identity out of the ``email`` claim.

    ``email`` is the identity in every IAP mode. ``sub`` is NEVER an identity —
    it is an opaque namespaced token — so this deliberately does not read it.
    Confirmed 2026-07-24 against a captured live workforce payload
    (``spec/fixtures/real_wif_iap_payload.json``):

    ==========================  ==================  ============================
    mode                        email               sub
    ==========================  ==================  ============================
    plain IAP (Google id)       bare address        accounts.google.com:<opaque>
    WIF, google.email mapped    bare address        sts.google.com:<opaque STS>
    WIF, mapping absent         ABSENT              sts.google.com:<opaque STS>
    ==========================  ==================  ============================

    The third row is a broken pool, and no app-side fallback can recover an
    address from it. Reaching for ``sub`` there buys nothing and costs
    diagnosis: it turns an accurate ``missing_email`` (= go fix the pool's
    ``attribute_mapping``) into a misleading ``malformed_subject``.

    NB the workforce principal URI
    (``principal://iam.googleapis.com/.../subject/<email>``) IS real, but it
    lives in the nested ``workforce_identity.iam_principal`` claim — it is the
    string IAM bindings match, not an identity claim, and it never appears in
    ``email`` or ``sub``.

    Strip a leading ``<prefix>:`` namespace before validating: a real email
    never contains a colon, so the first colon is always the IAP namespace.
    Observed prefixes are ``accounts.google.com:``, ``sts.google.com:``, and
    Identity Platform's ``securetoken.google.com/<project>/<tenant>:`` — split
    on the first colon rather than matching any literal prefix.

    Then downcase, to match the usual lowercased email column.
    """
    if not isinstance(raw, str):
        return ""
    email = raw.strip()
    _, separator, remainder = email.partition(":")
    if separator:
        email = remainder
    return email.lower()
