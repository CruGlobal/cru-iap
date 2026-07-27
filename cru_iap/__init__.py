"""Request authentication for Cru apps behind Google Identity-Aware Proxy, with
Okta federated in via Workforce Identity Federation.

The Python sibling of the ``cru_iap`` Ruby gem and the ``@cruglobal/cru-iap`` npm
package. All three share a rejection vocabulary and the same pinned capture of a
real Google assertion, so they cannot quietly drift apart about what IAP sends.

Scoped deliberately to the part that does NOT vary between apps — *"who is
this?"*. Everything downstream stays in the app: the user model, the session,
how a rejection is rendered, the dev bypass, and authorization. Those diverged
immediately across consumers; see the README.

    from cru_iap import verify_request

    result = verify_request(request)
    if result.ok:
        user = provision(email=result.email, name=result.name)
    else:
        log.warning("IAP auth rejected: %s", result.reason)
        # fail closed — never fall through to a dev stub
"""

from __future__ import annotations

from .dev_bypass import (
    CLOUD_MARKERS,
    DEV_BYPASS_EMAIL_VAR,
    DEV_BYPASS_NAME_VAR,
    dev_bypass,
)
from .reasons import REASONS, is_known_reason
from .request import HEADER, WSGI_ENVIRON_KEY, assertion_from
from .urls import LOGIN_QUERY, LOGOUT_QUERY, login_url, logout_url
from .verifier import (
    IAP_ISSUER,
    IAP_JWKS_URL,
    Result,
    reset_jwks_cache,
    verify,
    verify_request,
)

__all__ = [
    "CLOUD_MARKERS",
    "DEV_BYPASS_EMAIL_VAR",
    "DEV_BYPASS_NAME_VAR",
    "HEADER",
    "IAP_ISSUER",
    "IAP_JWKS_URL",
    "LOGIN_QUERY",
    "LOGOUT_QUERY",
    "REASONS",
    "Result",
    "WSGI_ENVIRON_KEY",
    "assertion_from",
    "dev_bypass",
    "is_known_reason",
    "login_url",
    "logout_url",
    "reset_jwks_cache",
    "verify",
    "verify_request",
]

__version__ = "0.1.0"
