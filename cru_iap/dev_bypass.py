"""A dev/test identity that cannot be switched on in production by accident.

Three consumers each grew their own bypass, in three incompatible shapes, and one
of them shipped an incident: dse-portal's ``AUTH_ENABLED`` defaulted to the
INSECURE value, so forgetting to set it disabled authentication. That is the
failure mode this primitive is built to make unreachable.

Why there is no boolean
-----------------------
A boolean flag has a wrong default — someone has to choose it, and half the time
they choose the open one. An identity-carrying variable has no wrong default:
either you name a developer to be, or you don't, and "unset" can only mean "no
bypass". So the opt-in IS the identity::

    CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org uvicorn backend.main:app --reload

There is deliberately no ``set_dev_bypass_enabled(True)`` either. Anything an app
can turn on in a config module, an app can turn on in production.

Two independent guards on top
-----------------------------
Neither depends on the app being written correctly:

1. ``IAP_AUDIENCE`` set => refuse. A deploy configured for IAP is a deploy that
   must verify, and cru-terraform injects ``IAP_AUDIENCE`` into every IAP-fronted
   container.
2. A cloud-runtime marker present => refuse. Cloud Run always sets ``K_SERVICE``;
   App Engine sets ``GAE_ENV``; Cloud Functions sets ``FUNCTION_TARGET``. Nobody
   has to remember to set these, which is exactly what makes them trustworthy.

Composition — the app writes one line, not a branch::

    result = dev_bypass() or verify_request(request, audience=audience)

Putting the bypass first is safe precisely because of the guards above: in any
environment where it could matter, it returns ``None``.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Mapping

from .verifier import Result, logger as _default_logger

DEV_BYPASS_EMAIL_VAR = "CRU_IAP_DEV_BYPASS_EMAIL"
DEV_BYPASS_NAME_VAR = "CRU_IAP_DEV_BYPASS_NAME"

#: Set by the platform, not by us — see guard 2 above.
CLOUD_MARKERS = ("K_SERVICE", "K_REVISION", "GAE_ENV", "FUNCTION_TARGET")

# At least as strict as the verifier's gate, so a bypass identity can never
# become a user the real path would have rejected.
#
# * "/" and "\" are excluded because RFC 5322 permits "/" in a local part, so a
#   principal:// URI would otherwise pass a naive address check.
# * ":" is excluded because a namespaced claim value ("sts.google.com:me@...") is
#   a copy-paste out of a JWT, not a developer's address. The verifier STRIPS
#   that prefix; here it is refused instead, because silently reinterpreting what
#   someone typed into an auth-disabling variable is worse than making them
#   retype it. Matches Ruby, whose URI::MailTo::EMAIL_REGEXP rejects it outright.
_PLAUSIBLE_EMAIL = re.compile(r"^[^\s@/\\:]+@[^\s@/\\:]+\.[^\s@/\\:]+$")


def _blank(value: str | None) -> bool:
    return not (value or "").strip()


def dev_bypass(
    env: Mapping[str, str] | None = None,
    log: logging.Logger | None = None,
) -> Result | None:
    """Return a bypass :class:`~cru_iap.Result`, or ``None`` to verify for real.

    :param env: defaults to ``os.environ``; injectable so tests need no shell
    :param log: defaults to the ``cru_iap`` logger
    """
    environ = os.environ if env is None else env
    active_log = log if log is not None else _default_logger

    raw = (environ.get(DEV_BYPASS_EMAIL_VAR) or "").strip()
    if not raw:
        return None

    def refuse(why: str) -> None:
        active_log.warning(
            "[cru-iap] ignoring %s: %s. Verifying the IAP assertion instead.",
            DEV_BYPASS_EMAIL_VAR,
            why,
        )
        return None

    if not _blank(environ.get("IAP_AUDIENCE")):
        return refuse("IAP_AUDIENCE is set")

    marker = next((name for name in CLOUD_MARKERS if not _blank(environ.get(name))), None)
    if marker:
        return refuse(f"{marker} is set, so this is a managed runtime")

    email = raw.lower()
    if not _PLAUSIBLE_EMAIL.match(email):
        return refuse(f"{DEV_BYPASS_EMAIL_VAR}={raw!r} is not an email address")

    # Loud on every activation, deliberately. A bypass that logs once is a bypass
    # someone forgets is on; dev-server request volume makes this affordable.
    active_log.warning(
        "[cru-iap] DEV BYPASS ACTIVE — the IAP assertion is NOT being verified. "
        "Acting as %s. Unset %s to restore verification.",
        email,
        DEV_BYPASS_EMAIL_VAR,
    )

    name = (environ.get(DEV_BYPASS_NAME_VAR) or "").strip()
    return Result(ok=True, reason="dev_bypass", email=email, name=name or None)
