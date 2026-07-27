"""The two IAP control URLs, which every consumer was re-typing.

Pure string builders — no request, no config, no I/O — because the mistakes they
prevent are string mistakes:

* Linking bare ``/`` for sign-in instead of ``/?login=true``. IAP redirects to
  the IdP, the IdP redirects back to ``/``, and round it goes. An infinite loop,
  and the single most-reported IAP footgun at Cru.
* Signing out without ``?gcp-iap-mode=CLEAR_LOGIN_COOKIE``. The app's own session
  goes away, IAP's federated login cookie does not, and the next request
  silently signs the same person straight back in.

Both were checklist items in the README, which is to say they were prose that
four apps had to re-read correctly. Now they are code.

Kept in step with ``lib/cru_iap/urls.rb``, ``src/urls.ts`` and ``cruiap/urls.go``
by a cross-language test (see ``cruiap/vocabulary_test.go``).
"""

from __future__ import annotations

#: Appended to trigger IAP's sign-in redirect.
LOGIN_QUERY = "login=true"

#: Appended to make IAP drop its federated login cookie.
LOGOUT_QUERY = "gcp-iap-mode=CLEAR_LOGIN_COOKIE"


def _with_param(target: str, param: str) -> str:
    """Query-string surgery that is easy to get wrong by hand.

    Which is the reason this exists rather than an f-string at each call site:

    * a fragment must stay LAST — ``"/a#b"`` with ``"?login=true"`` appended
      naively yields ``"/a#b?login=true"``, where the param is part of the
      fragment and never reaches the server at all
    * the separator depends on whether a query is already present
    * idempotent, so ``login_url(login_url(x)) == login_url(x)``
    """
    resolved = target if target.strip() else "/"

    base, separator_hash, fragment = resolved.partition("#")

    _, _, query = base.partition("?")
    if param in query.split("&"):
        return resolved

    if "?" not in base:
        separator = "?"
    elif base.endswith("?"):
        separator = ""
    else:
        separator = "&"

    return f"{base}{separator}{param}{separator_hash}{fragment}"


def login_url(target: str = "/") -> str:
    """The same target with IAP's login trigger appended."""
    return _with_param(target, LOGIN_QUERY)


def logout_url(target: str = "/") -> str:
    """The same target with IAP's cookie-clear mode appended."""
    return _with_param(target, LOGOUT_QUERY)
