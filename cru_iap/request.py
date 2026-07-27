"""Pulling the assertion off whatever kind of request object the app has.

Deliberately structural rather than a union of framework types, so this package
imports neither Starlette nor Django nor Flask and works with all of them (plus
a bare WSGI ``environ``).
"""

from __future__ import annotations

from typing import Any

#: The header IAP injects. Exposed because infra config and test fixtures
#: legitimately need the wire name — application code should not, and should
#: call :func:`cru_iap.verify_request` instead of reaching for it.
HEADER = "x-goog-iap-jwt-assertion"

#: The same header as WSGI/Django normalize it into ``environ`` / ``request.META``.
WSGI_ENVIRON_KEY = "HTTP_X_GOOG_IAP_JWT_ASSERTION"


def assertion_from(source: Any) -> str | None:
    """Return the raw assertion JWT carried by ``source``, or ``None``.

    Accepts, in the order tried:

    - anything with a ``.headers`` mapping — Starlette/FastAPI ``Request``,
      Django ``HttpRequest``, Flask/Werkzeug ``request``, ``httpx``/``requests``
      objects. Starlette and Werkzeug header mappings are already
      case-insensitive; Django's ``HttpHeaders`` is too.
    - anything with a ``.META`` mapping — Django ``HttpRequest``, for the case
      where a caller hands one over on an older Django without ``.headers``.
    - a plain mapping, either of wire-name headers (``{"x-goog-iap-jwt-assertion":
      …}``) or of a WSGI ``environ`` (``{"HTTP_X_GOOG_IAP_JWT_ASSERTION": …}``).

    Header lookup is case-insensitive throughout: framework mappings handle it
    themselves, and for a plain :class:`dict` we scan rather than trusting the
    caller to have lowercased.
    """
    headers = getattr(source, "headers", None)
    if _is_mapping(headers):
        found = _read(headers, HEADER)
        if found is not None:
            return _one(found)

    meta = getattr(source, "META", None)
    if _is_mapping(meta):
        found = _read(meta, WSGI_ENVIRON_KEY)
        if found is not None:
            return _one(found)

    if _is_mapping(source):
        # A plain dict may be either shape. Try the wire name first: a caller
        # hand-building a header dict is the common case, and a WSGI environ
        # never contains the hyphenated form.
        found = _read(source, HEADER)
        if found is None:
            found = _read(source, WSGI_ENVIRON_KEY)
        if found is not None:
            return _one(found)

    return None


def _is_mapping(candidate: Any) -> bool:
    # Duck-typed rather than isinstance(Mapping): Starlette's Headers and
    # Werkzeug's EnvironHeaders both support .get and __contains__ without
    # registering as collections.abc.Mapping.
    return candidate is not None and hasattr(candidate, "get")


def _read(mapping: Any, name: str) -> Any:
    value = mapping.get(name)
    if value is not None:
        return value

    # Fall back to a case-insensitive scan for plain dicts, whose .get is not.
    # Framework mappings already matched above, so this loop is only reached for
    # a hand-built dict with unexpected casing.
    try:
        items = mapping.items()
    except (AttributeError, TypeError):
        return None
    lowered = name.lower()
    for key, candidate in items:
        if isinstance(key, str) and key.lower() == lowered:
            return candidate
    return None


def _one(value: Any) -> str | None:
    """Normalize a header value to a single string, or None.

    A repeated header arrives as a list from some frameworks. Two assertions is
    not a shape IAP produces, so treat it as absent rather than guessing which
    to trust — the verifier then reports ``missing_token`` and fails closed.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("latin-1")
    if isinstance(value, (list, tuple)):
        return _one(value[0]) if len(value) == 1 else None
    return None
