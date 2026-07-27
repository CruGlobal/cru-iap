from __future__ import annotations

import pytest

from cru_iap import reset_jwks_cache
from tests.support.iap_jwt import LocalJwks, SigningKey


@pytest.fixture(autouse=True)
def _no_cached_jwks():
    """Never let one example be served Google's key set from another's cache.

    The mirror of the TypeScript suite's `resetJwksCache()` and the Ruby suite's
    `Google::Auth::IDTokens.forget_sources!`. Autouse because a leaked cache
    fails in a confusing, order-dependent way.
    """
    reset_jwks_cache()
    yield
    reset_jwks_cache()


@pytest.fixture(scope="session")
def key() -> SigningKey:
    # Session-scoped: EC keygen is not free, and no example mutates the key.
    return SigningKey()


@pytest.fixture(scope="session")
def jwks(key: SigningKey) -> LocalJwks:
    return LocalJwks(key)
