"""Loader for the shared live-capture artifact.

One browser login, four verifications — see test/support/capture.ts for the
reasoning and e2e/README.md for the artifact contract. This is the Python
sibling of that loader and applies the same staleness rule.

Nothing infrastructure-specific is hardcoded: the audience and expected email
resolve from the environment or the artifact and otherwise cause a skip, so
moving the e2e stack to another project does not touch test code.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Refuse a capture that is within this many seconds of expiry.
EXPIRY_MARGIN_SECONDS = 30

_DEFAULT_PATH = Path(__file__).resolve().parents[2] / "e2e" / "okta" / "capture.json"


@dataclass(frozen=True)
class LoadedCapture:
    assertion: str
    claims: dict[str, Any]
    audience: str
    expected_email: str
    captured_at: int


def capture_path() -> Path:
    override = os.environ.get("CRU_IAP_E2E_CAPTURE")
    return Path(override) if override else _DEFAULT_PATH


def load_capture() -> LoadedCapture | str:
    """Return the loaded capture, or a string explaining why to skip.

    Never raises: an absent stack is a skip, not a failure.
    """
    path = capture_path()
    if not path.exists():
        return f"no capture at {path} — run: node e2e/okta/capture_assertion.mjs --json"

    try:
        raw = json.loads(path.read_text())
    except ValueError as error:
        return f"capture at {path} is not readable JSON: {error}"

    assertion = raw.get("assertion")
    claims = raw.get("claims")
    if not assertion or not isinstance(claims, dict):
        return (
            f"capture at {path} has no assertion/claims — "
            "was it written by an older capture script?"
        )

    # Keyed on `exp` rather than captured_at: exp is what actually decides
    # whether a verify can succeed, and it comes from Google not our clock.
    try:
        exp = int(claims["exp"])
    except (KeyError, TypeError, ValueError):
        return f"capture at {path} has no numeric exp claim"

    now = int(time.time())
    if exp <= now + EXPIRY_MARGIN_SECONDS:
        return f"capture at {path} expired {now - exp}s ago — re-run the capture"

    # Audience is configuration, never read off the token: taking it from the
    # `aud` claim would turn the positive verify into "does aud equal aud".
    audience = os.environ.get("CRU_IAP_E2E_AUDIENCE") or raw.get("audience")
    if not audience:
        return (
            "no audience: set CRU_IAP_E2E_AUDIENCE or capture with "
            '--audience "$(terraform output -raw iap_audience)"'
        )

    expected_email = os.environ.get("CRU_IAP_E2E_EMAIL") or raw.get("expected_email")
    if not expected_email:
        return "no expected email: set CRU_IAP_E2E_EMAIL or re-run the capture script"

    return LoadedCapture(
        assertion=assertion,
        claims=claims,
        audience=audience,
        expected_email=expected_email,
        captured_at=int(raw.get("captured_at", 0)),
    )
