"""Promises the package makes about itself.

Mirrors ``test/unit/package.test.ts``. These are cheap and they catch the class
of mistake that only shows up in a consumer: a missing export, an accidental
framework import, a reason list that drifted from its sibling.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import cru_iap

ROOT = Path(__file__).resolve().parents[1]


def test_exports_the_public_surface():
    for name in (
        "verify",
        "verify_request",
        "assertion_from",
        "Result",
        "REASONS",
        "is_known_reason",
        "HEADER",
        "IAP_ISSUER",
        "IAP_JWKS_URL",
        "reset_jwks_cache",
        "login_url",
        "logout_url",
        "LOGIN_QUERY",
        "LOGOUT_QUERY",
        "dev_bypass",
        "DEV_BYPASS_EMAIL_VAR",
        "CLOUD_MARKERS",
    ):
        assert hasattr(cru_iap, name), f"cru_iap.{name} is not exported"


def test_all_matches_what_is_actually_exported():
    for name in cru_iap.__all__:
        assert hasattr(cru_iap, name), f"__all__ names {name}, which does not exist"


def test_imports_no_web_framework():
    # The package must work in FastAPI, Django, Flask and a bare WSGI app, which
    # means importing none of them. Checked in a subprocess so this test's own
    # imports (and pytest's) can't mask a leak.
    probe = (
        "import sys, cru_iap; "
        "leaked = [m for m in ('fastapi','starlette','django','flask','werkzeug') "
        "if m in sys.modules]; "
        "print(','.join(leaked))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == "", f"cru_iap pulled in {result.stdout.strip()}"


def test_the_reason_list_matches_the_ruby_gem():
    # Nothing mechanically keeps the four languages' vocabularies in step, so
    # compare them here — this is the cheapest place to notice a drift, and the
    # Datadog queries every Cru app files depend on the lists agreeing.
    ruby = (ROOT / "lib" / "cru_iap" / "token_verifier.rb").read_text()
    block = re.search(r"REASONS = \[(.*?)\]\.freeze", ruby, re.S)
    assert block, "could not find REASONS in the Ruby verifier"
    ruby_reasons = re.findall(r'"([^"]+)"', block.group(1))

    assert list(cru_iap.REASONS) == ruby_reasons


def test_the_reason_list_matches_the_typescript_package():
    typescript = (ROOT / "src" / "reasons.ts").read_text()
    block = re.search(r"export const REASONS = \[(.*?)\] as const;", typescript, re.S)
    assert block, "could not find REASONS in the TypeScript package"
    ts_reasons = re.findall(r'"([^"]+)"', block.group(1))

    assert list(cru_iap.REASONS) == ts_reasons


def test_the_four_declared_versions_agree():
    # The version lives in four files, one per language. A consumer's lockfile
    # records whichever one its ecosystem read, so a mismatch means "cru_iap
    # 0.1.0" in a Gemfile.lock and "cru-iap 0.2.0" in a uv.lock describe the
    # same tree.
    #
    # release-please moves all four in one commit (see
    # release-please-config.json's extra-files), so this now doubles as the
    # guard on that config: if this fails on a "chore(main): release X.Y.Z"
    # pull request, an extra-file stopped matching — most likely because an
    # `x-release-please-version` annotation was dropped from version.rb or
    # __init__.py, or because pyproject.toml's `[project] version` moved.
    #
    # Go is absent on purpose: Go modules take their version from the git tag,
    # not from a file, so there is nothing to keep in step there.
    declared = {
        "python": cru_iap.__version__,
        "ruby": re.search(
            r'VERSION\s*=\s*"([^"]+)"', (ROOT / "lib" / "cru_iap" / "version.rb").read_text()
        ).group(1),
        "typescript": json.loads((ROOT / "package.json").read_text())["version"],
        "pyproject": re.search(
            r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M
        ).group(1),
    }

    assert len(set(declared.values())) == 1, f"versions have drifted: {declared}"


def test_the_two_success_reasons_are_the_expected_ones():
    # Everything else in the vocabulary is a rejection. dev_bypass is a success
    # on purpose so a bypassed request lands in the same Datadog queries as a
    # real one rather than being invisible.
    assert "iap_jwt" in cru_iap.REASONS
    assert "dev_bypass" in cru_iap.REASONS


def test_the_jwks_url_is_the_jwk_endpoint_not_the_pem_one():
    # The bare .../iap/verify/public_key endpoint serves a PEM map, which is not
    # parseable as a JWK set. Pinned because the difference is one suffix and
    # the failure is a confusing parse error at runtime.
    assert cru_iap.IAP_JWKS_URL.endswith("public_key-jwk")
