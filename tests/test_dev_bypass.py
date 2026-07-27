"""The guards are the whole point, so most of this file is negative controls.

The incident being prevented: dse-portal's ``AUTH_ENABLED`` defaulted to the
insecure value, so forgetting to set it disabled authentication. Every test below
that asserts ``is None`` is a way that cannot happen here.
"""

from __future__ import annotations

import logging

import pytest

from cru_iap import CLOUD_MARKERS, DEV_BYPASS_EMAIL_VAR, dev_bypass, is_known_reason

QUIET = logging.getLogger("cru_iap.tests.quiet")
QUIET.addHandler(logging.NullHandler())
QUIET.propagate = False


def bypass(env, log=QUIET):
    return dev_bypass(env=env, log=log)


def test_is_off_when_nothing_is_set():
    assert bypass({}) is None


@pytest.mark.parametrize(
    "env",
    [
        {"AUTH_ENABLED": "false"},
        {"CRU_IAP_DEV_BYPASS": "true"},
        {"CRU_IAP_DEV_BYPASS_ENABLED": "1"},
    ],
)
def test_has_no_boolean_to_get_backwards(env):
    # The API surface is the assertion: an identity-carrying variable has no
    # wrong default, where AUTH_ENABLED=false vs =true does. Setting the "enable"
    # flag people reach for by habit does nothing at all.
    assert bypass(env) is None


def test_activates_when_a_developer_names_themselves():
    result = bypass({DEV_BYPASS_EMAIL_VAR: "dev@cru.org"})

    assert result is not None
    assert result.ok
    assert result.reason == "dev_bypass"
    assert result.email == "dev@cru.org"
    assert result.name is None


def test_emits_a_reason_from_the_shared_vocabulary():
    # So a bypassed request is queryable in Datadog alongside every real one,
    # rather than being invisible.
    result = bypass({DEV_BYPASS_EMAIL_VAR: "dev@cru.org"})

    assert is_known_reason(result.reason)


def test_normalises_the_address_and_carries_an_optional_display_name():
    result = bypass(
        {
            DEV_BYPASS_EMAIL_VAR: "  Dev@Cru.org  ",
            "CRU_IAP_DEV_BYPASS_NAME": "A Developer",
        }
    )

    assert result.email == "dev@cru.org"
    assert result.name == "A Developer"


def test_refuses_when_iap_audience_is_set():
    # cru-terraform injects IAP_AUDIENCE into every IAP-fronted container, so the
    # bypass cannot coexist with the config that means "verify for real".
    assert (
        bypass(
            {
                DEV_BYPASS_EMAIL_VAR: "dev@cru.org",
                "IAP_AUDIENCE": "/projects/1/global/backendServices/2",
            }
        )
        is None
    )


def test_ignores_a_blank_iap_audience_which_is_not_a_configured_one():
    result = bypass({DEV_BYPASS_EMAIL_VAR: "dev@cru.org", "IAP_AUDIENCE": "   "})

    assert result is not None and result.ok


@pytest.mark.parametrize("marker", CLOUD_MARKERS)
def test_refuses_in_a_managed_runtime(marker):
    # Nobody has to remember to set these — the platform does — which is exactly
    # what makes them trustworthy as a guard.
    assert bypass({DEV_BYPASS_EMAIL_VAR: "dev@cru.org", marker: "anything"}) is None


def test_refuses_on_cloud_run_even_with_iap_audience_somehow_missing():
    # The guards are independent on purpose: this is the misconfigured-deploy
    # case, where relying on IAP_AUDIENCE alone would open the bypass.
    assert bypass({DEV_BYPASS_EMAIL_VAR: "dev@cru.org", "K_SERVICE": "my-app"}) is None


@pytest.mark.parametrize(
    "value",
    [
        "not-an-address",
        "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/dev@cru.org",
        "dev@cru.org/../admin",
        "sts.google.com:dev@cru.org",
        "@cru.org",
    ],
)
def test_identity_must_survive_the_same_shape_gate_as_a_real_one(value):
    assert bypass({DEV_BYPASS_EMAIL_VAR: value}) is None


def test_warns_loudly_on_every_activation(caplog):
    # A bypass that logs once is a bypass someone forgets is on.
    with caplog.at_level(logging.WARNING, logger="cru_iap"):
        dev_bypass(env={DEV_BYPASS_EMAIL_VAR: "dev@cru.org"})
        dev_bypass(env={DEV_BYPASS_EMAIL_VAR: "dev@cru.org"})

    activations = [r for r in caplog.records if "DEV BYPASS ACTIVE" in r.getMessage()]
    assert len(activations) == 2


def test_explains_itself_when_it_refuses(caplog):
    with caplog.at_level(logging.WARNING, logger="cru_iap"):
        dev_bypass(env={DEV_BYPASS_EMAIL_VAR: "dev@cru.org", "K_SERVICE": "my-app"})

    assert any("K_SERVICE" in r.getMessage() for r in caplog.records)
