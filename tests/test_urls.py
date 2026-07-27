"""The two footguns these exist to close, then the string cases that make them
worth being code rather than a README bullet."""

from __future__ import annotations

import pytest

from cru_iap import LOGIN_QUERY, LOGOUT_QUERY, login_url, logout_url


@pytest.mark.parametrize("target", ["/", "", "   "])
def test_never_returns_bare_slash_the_infinite_loop_case(target):
    # IAP sends bare / to the IdP, which sends it back to /, forever. The single
    # most-reported IAP footgun at Cru, so it gets the first test.
    assert login_url(target) == "/?login=true"


def test_defaults_to_root():
    assert login_url() == "/?login=true"


def test_appends_to_a_path():
    assert login_url("/dashboard") == "/dashboard?login=true"


def test_appends_to_an_absolute_url():
    assert login_url("https://app.cru.org/dashboard") == "https://app.cru.org/dashboard?login=true"


def test_uses_ampersand_when_a_query_is_already_present():
    assert login_url("/dashboard?tab=reports") == "/dashboard?tab=reports&login=true"


def test_does_not_produce_question_ampersand_on_a_bare_trailing_question_mark():
    assert login_url("/dashboard?") == "/dashboard?login=true"


def test_keeps_the_fragment_last_so_the_param_reaches_the_server():
    # "/a#b" with "?login=true" appended naively is "/a#b?login=true", where the
    # param is part of the fragment and never leaves the browser. This is the
    # case a hand-rolled f-string gets wrong.
    assert login_url("/dashboard#reports") == "/dashboard?login=true#reports"
    assert login_url("/dashboard?tab=1#reports") == "/dashboard?tab=1&login=true#reports"


def test_is_idempotent():
    assert login_url(login_url("/dashboard")) == "/dashboard?login=true"


def test_does_not_mistake_a_param_that_merely_contains_the_trigger():
    assert login_url("/go?next=%2F%3Flogin%3Dtrue") == "/go?next=%2F%3Flogin%3Dtrue&login=true"


def test_logout_carries_the_cookie_clear_mode():
    # Without this the app's session goes away, IAP's federated login cookie does
    # not, and the next request signs the same person straight back in.
    assert logout_url() == "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE"
    assert logout_url("/goodbye") == "/goodbye?gcp-iap-mode=CLEAR_LOGIN_COOKIE"


def test_logout_composes_with_an_existing_query_and_fragment():
    assert (
        logout_url("/bye?reason=timeout#top")
        == "/bye?reason=timeout&gcp-iap-mode=CLEAR_LOGIN_COOKIE#top"
    )


def test_logout_is_idempotent():
    assert logout_url(logout_url("/bye")) == "/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE"


def test_the_query_constants_are_the_literals_iap_understands():
    # Pinned rather than derived: a typo in either is a silent auth failure, and
    # these strings are Google's, not ours to normalise.
    assert LOGIN_QUERY == "login=true"
    assert LOGOUT_QUERY == "gcp-iap-mode=CLEAR_LOGIN_COOKIE"
