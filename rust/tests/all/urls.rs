use cru_iap::{login_url, logout_url};

#[test]
fn login_url_never_returns_bare_slash() {
    // IAP sends bare / to the IdP, which sends it back to /, forever.
    for target in ["", "/", "   "] {
        assert_eq!(login_url(target), "/?login=true", "target {target:?}");
    }
}

#[test]
fn login_url_cases() {
    for (target, want) in [
        ("/dashboard", "/dashboard?login=true"),
        (
            "https://app.cru.org/dashboard",
            "https://app.cru.org/dashboard?login=true",
        ),
        (
            "/dashboard?tab=reports",
            "/dashboard?tab=reports&login=true",
        ),
        ("/dashboard?", "/dashboard?login=true"),
        // Appended naively, the param lands in the fragment and never leaves
        // the browser.
        ("/dashboard#reports", "/dashboard?login=true#reports"),
        (
            "/dashboard?tab=1#reports",
            "/dashboard?tab=1&login=true#reports",
        ),
        ("/dashboard?login=true", "/dashboard?login=true"),
        (
            "/go?next=%2F%3Flogin%3Dtrue",
            "/go?next=%2F%3Flogin%3Dtrue&login=true",
        ),
    ] {
        assert_eq!(login_url(target), want, "target {target:?}");
    }
}

#[test]
fn logout_url_cases() {
    assert_eq!(logout_url(""), "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE");
    assert_eq!(logout_url("/bye"), "/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE");
    assert_eq!(
        logout_url("/bye?a=1#top"),
        "/bye?a=1&gcp-iap-mode=CLEAR_LOGIN_COOKIE#top"
    );
}

#[test]
fn both_are_idempotent() {
    assert_eq!(login_url(&login_url("/a?b=1#c")), login_url("/a?b=1#c"));
    assert_eq!(logout_url(&logout_url("/a")), logout_url("/a"));
}
