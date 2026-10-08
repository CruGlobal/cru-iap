//! The two IAP control URLs, which every consumer was re-typing.
//!
//! Pure string builders, because the mistakes they prevent are string mistakes:
//!
//! - Linking bare "/" for sign-in instead of "/?login=true". IAP redirects to
//!   the IdP, the IdP redirects back to "/", and round it goes.
//! - Signing out without "?gcp-iap-mode=CLEAR_LOGIN_COOKIE". The app's session
//!   goes away, IAP's federated login cookie does not, and the next request
//!   signs the same person straight back in.
//!
//! Kept in step with the other four languages by a cross-language test.

/// Appended to trigger IAP's sign-in redirect.
pub const LOGIN_QUERY: &str = "login=true";
/// Appended to make IAP drop its federated login cookie.
pub const LOGOUT_QUERY: &str = "gcp-iap-mode=CLEAR_LOGIN_COOKIE";

/// `target` with IAP's login trigger appended. A blank target means "/".
pub fn login_url(target: &str) -> String {
    with_param(target, LOGIN_QUERY)
}

/// `target` with IAP's cookie-clear mode appended. A blank target means "/".
pub fn logout_url(target: &str) -> String {
    with_param(target, LOGOUT_QUERY)
}

/// A fragment must stay last, the separator depends on an existing query, and
/// appending is idempotent.
fn with_param(target: &str, param: &str) -> String {
    let resolved = if target.trim().is_empty() {
        "/"
    } else {
        target
    };
    let (base, fragment) = match resolved.find('#') {
        Some(hash) => resolved.split_at(hash),
        None => (resolved, ""),
    };

    if let Some((_, query)) = base.split_once('?')
        && query.split('&').any(|existing| existing == param)
    {
        return resolved.to_string();
    }

    let separator = if !base.contains('?') {
        "?"
    } else if base.ends_with('?') {
        ""
    } else {
        "&"
    };
    format!("{base}{separator}{param}{fragment}")
}
