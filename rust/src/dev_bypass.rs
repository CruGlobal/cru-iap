//! A dev/test identity that cannot be switched on in production by accident.
//!
//! Three consumers each grew their own bypass, and one shipped an incident: a
//! boolean `AUTH_ENABLED` whose default was the insecure value. So there is no
//! boolean here. The opt-in IS the identity, and "unset" can only mean "no
//! bypass":
//!
//! ```sh
//! CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org cargo run
//! ```
//!
//! Two guards on top, neither depending on the app being written correctly:
//!
//! 1. `IAP_AUDIENCE` set: refuse. A deploy configured for IAP must verify.
//! 2. A cloud-runtime marker set (`K_SERVICE` and friends): refuse. The
//!    platform sets these, so nobody has to remember to.
//!
//! The app writes one branch, not a policy:
//!
//! ```no_run
//! # async fn example(headers: &http::HeaderMap) {
//! let result = match cru_iap::dev_bypass() {
//!     Some(identity) => Ok(identity),
//!     None => cru_iap::verify_request(headers).await,
//! };
//! # }
//! ```

use std::sync::LazyLock;

use regex::Regex;

use crate::reasons;
use crate::verifier::Identity;

/// Names the developer to act as. Its presence is the opt-in.
pub const DEV_BYPASS_EMAIL_VAR: &str = "CRU_IAP_DEV_BYPASS_EMAIL";
/// Optionally supplies a display name.
pub const DEV_BYPASS_NAME_VAR: &str = "CRU_IAP_DEV_BYPASS_NAME";
/// Set by the platform, not by us. See guard 2.
pub const CLOUD_MARKERS: [&str; 4] = ["K_SERVICE", "K_REVISION", "GAE_ENV", "FUNCTION_TARGET"];

/// At least as strict as the verifier's gate. ":" is refused rather than
/// stripped: a namespaced value is a copy-paste out of a JWT, and silently
/// reinterpreting what someone typed into an auth-disabling variable is worse
/// than making them retype it.
static PLAUSIBLE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[^\s@/\\:]+@[^\s@/\\:]+\.[^\s@/\\:]+$").expect("PLAUSIBLE_EMAIL compiles")
});

/// The dev identity, if one is configured and permitted. `None` whenever the
/// caller must verify for real, which is every case in a managed runtime.
pub fn dev_bypass() -> Option<Identity> {
    dev_bypass_with(|name| std::env::var(name).ok())
}

/// `dev_bypass` over a supplied environment, so tests need no process env.
pub fn dev_bypass_with(lookup: impl Fn(&str) -> Option<String>) -> Option<Identity> {
    let read = |name: &str| lookup(name).unwrap_or_default().trim().to_string();
    let raw = read(DEV_BYPASS_EMAIL_VAR);
    if raw.is_empty() {
        return None;
    }

    let refuse = |why: String| {
        tracing::warn!(
            why,
            "[cru-iap] ignoring {DEV_BYPASS_EMAIL_VAR}, verifying the IAP assertion instead"
        );
        None
    };

    if !read("IAP_AUDIENCE").is_empty() {
        return refuse("IAP_AUDIENCE is set".into());
    }
    if let Some(marker) = CLOUD_MARKERS.iter().find(|marker| !read(marker).is_empty()) {
        return refuse(format!("{marker} is set, so this is a managed runtime"));
    }

    let email = raw.to_lowercase();
    if !PLAUSIBLE_EMAIL.is_match(&email) {
        return refuse(format!(
            "{DEV_BYPASS_EMAIL_VAR}={raw} is not an email address"
        ));
    }

    // Loud on every activation: a bypass that logs once is one someone
    // forgets is on.
    tracing::warn!(
        acting_as = %email,
        to_restore = %format!("unset {DEV_BYPASS_EMAIL_VAR}"),
        "[cru-iap] DEV BYPASS ACTIVE, the IAP assertion is NOT being verified"
    );

    let name = read(DEV_BYPASS_NAME_VAR);
    Some(Identity {
        email,
        name: (!name.is_empty()).then_some(name),
        reason: reasons::DEV_BYPASS,
        payload: None,
    })
}
