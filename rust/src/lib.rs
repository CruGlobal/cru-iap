//! Request authentication for applications behind Google Identity-Aware Proxy,
//! including IAP fronted by an external identity provider via Workforce
//! Identity Federation.
//!
//! The Rust sibling of the Ruby, TypeScript, Python and Go libraries in this
//! repository. See the README for the claim-shape decisions all five share.
//!
//! ```no_run
//! # async fn example(headers: &http::HeaderMap) {
//! match cru_iap::verify_request(headers).await {
//!     Ok(identity) => println!("{}", identity.email),
//!     // fail closed: never fall through to a dev stub
//!     Err(rejection) => tracing::warn!(reason = rejection.reason(), "IAP auth rejected"),
//! }
//! # }
//! ```

#[cfg(feature = "axum")]
pub mod axum;
mod dev_bypass;
mod keys;
pub mod reasons;
mod request;
mod urls;
mod verifier;

pub use dev_bypass::{
    CLOUD_MARKERS, DEV_BYPASS_EMAIL_VAR, DEV_BYPASS_NAME_VAR, dev_bypass, dev_bypass_with,
};
#[cfg(feature = "remote-keys")]
pub use keys::RemoteKeys;
pub use keys::{IAP_JWKS_URL, KeyError, KeySource, StaticKeys, parse_jwks};
pub use reasons::is_known_reason;
pub use request::{HEADER, assertion_from};
pub use urls::{LOGIN_QUERY, LOGOUT_QUERY, login_url, logout_url};
pub use verifier::{
    IAP_ISSUER, Identity, Rejection, Verifier, VerifyResult, verify, verify_request,
};

/// Re-exported so a `KeySource` implementation names the same type.
pub use jsonwebtoken::DecodingKey;
