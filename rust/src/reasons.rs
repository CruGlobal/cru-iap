//! The rejection vocabulary, shared verbatim with the Ruby gem
//! (`CruIap::TokenVerifier::REASONS`), the TypeScript package (src/reasons.ts),
//! the Python package (cru_iap/reasons.py) and the Go package
//! (cruiap/reasons.go), so every Cru app behind IAP files the same Datadog
//! queries.
//!
//! Entries ending in ":" carry a variable suffix.
//!
//! If you add one here, add it to the other four too, in the same ORDER. The
//! Rust suite cross-checks all four against this list (rust/tests/all/vocabulary.rs).

/// The assertion header was absent or blank.
pub const MISSING_TOKEN: &str = "missing_token";
/// `IAP_AUDIENCE` was unset: a deploy misconfiguration. Fails closed.
pub const MISSING_AUDIENCE_CONFIG: &str = "missing_audience_config";
/// Carries the offending `iss` as a suffix.
pub const BAD_ISS: &str = "bad_iss:";
/// Signed, but with no expiry, so nothing would ever consider it stale.
pub const MISSING_EXP: &str = "missing_exp";
/// No email claim arrived: an IAP/pool config gap, fixed in terraform.
pub const MISSING_EMAIL: &str = "missing_email";
/// Something arrived that is not an address.
pub const MALFORMED_SUBJECT: &str = "malformed_subject";
/// Carries the underlying detail as a suffix.
pub const SIGNATURE_ERROR: &str = "signature_error:";
pub const AUDIENCE_MISMATCH: &str = "audience_mismatch";
pub const EXPIRED_TOKEN: &str = "expired_token";
pub const ISSUER_MISMATCH: &str = "issuer_mismatch";
/// Carries the fault name as a suffix.
pub const VERIFICATION_ERROR: &str = "verification_error:";
/// The fail-closed catch-all.
pub const UNEXPECTED_ERROR: &str = "unexpected_error";
/// A real IAP assertion verified.
pub const IAP_JWT: &str = "iap_jwt";
/// `dev_bypass` supplied the identity. Unreachable in a managed runtime.
pub const DEV_BYPASS: &str = "dev_bypass";

pub const REASONS: [&str; 14] = [
    MISSING_TOKEN,
    MISSING_AUDIENCE_CONFIG,
    BAD_ISS,
    MISSING_EXP,
    MISSING_EMAIL,
    MALFORMED_SUBJECT,
    SIGNATURE_ERROR,
    AUDIENCE_MISMATCH,
    EXPIRED_TOKEN,
    ISSUER_MISMATCH,
    VERIFICATION_ERROR,
    UNEXPECTED_ERROR,
    IAP_JWT,
    DEV_BYPASS,
];

/// Exact match for the plain entries, prefix match for the ones ending in ":".
pub fn is_known_reason(reason: &str) -> bool {
    REASONS.iter().any(|known| match known.strip_suffix(':') {
        Some(_) => reason.starts_with(known),
        None => reason == *known,
    })
}
