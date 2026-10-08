//! End-to-end against LIVE Google infrastructure. Nothing is stubbed: a real
//! Okta sign-in federates through a real workforce pool into a real
//! IAP-fronted service, and the assertion Google injected is verified against
//! Google's real key set, fetched over the network.
//!
//! The Rust sibling of cruiap/live_iap_e2e_test.go, verifying the SAME
//! captured assertion. See e2e/README.md for the artifact contract.
//!
//! ```sh
//! e2e/run_all.sh --only rust
//! cargo test --features e2e --test live_iap   # against an existing capture
//! ```
//!
//! Rust has no runtime skip, so with no usable capture each test prints why
//! and passes vacuously; run_all.sh's preflight is what refuses a stale one.

#[allow(dead_code)]
#[path = "all/support.rs"]
mod support;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cru_iap::reasons::{AUDIENCE_MISMATCH, IAP_JWT, MISSING_AUDIENCE_CONFIG};
use cru_iap::{HEADER, Verifier};
use http::{HeaderMap, HeaderValue};
use serde_json::{Map, Value};

use support::{Signer, apply, now, reason, repo_file};

/// Refuse a capture within this many seconds of expiry.
const EXPIRY_MARGIN: i64 = 30;

struct Capture {
    assertion: String,
    claims: Map<String, Value>,
    audience: String,
    expected_email: String,
}

impl Capture {
    fn verifier(&self) -> Verifier {
        // No key_source: this goes over the wire to gstatic.com.
        Verifier::new().audience(&self.audience)
    }
}

fn load() -> Result<Capture, String> {
    let path = std::env::var("CRU_IAP_E2E_CAPTURE")
        .unwrap_or_else(|_| format!("{}/../e2e/okta/capture.json", env!("CARGO_MANIFEST_DIR")));
    let body = std::fs::read_to_string(&path).map_err(|_| {
        format!("no capture at {path}; run: node e2e/okta/capture_assertion.mjs --json")
    })?;
    let capture: Value =
        serde_json::from_str(&body).map_err(|error| format!("{path} is not JSON: {error}"))?;

    let text = |field: &str| {
        capture
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let claims = capture
        .get("claims")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if text("assertion").is_empty() || claims.is_empty() {
        return Err(format!("{path} has no assertion/claims"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("capture has no numeric exp")?;
    if exp <= now() + EXPIRY_MARGIN {
        return Err(format!(
            "capture expired {}s ago; re-run the capture",
            now() - exp
        ));
    }

    // Configuration, never read off the token: taking it from aud would make
    // the positive verify "does aud equal aud".
    let audience = std::env::var("CRU_IAP_E2E_AUDIENCE").unwrap_or_else(|_| text("audience"));
    if audience.is_empty() {
        return Err("no audience: set CRU_IAP_E2E_AUDIENCE".into());
    }
    let expected_email =
        std::env::var("CRU_IAP_E2E_EMAIL").unwrap_or_else(|_| text("expected_email"));
    if expected_email.is_empty() {
        return Err("no expected email: set CRU_IAP_E2E_EMAIL".into());
    }

    Ok(Capture {
        assertion: text("assertion"),
        claims,
        audience,
        expected_email,
    })
}

macro_rules! capture_or_skip {
    () => {
        match load() {
            Ok(capture) => capture,
            Err(why) => {
                eprintln!("SKIPPED: {why}");
                return;
            }
        }
    };
}

#[test]
fn the_assertion_was_minted_by_google_minutes_ago() {
    // Guards the file: a stale or hand-copied token would make the rest a
    // re-test of the offline fixtures.
    let capture = capture_or_skip!();
    let age = now() - capture.claims["iat"].as_i64().unwrap();
    assert!((0..600).contains(&age), "assertion is {age}s old");
}

#[tokio::test]
async fn verifies_against_googles_live_jwks() {
    let capture = capture_or_skip!();
    let identity = capture.verifier().verify(&capture.assertion).await.unwrap();
    assert_eq!(identity.reason, IAP_JWT);
    assert_eq!(identity.email, capture.expected_email);
    // Display names must fall back to the email local part.
    assert_eq!(identity.name, None);
}

#[tokio::test]
async fn verifies_straight_off_the_headers() {
    let capture = capture_or_skip!();
    let mut headers = HeaderMap::new();
    headers.insert(HEADER, HeaderValue::from_str(&capture.assertion).unwrap());
    let identity = capture.verifier().verify_request(&headers).await.unwrap();
    assert_eq!(identity.email, capture.expected_email);
}

// Each below takes the same genuine token and breaks one thing. Without them,
// "it verified" could mean the verifier accepts anything.

#[tokio::test]
async fn is_rejected_once_its_payload_is_edited() {
    let capture = capture_or_skip!();
    let segments: Vec<&str> = capture.assertion.split('.').collect();
    let mut claims = capture.claims.clone();
    claims.insert("email".into(), "attacker@evil.example".into());
    let edited = URL_SAFE_NO_PAD.encode(Value::Object(claims).to_string());
    let forged = format!("{}.{edited}.{}", segments[0], segments[2]);
    let result = capture.verifier().verify(&forged).await;
    assert!(
        reason(&result).starts_with("signature_error:"),
        "{}",
        reason(&result)
    );
}

#[tokio::test]
async fn is_rejected_against_a_different_backend_service() {
    let capture = capture_or_skip!();
    let (project, _) = capture.audience.rsplit_once('/').unwrap();
    let other = format!("{project}/1111111111111111111");
    let result = Verifier::new()
        .audience(other)
        .verify(&capture.assertion)
        .await;
    assert_eq!(reason(&result), AUDIENCE_MISMATCH);
}

#[tokio::test]
async fn is_rejected_with_no_audience_configured() {
    let capture = capture_or_skip!();
    let result = Verifier::new()
        .audience("")
        .verify(&capture.assertion)
        .await;
    assert_eq!(reason(&result), MISSING_AUDIENCE_CONFIG);
}

#[tokio::test]
async fn claims_re_signed_by_our_own_key_are_rejected() {
    // Proof the live JWKS fetch is load-bearing.
    let capture = capture_or_skip!();
    let mut ours = Signer::new();
    ours.kid = "not-googles-key".into();
    let claims = apply(
        Value::Object(capture.claims.clone()),
        serde_json::json!({ "iat": now() - 30, "exp": now() + 600 }),
    );
    let result = capture.verifier().verify(&ours.sign(&claims)).await;
    assert_eq!(reason(&result), "signature_error:no_matching_key");
}

#[test]
fn the_claim_shape_production_actually_emits() {
    let capture = capture_or_skip!();
    let claim = |name: &str| {
        capture
            .claims
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    assert_eq!(
        claim("email"),
        capture.expected_email,
        "a bare address, no namespace"
    );
    assert!(claim("sub").starts_with("sts.google.com:") && !claim("sub").contains('@'));
    let principal = capture.claims["workforce_identity"]["iam_principal"]
        .as_str()
        .unwrap_or("");
    assert!(principal.starts_with("principal://iam.googleapis.com/"));

    // Drift detector: if this fails, every language's offline suite is
    // modelling a shape that no longer exists. Re-capture and update the
    // pinned fixture.
    let pinned: Value =
        serde_json::from_str(&repo_file("spec/fixtures/real_wif_iap_payload.json")).unwrap();
    let mut live: Vec<&String> = capture.claims.keys().collect();
    let mut pinned: Vec<&String> = pinned["claims"].as_object().unwrap().keys().collect();
    live.sort();
    pinned.sort();
    assert_eq!(live, pinned, "claim keys drifted");
}
