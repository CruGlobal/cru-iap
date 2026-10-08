use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cru_iap::reasons::*;
use cru_iap::{DecodingKey, HEADER, KeyError, KeySource, Verifier, is_known_reason};
use http::{HeaderMap, HeaderValue};
use serde_json::{Value, json};

use crate::support::*;

#[tokio::test]
async fn accepts_a_valid_assertion() {
    let identity = verify_with(&Signer::new(), iap_claims(json!({})))
        .await
        .unwrap();
    assert_eq!(identity.reason, IAP_JWT);
    assert_eq!(identity.email, "alice@cru.org");
}

#[tokio::test]
async fn exposes_the_payload_for_callers_needing_another_claim() {
    let identity = verify_with(&Signer::new(), iap_claims(json!({ "hd": "cru.org" })))
        .await
        .unwrap();
    assert_eq!(identity.payload.unwrap()["hd"], "cru.org");
}

#[tokio::test]
async fn normalizes_the_email() {
    let signer = Signer::new();
    for raw in [
        "Alice@Cru.org",
        "  alice@cru.org  ",
        "accounts.google.com:alice@cru.org",
        "sts.google.com:ALICE@cru.org",
        "securetoken.google.com/p/t:alice@cru.org",
    ] {
        let result = verify_with(&signer, iap_claims(json!({ "email": raw }))).await;
        assert_eq!(
            result.map(|identity| identity.email),
            Ok("alice@cru.org".into()),
            "{raw}"
        );
    }
}

#[tokio::test]
async fn the_name_claim() {
    let signer = Signer::new();
    let name = |claims| async { verify_with(&signer, claims).await.unwrap().name };
    assert_eq!(
        name(iap_claims(json!({ "name": " Alice Example " })))
            .await
            .as_deref(),
        Some("Alice Example")
    );
    assert_eq!(name(iap_claims(json!({ "name": "   " }))).await, None);
    // Decoration, not identity: a non-string degrades rather than rejecting.
    assert_eq!(name(iap_claims(json!({ "name": ["Alice"] }))).await, None);
}

#[tokio::test]
async fn fails_closed_on_a_missing_token() {
    let verifier = Signer::new().verifier();
    for token in ["", "   ", "\n"] {
        assert_eq!(
            verifier.verify(token).await.unwrap_err().reason(),
            MISSING_TOKEN
        );
    }
}

#[tokio::test]
async fn fails_closed_when_no_audience_is_configured() {
    let signer = Signer::new();
    let verifier = Verifier::new().audience("  ").key_source(signer.keys());
    let result = verifier.verify(&signer.sign(&iap_claims(json!({})))).await;
    assert_eq!(result.unwrap_err().reason(), MISSING_AUDIENCE_CONFIG);
}

#[tokio::test]
async fn rejects_a_token_signed_by_someone_else() {
    let signer = Signer::new();
    let forger = Signer::new();
    let result = signer
        .verifier()
        .verify(&forger.sign(&iap_claims(json!({}))))
        .await;
    assert!(result.unwrap_err().reason().starts_with(SIGNATURE_ERROR));
}

#[tokio::test]
async fn rejects_an_unknown_kid() {
    let signer = Signer::new();
    let mut stranger = Signer::new();
    stranger.kid = "rotated-away".into();
    let result = signer
        .verifier()
        .verify(&stranger.sign(&iap_claims(json!({}))))
        .await;
    assert_eq!(
        result.unwrap_err().reason(),
        "signature_error:no_matching_key"
    );
}

#[tokio::test]
async fn rejects_a_tampered_payload() {
    let signer = Signer::new();
    let token = signer.sign(&iap_claims(json!({})));
    let parts: Vec<&str> = token.split('.').collect();
    let forged = encode(iap_claims(json!({ "email": "admin@cru.org" })).to_string());
    let result = signer
        .verifier()
        .verify(&format!("{}.{forged}.{}", parts[0], parts[2]))
        .await;
    assert!(result.unwrap_err().reason().starts_with(SIGNATURE_ERROR));
}

#[tokio::test]
async fn rejects_alg_confusion_and_none() {
    let signer = Signer::new();
    for alg in ["none", "HS256", "RS256", "ES384", "PS256", "", "es256"] {
        let token =
            signer.sign_with_header(&json!({ "alg": alg, "kid": KID }), &iap_claims(json!({})));
        let result = signer.verifier().verify(&token).await;
        assert_eq!(
            result.unwrap_err().reason(),
            "verification_error:AlgNotAllowed",
            "alg {alg:?}"
        );
    }
}

#[tokio::test]
async fn rejects_a_mangled_signature() {
    // ES256 in JWS is the fixed-width 64-byte r||s form, never DER.
    let signer = Signer::new();
    let token = signer.sign(&iap_claims(json!({})));
    let parts: Vec<&str> = token.split('.').collect();
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[2])
        .unwrap();
    let mut extended = raw.clone();
    extended.push(0);
    for mangled in [raw[..32].to_vec(), extended, vec![]] {
        let token = format!("{}.{}.{}", parts[0], parts[1], encode(&mangled));
        let result = signer.verifier().verify(&token).await;
        assert!(
            result.unwrap_err().reason().starts_with(SIGNATURE_ERROR),
            "{} bytes",
            mangled.len()
        );
    }
}

#[tokio::test]
async fn rejects_what_is_not_a_compact_jws() {
    let verifier = Signer::new().verifier();
    for token in ["abc", "a.b", "a.b.c.d", "!!!.b.c", "e30.b.c"] {
        let reason = verifier
            .verify(token)
            .await
            .unwrap_err()
            .reason()
            .to_string();
        assert!(
            reason.starts_with(SIGNATURE_ERROR) || reason == "verification_error:AlgNotAllowed",
            "{token}: {reason}"
        );
    }
}

#[tokio::test]
async fn the_audience() {
    let signer = Signer::new();
    let check = |aud: Value| verify_with(&signer, iap_claims(json!({ "aud": aud })));
    assert_eq!(
        reason(&check(json!("/projects/1/global/backendServices/2")).await),
        AUDIENCE_MISMATCH
    );
    assert!(
        check(json!(["/other", AUDIENCE])).await.is_ok(),
        "an array containing ours"
    );
    assert_eq!(reason(&check(json!(["/other"])).await), AUDIENCE_MISMATCH);
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "aud": null }))).await),
        AUDIENCE_MISMATCH
    );
}

#[tokio::test]
async fn the_issuer() {
    let signer = Signer::new();
    assert_eq!(
        reason(
            &verify_with(
                &signer,
                iap_claims(json!({ "iss": "https://accounts.google.com" }))
            )
            .await
        ),
        ISSUER_MISMATCH
    );
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "iss": null }))).await),
        ISSUER_MISMATCH
    );
}

#[tokio::test]
async fn the_expiry() {
    let signer = Signer::new();
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "exp": now() - 5 }))).await),
        EXPIRED_TOKEN
    );
    // The Ruby jwt gem, jose and PyJWT all skip the check when exp is absent.
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "exp": null }))).await),
        MISSING_EXP
    );
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "exp": "1785030166" }))).await),
        MISSING_EXP
    );
}

#[tokio::test]
async fn defaults_to_no_clock_tolerance_and_honours_one() {
    // jsonwebtoken's own default leeway is 60s; the siblings' is zero.
    let signer = Signer::new();
    let token = signer.sign(&iap_claims(json!({ "exp": now() - 5 })));
    assert_eq!(
        reason(&signer.verifier().verify(&token).await),
        EXPIRED_TOKEN
    );
    let tolerant = signer.verifier().clock_tolerance(Duration::from_secs(60));
    assert!(tolerant.verify(&token).await.is_ok());
}

#[tokio::test]
async fn the_email_claim() {
    let signer = Signer::new();
    let check = |email: Value| verify_with(&signer, iap_claims(json!({ "email": email })));
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "email": null }))).await),
        MISSING_EMAIL
    );
    assert_eq!(reason(&check(json!("   ")).await), MISSING_EMAIL);
    assert_eq!(
        reason(&check(json!("accounts.google.com:")).await),
        MISSING_EMAIL
    );
    for malformed in [
        json!("not-an-address"),
        json!("alice@"),
        json!("a b@cru.org"),
        json!("alice@cru.org\nbob@cru.org"),
        json!(["alice@cru.org"]),
        json!(42),
        json!({ "email": "alice@cru.org" }),
    ] {
        assert_eq!(
            reason(&check(malformed.clone()).await),
            MALFORMED_SUBJECT,
            "{malformed}"
        );
    }
}

#[tokio::test]
async fn never_falls_back_to_sub() {
    let signer = Signer::new();
    let result = verify_with(
        &signer,
        iap_claims(json!({ "email": null, "sub": "accounts.google.com:alice@cru.org" })),
    )
    .await;
    assert_eq!(reason(&result), MISSING_EMAIL);
}

#[tokio::test]
async fn rejects_the_principal_uri_that_survives_the_colon_strip() {
    // "principal:" is stripped as a namespace, leaving "//iam…/subject/alice@cru.org",
    // which the address pattern alone would accept.
    let signer = Signer::new();
    let email =
        "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/alice@cru.org";
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "email": email }))).await),
        MALFORMED_SUBJECT
    );
    let backslash = "a\\b@cru.org";
    assert_eq!(
        reason(&verify_with(&signer, iap_claims(json!({ "email": backslash }))).await),
        MALFORMED_SUBJECT
    );
}

struct Failing;

#[async_trait]
impl KeySource for Failing {
    async fn key_for(&self, _: &str) -> Result<DecodingKey, KeyError> {
        Err(KeyError::Unavailable("connection refused".into()))
    }
}

struct Panicking;

#[async_trait]
impl KeySource for Panicking {
    async fn key_for(&self, _: &str) -> Result<DecodingKey, KeyError> {
        panic!("something nobody anticipated")
    }
}

#[tokio::test]
async fn an_unreachable_key_source_is_a_key_source_error() {
    let signer = Signer::new();
    let verifier = Verifier::new()
        .audience(AUDIENCE)
        .key_source(Arc::new(Failing));
    let result = verifier.verify(&signer.sign(&iap_claims(json!({})))).await;
    assert_eq!(reason(&result), "verification_error:KeySourceError");
}

#[tokio::test]
async fn the_fail_closed_backstop_catches_a_panic() {
    let signer = Signer::new();
    let verifier = Verifier::new()
        .audience(AUDIENCE)
        .key_source(Arc::new(Panicking));
    let result = verifier.verify(&signer.sign(&iap_claims(json!({})))).await;
    assert_eq!(reason(&result), UNEXPECTED_ERROR);
}

#[tokio::test]
async fn every_failure_reason_is_in_the_vocabulary() {
    let signer = Signer::new();
    let tokens = [
        String::new(),
        "abc".into(),
        signer.sign(&iap_claims(json!({ "exp": now() - 5 }))),
        signer.sign(&iap_claims(json!({ "aud": "/x" }))),
        signer.sign(&iap_claims(json!({ "iss": "/x" }))),
        signer.sign(&iap_claims(json!({ "exp": null }))),
        signer.sign(&iap_claims(json!({ "email": null }))),
        signer.sign(&iap_claims(json!({ "email": 1 }))),
        signer.sign(&iap_claims(json!({ "nbf": now() + 600 }))),
        Signer::new().sign(&iap_claims(json!({}))),
        signer.sign_with_header(&json!({ "alg": "none" }), &iap_claims(json!({}))),
    ];
    for token in tokens {
        let rejection = signer.verifier().verify(&token).await.unwrap_err();
        assert!(
            is_known_reason(rejection.reason()),
            "{}",
            rejection.reason()
        );
    }
}

#[tokio::test]
async fn verify_request() {
    let signer = Signer::new();
    let token = signer.sign(&iap_claims(json!({})));
    let mut headers = HeaderMap::new();
    assert_eq!(
        reason(&signer.verifier().verify_request(&headers).await),
        MISSING_TOKEN
    );

    headers.insert(
        "X-Goog-IAP-JWT-Assertion",
        HeaderValue::from_str(&token).unwrap(),
    );
    assert!(
        signer.verifier().verify_request(&headers).await.is_ok(),
        "case-insensitive"
    );

    // Two assertions is not a shape IAP produces; refuse to pick one.
    headers.append(HEADER, HeaderValue::from_str(&token).unwrap());
    assert_eq!(
        reason(&signer.verifier().verify_request(&headers).await),
        MISSING_TOKEN
    );
}

#[tokio::test]
async fn reads_the_audience_from_the_environment_at_call_time() {
    // The only test that touches process env, so it cannot race another.
    let signer = Signer::new();
    let verifier = Verifier::new().key_source(signer.keys());
    let token = signer.sign(&iap_claims(json!({})));
    unsafe { std::env::remove_var("IAP_AUDIENCE") };
    assert_eq!(
        reason(&verifier.verify(&token).await),
        MISSING_AUDIENCE_CONFIG
    );
    unsafe { std::env::set_var("IAP_AUDIENCE", AUDIENCE) };
    let result = verifier.verify(&token).await;
    unsafe { std::env::remove_var("IAP_AUDIENCE") };
    assert!(result.is_ok());
}
