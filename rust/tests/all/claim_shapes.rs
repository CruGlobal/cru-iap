//! The claim shapes IAP actually emits, each as a really-signed token. Mirrors
//! claim_shapes_test.go and its siblings; all five suites are anchored to the
//! same pinned capture of a real Google assertion.

use cru_iap::reasons::{IAP_JWT, MISSING_EMAIL};
use serde_json::{Value, json};

use crate::support::*;

fn fixture() -> Value {
    serde_json::from_str(&repo_file("spec/fixtures/real_wif_iap_payload.json")).unwrap()
}

/// Re-timed and re-audienced: the capture expired 600s after it was taken and
/// its signature is deliberately not stored.
fn replay_capture(overrides: Value) -> Value {
    let now = now();
    let claims = apply(
        fixture()["claims"].clone(),
        json!({ "iat": now - 30, "exp": now + 600, "aud": AUDIENCE }),
    );
    apply(claims, overrides)
}

#[tokio::test]
async fn plain_iap_takes_identity_from_the_bare_email_and_ignores_sub() {
    let identity = verify_with(&Signer::new(), iap_claims(json!({})))
        .await
        .unwrap();
    assert_eq!(identity.email, "alice@cru.org");
}

#[tokio::test]
async fn workforce_identity_federation() {
    let signer = Signer::new();
    let identity = verify_with(&signer, wif_claims(json!({}))).await.unwrap();
    assert_eq!(identity.email, "alice@cru.org");
    assert_eq!(
        identity.payload.as_ref().unwrap()["identity_source"],
        "WORKFORCE_IDENTITY"
    );

    // The nested principal is what IAM bindings match, never an identity.
    let someone_else = json!({ "iam_principal": "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/someone-else@cru.org" });
    let identity = verify_with(
        &signer,
        wif_claims(json!({ "workforce_identity": someone_else })),
    )
    .await
    .unwrap();
    assert_eq!(identity.email, "alice@cru.org");

    // An unmapped pool: the fix is in terraform, and only missing_email says so.
    // The principal carries a good subject, and it is still not unwrapped.
    let unmapped = wif_claims(json!({ "email": null }));
    assert!(
        unmapped["workforce_identity"]["iam_principal"]
            .as_str()
            .unwrap()
            .contains("okta-user-9f31c0")
    );
    assert_eq!(reason(&verify_with(&signer, unmapped).await), MISSING_EMAIL);
}

#[tokio::test]
async fn carries_no_group_membership() {
    // Gotcha 8c: there is no groups claim and nothing to derive one from.
    let identity = verify_with(&Signer::new(), wif_claims(json!({})))
        .await
        .unwrap();
    assert!(
        identity
            .payload
            .unwrap()
            .keys()
            .all(|claim| !claim.to_lowercase().contains("group"))
    );
}

#[tokio::test]
async fn the_pinned_real_capture() {
    let signer = Signer::new();
    // The verdict all five languages must agree on.
    let identity = verify_with(&signer, replay_capture(json!({})))
        .await
        .unwrap();
    assert_eq!(identity.reason, IAP_JWT);
    assert_eq!(identity.email, "cru-iap-e2e-test@example.invalid");
    // No name claim at all: the local-part fallback is the production path.
    assert_eq!(identity.name, None);

    assert!(
        verify_with(
            &signer,
            replay_capture(json!({ "workforce_identity": null }))
        )
        .await
        .is_ok()
    );
    assert_eq!(
        reason(&verify_with(&signer, replay_capture(json!({ "email": null }))).await),
        MISSING_EMAIL
    );
}

#[test]
fn the_synthetic_wif_helper_is_faithful_to_the_real_claim_set() {
    // If Google adds or renames a top-level claim, the rest of the suite would
    // otherwise go on testing a fiction.
    let synthetic = wif_claims(json!({}));
    let real = fixture();
    let missing: Vec<&String> = real["claims"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|claim| synthetic.get(claim.as_str()).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "real payload has claims the helper lacks: {missing:?}"
    );
}

#[test]
fn the_capture_stores_no_signature() {
    assert!(
        fixture().get("signature").is_none(),
        "see the fixture's _provenance note"
    );
}
