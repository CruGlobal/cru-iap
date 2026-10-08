use std::collections::HashMap;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use cru_iap::axum::IapLayer;
use cru_iap::{DEV_BYPASS_EMAIL_VAR, HEADER, Identity, Verifier};
use serde_json::json;
use tower::ServiceExt;

use crate::support::*;

fn app(layer: IapLayer) -> Router {
    Router::new()
        .route("/who", get(|identity: Identity| async move { format!("{} {}", identity.email, identity.reason) }))
        .route("/health", get(|| async { "ok" }))
        .route("/healthz/deep", get(|| async { "deep" }))
        .layer(layer)
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name| map.get(name).cloned()
}

async fn get_path(app: &Router, path: &str, assertion: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::builder().uri(path);
    if let Some(assertion) = assertion {
        request = request.header(HEADER, assertion);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn a_verified_assertion_reaches_the_handler_as_its_person() {
    let signer = Signer::new();
    let app = app(IapLayer::new().verifier(signer.verifier()).env(env(&[])));
    let token = signer.sign(&iap_claims(json!({})));
    assert_eq!(
        get_path(&app, "/who", Some(&token)).await,
        (StatusCode::OK, "alice@cru.org iap_jwt".into())
    );
}

#[tokio::test]
async fn fails_closed_without_an_assertion() {
    let signer = Signer::new();
    let app = app(IapLayer::new().verifier(signer.verifier()).env(env(&[])));
    assert_eq!(
        get_path(&app, "/who", None).await,
        (StatusCode::UNAUTHORIZED, "Unauthorized".into())
    );
    let forged = Signer::new().sign(&iap_claims(json!({})));
    assert_eq!(
        get_path(&app, "/who", Some(&forged)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn fails_closed_with_no_audience_and_says_how_to_run_locally() {
    let signer = Signer::new();
    let app = app(IapLayer::new()
        .verifier(Verifier::new().audience("").key_source(signer.keys()))
        .env(env(&[])));
    let (status, body) = get_path(&app, "/who", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains(DEV_BYPASS_EMAIL_VAR), "{body}");
}

#[tokio::test]
async fn public_prefixes_skip_the_gate_by_exact_or_prefix_match() {
    let app = app(IapLayer::new()
        .public_prefixes(["/health"])
        .verifier(Signer::new().verifier())
        .env(env(&[])));
    assert_eq!(get_path(&app, "/health", None).await.0, StatusCode::OK);
    assert_eq!(
        get_path(&app, "/healthz/deep", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        get_path(&app, "/who", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_extractor_fails_closed_on_a_public_path() {
    let router = Router::new()
        .route(
            "/open/who",
            get(|identity: Identity| async move { identity.email }),
        )
        .layer(
            IapLayer::new()
                .public_prefixes(["/open/"])
                .verifier(Signer::new().verifier())
                .env(env(&[])),
        );
    assert_eq!(
        get_path(&router, "/open/who", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_dev_bypass_names_the_developer_locally() {
    let signer = Signer::new();
    let local = Verifier::new().audience("").key_source(signer.keys());
    let app = app(IapLayer::new()
        .verifier(local)
        .env(env(&[(DEV_BYPASS_EMAIL_VAR, "you@cru.org")])));
    assert_eq!(
        get_path(&app, "/who", None).await,
        (StatusCode::OK, "you@cru.org dev_bypass".into())
    );
}

#[tokio::test]
async fn the_dev_bypass_sees_an_audience_passed_in_code() {
    let signer = Signer::new();
    let app = app(IapLayer::new()
        .verifier(signer.verifier())
        .env(env(&[(DEV_BYPASS_EMAIL_VAR, "you@cru.org")])));
    assert_eq!(
        get_path(&app, "/who", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}
