use cru_iap::{KeyError, KeySource, StaticKeys, parse_jwks};
use serde_json::json;

use crate::support::Signer;

#[test]
fn parses_googles_shape() {
    let signer = Signer::new();
    assert!(
        parse_jwks(&signer.jwks())
            .unwrap()
            .contains_key(&signer.kid)
    );
}

#[test]
fn errors_on_unparseable_json() {
    assert!(matches!(
        parse_jwks(b"<html>"),
        Err(KeyError::Unavailable(_))
    ));
    assert!(matches!(parse_jwks(b"{}"), Err(KeyError::Unavailable(_))));
}

#[test]
fn skips_an_unusable_key_but_keeps_the_rest() {
    let signer = Signer::new();
    let mut short = signer.jwk();
    short["kid"] = "short".into();
    short["x"] = "AAAA".into();
    let set = json!({ "keys": [
        { "kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB" },
        { "kty": "EC", "crv": "P-384", "kid": "p384", "x": "AA", "y": "AA" },
        short,
        signer.jwk(),
    ]});
    let keys = parse_jwks(set.to_string().as_bytes()).unwrap();
    assert_eq!(keys.keys().collect::<Vec<_>>(), vec![&signer.kid]);
}

#[test]
fn errors_when_nothing_in_a_non_empty_set_is_usable() {
    let set = json!({ "keys": [{ "kty": "RSA", "kid": "rsa" }] });
    assert!(matches!(
        parse_jwks(set.to_string().as_bytes()),
        Err(KeyError::Unavailable(_))
    ));
    assert!(parse_jwks(br#"{"keys": []}"#).unwrap().is_empty());
}

#[tokio::test]
async fn an_off_curve_point_never_verifies() {
    // Parsed, but refused by aws-lc-rs at verification.
    use crate::support::*;
    let signer = Signer::new();
    let mut jwk = signer.jwk();
    jwk["y"] = encode([7u8; 32]).into();
    let keys = StaticKeys::from_jwks(json!({ "keys": [jwk] }).to_string().as_bytes()).unwrap();
    let verifier = cru_iap::Verifier::new()
        .audience(AUDIENCE)
        .key_source(std::sync::Arc::new(keys));
    let result = verifier.verify(&signer.sign(&iap_claims(json!({})))).await;
    assert!(result.unwrap_err().reason().starts_with("signature_error:"));
}

#[tokio::test]
async fn static_keys_report_an_unknown_kid() {
    let keys = StaticKeys::from_jwks(&Signer::new().jwks()).unwrap();
    assert_eq!(keys.key_for("nope").await.err(), Some(KeyError::UnknownKid));
}

#[cfg(feature = "remote-keys")]
mod remote {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use cru_iap::{KeyError, KeySource, RemoteKeys};

    use crate::support::Signer;

    struct Endpoint {
        url: String,
        fetches: Arc<AtomicUsize>,
        status: Arc<AtomicU16>,
    }

    async fn serve(body: Vec<u8>) -> Endpoint {
        let fetches = Arc::new(AtomicUsize::new(0));
        let status = Arc::new(AtomicU16::new(200));
        let (counter, code) = (fetches.clone(), status.clone());
        let app = Router::new().route(
            "/jwks",
            get(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let status = StatusCode::from_u16(code.load(Ordering::SeqCst)).unwrap();
                let body = body.clone();
                async move { (status, body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Endpoint {
            url,
            fetches,
            status,
        }
    }

    #[tokio::test]
    async fn fetches_once_and_serves_the_rest_from_cache() {
        let signer = Signer::new();
        let endpoint = serve(signer.jwks()).await;
        let keys = RemoteKeys::new(&endpoint.url, reqwest::Client::new());
        for _ in 0..3 {
            keys.key_for(&signer.kid).await.unwrap();
        }
        assert_eq!(endpoint.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unknown_kid_refreshes_once_then_waits_out_the_floor() {
        let signer = Signer::new();
        let endpoint = serve(signer.jwks()).await;
        let keys = RemoteKeys::new(&endpoint.url, reqwest::Client::new());
        keys.key_for(&signer.kid).await.unwrap();
        for _ in 0..3 {
            assert_eq!(
                keys.key_for("stranger").await.err(),
                Some(KeyError::UnknownKid)
            );
        }
        assert_eq!(
            endpoint.fetches.load(Ordering::SeqCst),
            1,
            "a bad token cannot hammer the endpoint"
        );
    }

    #[tokio::test]
    async fn reports_a_non_200() {
        let endpoint = serve(Signer::new().jwks()).await;
        endpoint.status.store(503, Ordering::SeqCst);
        let keys = RemoteKeys::new(&endpoint.url, reqwest::Client::new());
        assert!(matches!(
            keys.key_for("any").await,
            Err(KeyError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn serves_a_cached_key_when_a_refresh_fails() {
        let signer = Signer::new();
        let endpoint = serve(signer.jwks()).await;
        let keys = RemoteKeys::new(&endpoint.url, reqwest::Client::new()).cache_for(Duration::ZERO);
        keys.key_for(&signer.kid).await.unwrap();
        endpoint.status.store(503, Ordering::SeqCst);
        keys.key_for(&signer.kid).await.unwrap();
        assert_eq!(endpoint.fetches.load(Ordering::SeqCst), 2, "it did try");
    }
}
