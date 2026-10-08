//! Real ES256 signing against a throwaway key, so the suite exercises the
//! production verification path with no network.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cru_iap::{IAP_ISSUER, StaticKeys, Verifier, VerifyResult};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Map, Value, json};

pub const AUDIENCE: &str = "/projects/123456789/global/backendServices/9876543210";
pub const KID: &str = "test-key-1";

pub struct Signer {
    key: SigningKey,
    pub kid: String,
}

impl Signer {
    pub fn new() -> Self {
        Signer {
            key: SigningKey::random(&mut rand_core::OsRng),
            kid: KID.into(),
        }
    }

    pub fn sign(&self, claims: &Value) -> String {
        self.sign_with_header(
            &json!({ "alg": "ES256", "kid": self.kid, "typ": "JWT" }),
            claims,
        )
    }

    pub fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            encode(header.to_string()),
            encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", encode(signature.to_bytes()))
    }

    pub fn jwk(&self) -> Value {
        let point = self.key.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
            "x": encode(point.x().unwrap()), "y": encode(point.y().unwrap()),
        })
    }

    pub fn jwks(&self) -> Vec<u8> {
        json!({ "keys": [self.jwk()] }).to_string().into_bytes()
    }

    pub fn keys(&self) -> Arc<StaticKeys> {
        Arc::new(StaticKeys::from_jwks(&self.jwks()).unwrap())
    }

    pub fn verifier(&self) -> Verifier {
        Verifier::new().audience(AUDIENCE).key_source(self.keys())
    }
}

pub fn encode(raw: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub async fn verify_with(signer: &Signer, claims: Value) -> VerifyResult {
    signer.verifier().verify(&signer.sign(&claims)).await
}

pub fn reason(result: &VerifyResult) -> &str {
    match result {
        Ok(identity) => identity.reason,
        Err(rejection) => rejection.reason(),
    }
}

pub fn iap_claims(overrides: Value) -> Value {
    let now = now();
    apply(
        json!({
            "iss": IAP_ISSUER,
            "aud": AUDIENCE,
            "azp": AUDIENCE,
            "sub": "accounts.google.com:104291823410293841029",
            "email": "alice@cru.org",
            "iat": now - 30,
            "exp": now + 600,
        }),
        overrides,
    )
}

pub fn wif_claims(overrides: Value) -> Value {
    let now = now();
    apply(
        json!({
            "iss": IAP_ISSUER,
            "aud": AUDIENCE,
            "azp": AUDIENCE,
            "sub": "sts.google.com:AAFTZtu4HH_YB5N-0PKpuRFXZj-ziDJSvJCIhth-IjORtiSFUzzGWOVy",
            "email": "alice@cru.org",
            "iat": now - 30,
            "exp": now + 600,
            "identity_source": "WORKFORCE_IDENTITY",
            "workforce_identity": {
                "iam_principal": "principal://iam.googleapis.com/locations/global/workforcePools/keepzero-okta-poc/subject/okta-user-9f31c0@cru.org",
                "workforce_pool_name": "locations/global/workforcePools/keepzero-okta-poc",
            },
        }),
        overrides,
    )
}

/// A null override removes the claim.
pub fn apply(mut claims: Value, overrides: Value) -> Value {
    let object: &mut Map<String, Value> = claims.as_object_mut().unwrap();
    if let Value::Object(overrides) = overrides {
        for (key, value) in overrides {
            if value.is_null() {
                object.remove(&key);
            } else {
                object.insert(key, value);
            }
        }
    }
    claims
}

/// A path relative to the repository root.
pub fn repo_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}
