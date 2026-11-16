use std::collections::HashMap;

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use serde_json::Value;

/// Google's IAP key set. Note the `-jwk` suffix: the bare
/// `.../iap/verify/public_key` endpoint serves a PEM map, which is not a JWK set.
pub const IAP_JWKS_URL: &str = "https://www.gstatic.com/iap/verify/public_key-jwk";

/// Why a `KeySource` could not supply a key. The verifier maps the two onto
/// different reasons: a rotated-away key versus an unreachable Google.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The key set was retrieved, but nothing in it matches the token's `kid`.
    UnknownKid,
    /// The key set could not be fetched or parsed.
    Unavailable(String),
}

/// Supplies the public key for a JWK `kid`.
///
/// Narrow on purpose: it is the whole seam tests substitute, so a suite can
/// sign real ES256 tokens against its own key and still run the production
/// verification path.
#[async_trait]
pub trait KeySource: Send + Sync {
    async fn key_for(&self, kid: &str) -> Result<DecodingKey, KeyError>;
}

/// A fixed key set: for tests, and for pinning keys in a hermetic environment.
#[derive(Clone)]
pub struct StaticKeys(HashMap<String, DecodingKey>);

impl StaticKeys {
    pub fn new(keys: HashMap<String, DecodingKey>) -> Self {
        StaticKeys(keys)
    }

    /// From a JWK set document, as Google serves it.
    pub fn from_jwks(body: &[u8]) -> Result<Self, KeyError> {
        parse_jwks(body).map(StaticKeys)
    }
}

#[async_trait]
impl KeySource for StaticKeys {
    async fn key_for(&self, kid: &str) -> Result<DecodingKey, KeyError> {
        self.0.get(kid).cloned().ok_or(KeyError::UnknownKid)
    }
}

/// Parse an EC JWK set into keys by `kid`.
///
/// Non-EC and non-P-256 keys are skipped rather than erroring: Google
/// publishing another key type must not break the ES256 tokens we do
/// understand. A non-empty set that yields nothing usable is an error, though:
/// an empty map would surface as `no_matching_key` and send the reader hunting
/// a rotation that never happened.
///
/// The point is not checked against the curve here; aws-lc-rs refuses an
/// off-curve key at verification, which surfaces as a `signature_error`.
pub fn parse_jwks(body: &[u8]) -> Result<HashMap<String, DecodingKey>, KeyError> {
    let document: Value = serde_json::from_slice(body)
        .map_err(|error| KeyError::Unavailable(format!("unparseable JWKS: {error}")))?;
    let listed = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| KeyError::Unavailable("JWKS has no keys array".into()))?;

    let text = |jwk: &Value, field: &str| {
        jwk.get(field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let mut keys = HashMap::new();
    for jwk in listed {
        let (kid, x, y) = (text(jwk, "kid"), text(jwk, "x"), text(jwk, "y"));
        if text(jwk, "kty") != "EC" || text(jwk, "crv") != "P-256" || kid.is_empty() {
            continue;
        }
        if !coordinate_is_32_bytes(&x) || !coordinate_is_32_bytes(&y) {
            continue;
        }
        if let Ok(key) = DecodingKey::from_ec_components(&x, &y) {
            keys.insert(kid, key);
        }
    }

    if !listed.is_empty() && keys.is_empty() {
        return Err(KeyError::Unavailable(
            "JWKS contained no usable P-256 keys".into(),
        ));
    }
    Ok(keys)
}

/// 32 bytes is 43 unpadded base64url characters, the last of which carries
/// only 4 bits.
fn coordinate_is_32_bytes(coordinate: &str) -> bool {
    coordinate.len() == 43
        && coordinate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(feature = "remote-keys")]
pub use remote::RemoteKeys;

#[cfg(feature = "remote-keys")]
mod remote {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use jsonwebtoken::DecodingKey;
    use tokio::sync::Mutex;

    use super::{IAP_JWKS_URL, KeyError, KeySource, parse_jwks};

    /// Matches googleauth's one-hour key cache and PyJWKClient's lifespan.
    const TTL: Duration = Duration::from_secs(3600);
    /// The least gap between two fetches prompted by an unknown `kid`, so a
    /// stream of bad tokens cannot hammer gstatic.com.
    const REFETCH_FLOOR: Duration = Duration::from_secs(30);
    /// An endpoint that streamed forever would otherwise hold the lock every
    /// concurrent request is waiting on.
    const MAX_BODY: usize = 1 << 20;

    #[derive(Default)]
    struct Cache {
        keys: HashMap<String, DecodingKey>,
        fetched_at: Option<Instant>,
    }

    /// Fetches and caches a JWK set over HTTPS.
    ///
    /// The hot path, a cached and fresh `kid`, does no I/O. An unknown `kid`
    /// triggers one refresh (at most once per 30s) before it is reported, so a
    /// rotation is picked up without a fetch per request. Fetches hold the
    /// lock, so concurrent misses share one request instead of stampeding.
    pub struct RemoteKeys {
        url: String,
        client: reqwest::Client,
        ttl: Duration,
        cache: Mutex<Cache>,
    }

    impl RemoteKeys {
        /// Over `url`, with your own client: a proxy, a tighter timeout, or
        /// instrumentation.
        pub fn new(url: impl Into<String>, client: reqwest::Client) -> Self {
            RemoteKeys {
                url: url.into(),
                client,
                ttl: TTL,
                cache: Mutex::new(Cache::default()),
            }
        }

        /// How long a fetched set is served from cache. Defaults to an hour.
        pub fn cache_for(mut self, ttl: Duration) -> Self {
            self.ttl = ttl;
            self
        }

        /// The process-wide source over Google's key set, shared so its cache
        /// is actually a cache.
        pub fn google() -> &'static RemoteKeys {
            static SHARED: OnceLock<RemoteKeys> = OnceLock::new();
            SHARED.get_or_init(|| {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap_or_default();
                RemoteKeys::new(IAP_JWKS_URL, client)
            })
        }

        async fn fetch(&self) -> Result<HashMap<String, DecodingKey>, KeyError> {
            let unavailable = |error: reqwest::Error| KeyError::Unavailable(error.to_string());
            let mut response = self
                .client
                .get(&self.url)
                .send()
                .await
                .map_err(unavailable)?;
            if !response.status().is_success() {
                return Err(KeyError::Unavailable(format!(
                    "JWKS fetch returned {}",
                    response.status()
                )));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(unavailable)? {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_BODY {
                    return Err(KeyError::Unavailable("JWKS response is over 1 MiB".into()));
                }
            }
            parse_jwks(&body)
        }
    }

    #[async_trait]
    impl KeySource for RemoteKeys {
        async fn key_for(&self, kid: &str) -> Result<DecodingKey, KeyError> {
            let mut cache = self.cache.lock().await;
            let age = cache.fetched_at.map(|fetched_at| fetched_at.elapsed());
            let cached = cache.keys.get(kid).cloned();

            let refresh = match (&cached, age) {
                (Some(_), Some(age)) => age >= self.ttl,
                (None, Some(age)) => age >= REFETCH_FLOOR,
                (_, None) => true,
            };
            if !refresh {
                return cached.ok_or(KeyError::UnknownKid);
            }

            match self.fetch().await {
                Ok(keys) => {
                    cache.keys = keys;
                    cache.fetched_at = Some(Instant::now());
                    cache.keys.get(kid).cloned().ok_or(KeyError::UnknownKid)
                }
                // Serve a cached key rather than lock every user out over a
                // transient gstatic.com blip. The TTL bounds how stale it is.
                Err(error) => cached.ok_or(error),
            }
        }
    }
}
