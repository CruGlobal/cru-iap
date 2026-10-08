//! The axum IAP gate, as a tower layer.
//!
//! The Rust counterpart of `@cruglobal/cru-iap/next`'s `createIapProxy`, and
//! fails closed the same way: no assertion and no `CRU_IAP_DEV_BYPASS_EMAIL`
//! is a 401, in every environment. Opening the gate when `IAP_AUDIENCE` is
//! unset, or a boolean bypass flag, are the incidents this crate exists to
//! prevent.
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use cru_iap::{Identity, axum::IapLayer};
//!
//! let app: Router = Router::new()
//!     .route("/", get(|identity: Identity| async move { identity.email }))
//!     .route("/health", get(|| async { "ok" }))
//!     .layer(IapLayer::new().public_prefixes(["/health"]));
//! ```
//!
//! The identity travels in request extensions, which a client cannot set, so
//! there is no header to strip and no injection point on a public path. That
//! is why there is no counterpart to the Next gate's `x-cru-iap-*` headers.
//!
//! Anything in `public_prefixes` must ALSO be in the IAP module's
//! `bypass_paths`, or the load balancer 401s it before the app runs.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;
use tower_layer::Layer;
use tower_service::Service;

use crate::dev_bypass::{DEV_BYPASS_EMAIL_VAR, dev_bypass_with};
use crate::verifier::{Identity, Verifier};

/// Not a redirect: IAP owns sign-in and has already run, so bouncing the
/// browser only loops.
const UNAUTHORIZED: &str = "Unauthorized";

type Lookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Builds the gate. See the module docs.
#[derive(Clone)]
pub struct IapLayer {
    verifier: Verifier,
    public_prefixes: Arc<[String]>,
    env: Lookup,
}

impl Default for IapLayer {
    fn default() -> Self {
        IapLayer {
            verifier: Verifier::new(),
            public_prefixes: Arc::new([]),
            env: Arc::new(|name| std::env::var(name).ok()),
        }
    }
}

impl IapLayer {
    pub fn new() -> Self {
        IapLayer::default()
    }

    /// Paths served without an identity, matched as `path == prefix ||
    /// path.starts_with(prefix)`. Write directory prefixes with a trailing
    /// slash: "/api/" leaves /apiary gated, where "/api" would not.
    pub fn public_prefixes<I, P>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.public_prefixes = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// The verifier to use: an audience or key source override.
    pub fn verifier(mut self, verifier: Verifier) -> Self {
        self.verifier = verifier;
        self
    }

    /// The environment the dev bypass reads. Defaults to the process env.
    pub fn env(mut self, lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        self.env = Arc::new(lookup);
        self
    }

    fn is_public(&self, path: &str) -> bool {
        self.public_prefixes
            .iter()
            .any(|prefix| path == prefix || path.starts_with(prefix.as_str()))
    }

    async fn identify(&self, headers: &HeaderMap, path: &str) -> Result<Identity, Response> {
        let audience = self.verifier.configured_audience();
        // An audience passed in code is as much proof of a real IAP
        // environment as one in the env, so the bypass has to see it.
        let env = &self.env;
        let bypass = dev_bypass_with(|name| match name {
            "IAP_AUDIENCE" if !audience.is_empty() => Some(audience.clone()),
            _ => env(name),
        });
        let result = match bypass {
            Some(identity) => Ok(identity),
            None => self.verifier.verify_request(headers).await,
        };

        result.map_err(|rejection| {
            tracing::warn!(reason = rejection.reason(), path, "iap_rejected");
            let body = if audience.is_empty() {
                local_hint()
            } else {
                UNAUTHORIZED.to_string()
            };
            (StatusCode::UNAUTHORIZED, body).into_response()
        })
    }
}

/// Shown only when no audience is configured, which locally means "you have
/// not named yourself yet" far more often than a bad assertion.
fn local_hint() -> String {
    format!(
        "Unauthorized: no IAP assertion, and no dev bypass.\n\n\
         This app is gated by Google Identity-Aware Proxy. Running locally there is no\n\
         assertion to verify, so name yourself instead:\n\n  \
         {DEV_BYPASS_EMAIL_VAR}=you@cru.org cargo run\n"
    )
}

impl<S> Layer<S> for IapLayer {
    type Service = IapService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IapService {
            inner,
            gate: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct IapService<S> {
    inner: S,
    gate: IapLayer,
}

impl<S> Service<Request<Body>> for IapService<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        // The inner service was readied, not its clone; swap so the ready one
        // handles this request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let gate = self.gate.clone();

        Box::pin(async move {
            let path = request.uri().path().to_string();
            if gate.is_public(&path) {
                return inner.call(request).await;
            }
            match gate.identify(request.headers(), &path).await {
                Ok(identity) => {
                    request.extensions_mut().insert(identity);
                    inner.call(request).await
                }
                Err(response) => Ok(response),
            }
        })
    }
}

/// The identity `IapLayer` verified. A 401 if the layer is not in front of the
/// handler, so a route mounted outside it fails closed.
impl<S: Send + Sync> FromRequestParts<S> for Identity {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        parts
            .extensions
            .get::<Identity>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}
