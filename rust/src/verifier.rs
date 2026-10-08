//! Verifies the Google-signed JWT that Identity-Aware Proxy injects on every
//! request it lets through, and extracts an email identity.
//!
//! A port of `CruIap::TokenVerifier`, src/verifier.ts, cru_iap/verifier.py and
//! cruiap/verifier.go. All five share a rejection vocabulary and every
//! claim-shape decision; keep them in step.
//!
//! jsonwebtoken does the signature, `exp`, `aud` and `iss` checks; its typed
//! error kinds are mapped onto the shared vocabulary in `reason_for`.
//! Two things are checked here rather than trusted to it:
//!
//! - `alg` is read off the header before jsonwebtoken sees the token, because
//!   its `Algorithm` enum has no `none` and would report that as a JSON error
//!   rather than as the alg confusion it is.
//! - `iss` is re-asserted after it passes, emitting `bad_iss:` if a future
//!   change ever drops the issuer from the `Validation`.

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::FutureExt;
use http::HeaderMap;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation};
use regex::Regex;
use serde_json::{Map, Value};

use crate::keys::{KeyError, KeySource};
use crate::reasons;
use crate::request::assertion_from;

/// The only issuer the verifier trusts.
pub const IAP_ISSUER: &str = "https://cloud.google.com/iap";

/// `URI::MailTo::EMAIL_REGEXP`, ported character for character from Ruby so
/// all five verifiers accept and reject exactly the same strings.
static EMAIL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
    )
    .expect("EMAIL_PATTERN compiles")
});

/// A verified identity.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    /// Normalized: namespace prefix stripped, lowercased.
    pub email: String,
    /// `None` when absent, blank or not a string. The real WIF payload has no
    /// `name` claim, so fall back to the email's local part.
    pub name: Option<String>,
    /// `reasons::IAP_JWT`, or `reasons::DEV_BYPASS`.
    pub reason: &'static str,
    /// Every claim, for a caller that needs another one. `None` under the dev
    /// bypass, where no assertion was verified.
    pub payload: Option<Map<String, Value>>,
}

/// Why a request was refused. The reason is for telemetry and is drawn from
/// `reasons::REASONS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    reason: String,
}

impl Rejection {
    fn new(reason: impl Into<String>) -> Self {
        Rejection {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "IAP assertion rejected: {}", self.reason)
    }
}

impl std::error::Error for Rejection {}

pub type VerifyResult = Result<Identity, Rejection>;

/// The verifier's configuration. `Verifier::default()` reads `IAP_AUDIENCE` at
/// call time and uses the process-wide Google key source.
#[derive(Clone, Default)]
pub struct Verifier {
    audience: Option<String>,
    keys: Option<Arc<dyn KeySource>>,
    leeway: Duration,
}

impl Verifier {
    pub fn new() -> Self {
        Verifier::default()
    }

    /// Overrides `IAP_AUDIENCE`.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Overrides the shared Google key source.
    pub fn key_source(mut self, keys: Arc<dyn KeySource>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Leeway on `exp`. Defaults to zero, unlike jsonwebtoken's own 60s, to
    /// match the siblings.
    pub fn clock_tolerance(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// The audience this verifier will check against: the override, else
    /// `IAP_AUDIENCE` as it is right now. Blank when neither is set.
    pub fn configured_audience(&self) -> String {
        match &self.audience {
            Some(audience) => audience.trim().to_string(),
            None => std::env::var("IAP_AUDIENCE")
                .unwrap_or_default()
                .trim()
                .to_string(),
        }
    }

    /// Pulls the assertion off the request's headers, so application code
    /// never names the header.
    pub async fn verify_request(&self, headers: &HeaderMap) -> VerifyResult {
        self.verify(assertion_from(headers).unwrap_or("")).await
    }

    /// Verify a raw assertion.
    ///
    /// Never panics: every path returns a result, and a panic anywhere below
    /// (a key source's, say) becomes `unexpected_error`. An authentication
    /// check must not become a 500, or a crash some upstream handler swallows
    /// into a pass. (Under `panic = "abort"` there is nothing to catch.)
    pub async fn verify(&self, assertion: &str) -> VerifyResult {
        match AssertUnwindSafe(self.attempt(assertion))
            .catch_unwind()
            .await
        {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("[cru-iap] unexpected panic during verification");
                Err(Rejection::new(reasons::UNEXPECTED_ERROR))
            }
        }
    }

    async fn attempt(&self, assertion: &str) -> VerifyResult {
        let token = assertion.trim();
        if token.is_empty() {
            return Err(Rejection::new(reasons::MISSING_TOKEN));
        }
        // Fail closed if unset, so a misconfigured deploy never accepts
        // unaudienced tokens.
        let audience = self.configured_audience();
        if audience.is_empty() {
            return Err(Rejection::new(reasons::MISSING_AUDIENCE_CONFIG));
        }

        let header = read_header(token)?;
        // Pinned before touching a key: a key set that also published an RSA
        // or HMAC key, or a token claiming "none", must not be able to talk us
        // into a weaker verification.
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(verification_error("AlgNotAllowed"));
        }
        let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");

        let key = match self.key_for(kid).await {
            Ok(key) => key,
            // Ruby reports this as a SignatureError and the other siblings as
            // signature_error:no_matching_key; keep it in the same bucket.
            Err(KeyError::UnknownKid) => return Err(signature_error("no_matching_key")),
            Err(KeyError::Unavailable(detail)) => {
                tracing::warn!(detail, "[cru-iap] could not load Google's IAP keys");
                return Err(verification_error("KeySourceError"));
            }
        };

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[IAP_ISSUER]);
        validation.set_audience(&[&audience]);
        // Required explicitly. IAP always sets exp, but the Ruby jwt gem, jose
        // and PyJWT all skip the expiry check when it is absent, so it is
        // never assumed.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        // jsonwebtoken skips nbf by default; jose, PyJWT and the Ruby jwt gem
        // all enforce it when present.
        validation.validate_nbf = true;
        validation.leeway = self.leeway.as_secs();

        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|error| Rejection::new(reason_for(error.kind())))?
            .claims;

        let issuer = claims.get("iss").and_then(Value::as_str).unwrap_or("");
        if issuer != IAP_ISSUER {
            return Err(Rejection::new(format!("{}{issuer}", reasons::BAD_ISS)));
        }

        identity_from(claims)
    }

    async fn key_for(&self, kid: &str) -> Result<jsonwebtoken::DecodingKey, KeyError> {
        match &self.keys {
            Some(keys) => keys.key_for(kid).await,
            #[cfg(feature = "remote-keys")]
            None => crate::keys::RemoteKeys::google().key_for(kid).await,
            #[cfg(not(feature = "remote-keys"))]
            None => Err(KeyError::Unavailable(
                "no key source: enable the remote-keys feature or call Verifier::key_source".into(),
            )),
        }
    }
}

/// Verify a raw assertion with the default `Verifier`.
pub async fn verify(assertion: &str) -> VerifyResult {
    Verifier::new().verify(assertion).await
}

/// Verify the assertion on a request's headers with the default `Verifier`.
pub async fn verify_request(headers: &HeaderMap) -> VerifyResult {
    Verifier::new().verify_request(headers).await
}

fn signature_error(detail: &str) -> Rejection {
    Rejection::new(format!("{}{detail}", reasons::SIGNATURE_ERROR))
}

fn verification_error(detail: &str) -> Rejection {
    Rejection::new(format!("{}{detail}", reasons::VERIFICATION_ERROR))
}

fn read_header(token: &str) -> Result<Map<String, Value>, Rejection> {
    let mut segments = token.split('.');
    let (Some(header), Some(_), Some(_), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(signature_error("not a compact JWS"));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| signature_error("undecodable header"))?;
    serde_json::from_slice(&bytes).map_err(|_| signature_error("unparseable header"))
}

/// Map a jsonwebtoken failure onto the shared vocabulary.
fn reason_for(kind: &ErrorKind) -> String {
    match kind {
        ErrorKind::ExpiredSignature => reasons::EXPIRED_TOKEN.into(),
        ErrorKind::InvalidAudience => reasons::AUDIENCE_MISMATCH.into(),
        ErrorKind::InvalidIssuer => reasons::ISSUER_MISMATCH.into(),
        ErrorKind::MissingRequiredClaim(claim) => match claim.as_str() {
            "exp" => reasons::MISSING_EXP.into(),
            "aud" => reasons::AUDIENCE_MISMATCH.into(),
            "iss" => reasons::ISSUER_MISMATCH.into(),
            other => format!(
                "{}MissingRequiredClaim_{other}",
                reasons::VERIFICATION_ERROR
            ),
        },
        // A present but unreadable exp is no expiry at all; the siblings say
        // missing_exp too.
        ErrorKind::InvalidClaimFormat(claim) if claim == "exp" => reasons::MISSING_EXP.into(),
        ErrorKind::InvalidClaimFormat(claim) => {
            format!("{}InvalidClaimFormat_{claim}", reasons::VERIFICATION_ERROR)
        }
        ErrorKind::InvalidSignature => {
            format!("{}signature did not verify", reasons::SIGNATURE_ERROR)
        }
        ErrorKind::InvalidToken => format!("{}not a compact JWS", reasons::SIGNATURE_ERROR),
        ErrorKind::Base64(_) => format!("{}undecodable segment", reasons::SIGNATURE_ERROR),
        ErrorKind::Json(_) | ErrorKind::Utf8(_) => {
            format!("{}unparseable payload", reasons::SIGNATURE_ERROR)
        }
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::MissingAlgorithm => {
            format!("{}AlgNotAllowed", reasons::VERIFICATION_ERROR)
        }
        // A key the backend refuses: off the curve, or malformed.
        ErrorKind::InvalidEcdsaKey | ErrorKind::InvalidKeyFormat => {
            format!("{}invalid key", reasons::SIGNATURE_ERROR)
        }
        other => format!("{}{}", reasons::VERIFICATION_ERROR, kind_name(other)),
    }
}

/// The variant name alone: `Debug` on a tuple variant would leak its payload
/// into a Datadog facet.
fn kind_name(kind: &ErrorKind) -> String {
    let debug = format!("{kind:?}");
    debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn identity_from(claims: Map<String, Value>) -> VerifyResult {
    let raw_email = claims.get("email").filter(|value| !value.is_null());
    // A non-string email is something that arrived and is not an address, so
    // it is malformed_subject, not missing_email. Never coerced.
    let email = match raw_email {
        None => String::new(),
        Some(Value::String(email)) => normalize_email(email),
        Some(other) => {
            let (detail, payload) = (
                format!("email claim is {}", json_type(other)),
                describe(&claims),
            );
            tracing::warn!(detail, payload, "[cru-iap] malformed subject");
            return Err(Rejection::new(reasons::MALFORMED_SUBJECT));
        }
    };

    // Two reasons on purpose. missing_email: the pool never sent one, an
    // infrastructure fix. malformed_subject: something arrived that is not an
    // address. Different fixes, so keep them apart in Datadog.
    if email.is_empty() {
        return Err(Rejection::new(reasons::MISSING_EMAIL));
    }
    // The pattern alone is not enough: RFC 5322 allows "/" in a local part, so
    // principal://.../subject/alice@cru.org matches it. No real identity
    // contains a slash or backslash.
    if !EMAIL_PATTERN.is_match(&email) || email.contains(['/', '\\']) {
        let payload = describe(&claims);
        tracing::warn!(normalized = %email, payload, "[cru-iap] malformed subject");
        return Err(Rejection::new(reasons::MALFORMED_SUBJECT));
    }

    // Decoration, not identity: a non-string degrades to None rather than
    // rejecting the request.
    let name = claims
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string);

    Ok(Identity {
        email,
        name,
        reason: reasons::IAP_JWT,
        payload: Some(claims),
    })
}

/// `email` is the identity in every IAP mode; `sub` is never one, so this
/// does not read it. Confirmed 2026-07-24 against a live workforce capture
/// (spec/fixtures/real_wif_iap_payload.json):
///
/// ```text
/// mode                      email         sub
/// plain IAP (Google id)     bare address  accounts.google.com:<opaque>
/// WIF, google.email mapped  bare address  sts.google.com:<opaque STS>
/// WIF, mapping absent       ABSENT        sts.google.com:<opaque STS>
/// ```
///
/// Strip a leading "<prefix>:" namespace (a real address never contains a
/// colon), then lowercase.
fn normalize_email(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .split_once(':')
        .map_or(trimmed, |(_, address)| address)
        .to_lowercase()
}

/// Identity claims, not credentials: same sensitivity as the emails already in
/// request logs, and it makes a rejection diagnosable without redeploying.
fn describe(claims: &Map<String, Value>) -> String {
    serde_json::to_string(claims).unwrap_or_default()
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
