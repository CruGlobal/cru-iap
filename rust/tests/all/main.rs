//! One integration-test binary, so the suite links once.

#[cfg(feature = "axum")]
mod axum_layer;
mod claim_shapes;
mod dev_bypass;
mod keys;
mod support;
mod urls;
mod verifier;
mod vocabulary;
