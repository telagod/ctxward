//! Ctxward core: the IO-free detection / redaction / tokenization / policy
//! engine and config types, shared by the gateway (reverse proxy + MITM
//! desktop) and — compiled to WASM — the browser extension.
//!
//! These modules reference only each other and pure crates (no tokio / axum /
//! reqwest / hudsucker), so the same detection logic runs identically in every
//! shell with zero drift.

pub mod auth;
pub mod config;
pub mod detect;
pub mod policy;
pub mod redact;
pub mod session;
pub mod tokenize;
pub mod types;
