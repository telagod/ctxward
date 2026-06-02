// The detection / redaction / tokenization / policy engine and config types
// live in the IO-free `ctxward-core` crate. Re-export them here so the gateway's
// existing `crate::types::…`, `crate::config::…`, etc. paths keep resolving and
// both shells share one source of truth.
pub use ctxward_core::{auth, config, detect, policy, redact, session, tokenize, types};

pub mod admin_ui;
pub mod app;
pub mod attachments;
pub mod audit;
pub mod benchmarks;
pub mod mitm;
pub mod observability;
pub mod opa;
pub mod platform;
pub mod presidio;
pub mod proxy;
pub mod proxy_mode;
pub mod review;
