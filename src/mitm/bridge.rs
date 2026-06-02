//! Bridges hudsucker's decoded HTTP bodies into the existing detection /
//! decision / redaction pipeline (`crate::proxy::process_payload`).
//!
//! No detection or redaction logic lives here — this only adapts body types so
//! the MITM path reuses the exact same pipeline as the reverse-proxy path.

use bytes::Bytes;
use http::HeaderMap;
use http_body_util::BodyExt;
use hudsucker::Body;

use crate::{
    app::{AppError, RuntimeState},
    auth::Principal,
    observability::Metrics,
    proxy::{ProcessedPayload, process_payload},
    types::Direction,
};

/// Collect a body to bytes and run it through the detection/redaction pipeline.
///
/// Returns `(raw, processed)` — the original collected bytes alongside the
/// [`ProcessedPayload`] (sanitized body + policy outcome). The raw bytes let the
/// caller preserve an upstream-signed body (signs_body hosts) when redaction
/// would otherwise modify it.
pub(crate) async fn filter_body(
    runtime: &RuntimeState,
    metrics: &Metrics,
    principal: &Principal,
    headers: &HeaderMap,
    body: Body,
    direction: Direction,
) -> Result<(Bytes, ProcessedPayload), AppError> {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let raw: Bytes = body
        .collect()
        .await
        .map_err(|e| AppError::RuntimeIo(std::io::Error::other(e)))?
        .to_bytes();
    let processed = process_payload(
        runtime,
        metrics,
        principal,
        &raw,
        content_type.as_deref(),
        direction,
    )
    .await?;
    Ok((raw, processed))
}
