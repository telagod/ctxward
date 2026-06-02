//! Streaming SSE redaction for the MITM response path.
//!
//! Wraps the upstream `text/event-stream` body in a stream that buffers across
//! chunk boundaries, splits on `\n`, scrubs each event line through the existing
//! [`crate::proxy::transform_sse_line`] pipeline, and meters token usage from
//! the trailing `usage` event. Audit + metrics are emitted once the stream ends.

use std::sync::Arc;

use async_stream::stream;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyStream;
use hudsucker::Body;

use crate::{
    app::RuntimeState,
    auth::Principal,
    mitm::usage,
    observability::Metrics,
    policy::PolicyOutcome,
    proxy::{merge_policy_outcomes, transform_sse_line},
    types::{DecisionAction, Direction},
};

fn allow_policy() -> PolicyOutcome {
    PolicyOutcome {
        decision: DecisionAction::Allow,
        findings: Vec::new(),
        source: "builtin".to_string(),
        reason: None,
    }
}

/// Meter token usage from a single SSE `data:` line, if it carries a `usage`
/// object (OpenAI emits one trailing usage event when `stream_options
/// .include_usage` is set). `metered` guards against double-counting.
fn meter_sse_usage(metrics: &Metrics, line: &str, metered: &mut bool) {
    if *metered || !line.starts_with("data:") {
        return;
    }
    let payload = line.trim_start_matches("data:").trim();
    if payload.is_empty() || payload == "[DONE]" {
        return;
    }
    if let Some(u) = usage::usage_from_response(payload.as_bytes()) {
        metrics.llm_tokens(
            u.model.as_deref().unwrap_or("unknown"),
            u.prompt_tokens,
            u.completion_tokens,
        );
        *metered = true;
    }
}

/// Build a redacting SSE body: per-event scrub via `transform_sse_line`, token
/// metering, and end-of-stream audit/metrics telemetry.
pub(crate) fn redact_sse_stream(
    runtime: Arc<RuntimeState>,
    metrics: Arc<Metrics>,
    principal: Principal,
    body: Body,
) -> Body {
    let out = stream! {
        let mut frames = BodyStream::new(body);
        let mut buffer: Vec<u8> = Vec::new();
        let mut acc_policy = allow_policy();
        let mut metered = false;

        while let Some(frame) = frames.next().await {
            let data = match frame {
                Ok(frame) => match frame.into_data() {
                    Ok(data) => data,
                    Err(_) => continue, // trailers frame: nothing to scrub
                },
                Err(err) => {
                    tracing::warn!(%err, "failed to read upstream SSE chunk");
                    break;
                }
            };
            buffer.extend_from_slice(&data);
            while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buffer.drain(..=pos).collect();
                let line_str = String::from_utf8_lossy(&line);
                meter_sse_usage(&metrics, &line_str, &mut metered);
                let transformed =
                    transform_sse_line(&runtime, &principal, "/sse", false, &line_str).await;
                acc_policy = merge_policy_outcomes(acc_policy, transformed.policy);
                yield Ok::<Bytes, hudsucker::Error>(Bytes::from(transformed.line));
            }
        }

        // Flush any trailing partial line (no terminating newline).
        if !buffer.is_empty() {
            let line_str = String::from_utf8_lossy(&buffer);
            meter_sse_usage(&metrics, &line_str, &mut metered);
            let transformed =
                transform_sse_line(&runtime, &principal, "/sse", false, &line_str).await;
            acc_policy = merge_policy_outcomes(acc_policy, transformed.policy);
            yield Ok::<Bytes, hudsucker::Error>(Bytes::from(transformed.line));
        }

        crate::proxy::emit_decision_telemetry(
            &runtime,
            &metrics,
            &principal,
            Direction::Response,
            "",
            "/sse",
            &acc_policy,
            None,
        );
    };

    Body::from_stream(out)
}
