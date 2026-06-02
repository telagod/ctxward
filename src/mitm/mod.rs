//! Transparent MITM proxy handler.
//!
//! Wires hudsucker's [`HttpHandler`] hooks into ctxward's detection/redaction
//! pipeline. Only hosts that the [`Classifier`] marks `Intercept` are
//! TLS-terminated and scanned; everything else is an opaque TCP tunnel (no cert
//! signed, no decryption).

pub mod bridge;
pub mod ca;
pub mod classify;
pub mod ruleset;

use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, decode_request, decode_response,
};
use parking_lot::RwLock;

use crate::{
    app::RuntimeState,
    auth::Principal,
    observability::Metrics,
    types::{Clearance, DecisionAction, Direction},
};

pub use classify::{Classifier, PinCache};

/// Hot-swappable classifier shared between the request handler and the rule-set
/// updater. A new (verified) rule-set replaces the inner `Arc<Classifier>` under
/// the write lock; the read path is a cheap `Arc` clone.
pub type SharedClassifier = Arc<RwLock<Arc<Classifier>>>;

/// A fixed local principal for the desktop proxy.
///
/// It carries no `allowed_labels` and the lowest clearance, so every detected
/// finding takes its rule's `unauthorized_action` (typically redact/tokenize) —
/// the privacy-maximizing default for a single-user machine. See
/// [`crate::policy::PolicyEngine::resolve`].
pub fn local_principal() -> Principal {
    Principal {
        name: "local".to_string(),
        tenant_id: "local".to_string(),
        role: "local".to_string(),
        clearance: Clearance::Public,
        allowed_labels: Default::default(),
    }
}

/// hudsucker HTTP handler that runs the ctxward pipeline on intercepted traffic.
#[derive(Clone)]
pub struct CtxwardHandler {
    runtime: Arc<RuntimeState>,
    metrics: Arc<Metrics>,
    principal: Principal,
    classifier: SharedClassifier,
    pins: Arc<PinCache>,
}

impl CtxwardHandler {
    pub fn new(
        runtime: Arc<RuntimeState>,
        metrics: Arc<Metrics>,
        principal: Principal,
        classifier: SharedClassifier,
        pins: Arc<PinCache>,
    ) -> Self {
        Self {
            runtime,
            metrics,
            principal,
            classifier,
            pins,
        }
    }

    /// Snapshot the current classifier (cheap `Arc` clone under a read lock).
    fn classifier(&self) -> Arc<Classifier> {
        self.classifier.read().clone()
    }
}

/// Extract the target host from a request: the URI authority (CONNECT) or the
/// `Host` header, lowercased, port stripped.
fn request_host(req_uri: &http::Uri, headers: &http::HeaderMap) -> String {
    req_uri
        .host()
        .map(|h| h.to_string())
        .or_else(|| {
            headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .unwrap_or_default()
}

impl HttpHandler for CtxwardHandler {
    async fn should_intercept(&mut self, ctx: &HttpContext, req: &Request<Body>) -> bool {
        // For a CONNECT request the URI authority is the target `host:port`.
        let host = request_host(req.uri(), req.headers());
        let peer = ctx.client_addr.ip().to_string();

        // A host whose client previously rejected our leaf cert is spliced (no MITM).
        if self.pins.is_pinned(&peer, &host) {
            tracing::debug!(%host, "host pinned, splicing (no intercept)");
            return false;
        }

        let intercept = matches!(
            self.classifier().classify(&host),
            crate::config::ProxyAction::Intercept
        );
        tracing::debug!(%host, intercept, "classify CONNECT");
        intercept
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // hudsucker's `decode_request` decompresses the body and strips the
        // now-stale Content-Encoding/Content-Length headers for us.
        let req = match decode_request(req) {
            Ok(req) => req,
            Err(err) => {
                tracing::warn!(%err, "failed to decode request body");
                return RequestOrResponse::Response(bad_gateway());
            }
        };
        let (mut parts, body) = req.into_parts();
        let request_id = uuid::Uuid::new_v4().to_string();
        let host = request_host(&parts.uri, &parts.headers);
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());

        let (raw, processed) = match bridge::filter_body(
            &self.runtime,
            &self.metrics,
            &self.principal,
            &parts.headers,
            body,
            Direction::Request,
        )
        .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(%err, "request pipeline error; failing closed");
                return RequestOrResponse::Response(bad_gateway());
            }
        };

        let blocked = processed.policy.decision == DecisionAction::Block;
        // Emit audit + metrics so the MITM path has the same observability as the
        // reverse-proxy path (lets the user verify redaction actually happened).
        crate::proxy::emit_decision_telemetry(
            &self.runtime,
            &self.metrics,
            &self.principal,
            Direction::Request,
            &request_id,
            &path,
            &processed.policy,
            blocked.then_some(StatusCode::FORBIDDEN.as_u16()),
        );

        if blocked {
            tracing::info!(source = %processed.policy.source, "request blocked by policy");
            return RequestOrResponse::Response(blocked_response());
        }

        // signs_body hosts (e.g. AWS SigV4): the upstream signed the *original*
        // body, so a redacted body would 4xx. Detection/audit already happened
        // above; forward the original bytes to keep the signature valid.
        let outbound = if self.classifier().signs_body(&host) && processed.sanitized_body != raw {
            tracing::warn!(%host, "signs_body host: forwarding original body (redaction skipped to preserve signature)");
            raw
        } else {
            processed.sanitized_body
        };

        // Body length changed by redaction; drop framing headers so hyper
        // recomputes them for the rebuilt (un-chunked, known-length) body.
        strip_framing_headers(&mut parts.headers);
        RequestOrResponse::Request(Request::from_parts(parts, Body::from(outbound)))
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let content_type = res
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        // D1: streaming (SSE) responses are passed through untouched. The core
        // privacy goal — scrubbing *outbound request* bodies — is unaffected
        // (requests are not streamed). Response-side per-event redaction via
        // `crate::proxy::transform_sse_line` is wired in D1.5.
        if is_sse(content_type.as_deref()) {
            return res;
        }

        let res = match decode_response(res) {
            Ok(res) => res,
            Err(err) => {
                tracing::warn!(%err, "failed to decode response body");
                return bad_gateway();
            }
        };
        let (mut parts, body) = res.into_parts();
        let status = parts.status.as_u16();

        let (_raw, processed) = match bridge::filter_body(
            &self.runtime,
            &self.metrics,
            &self.principal,
            &parts.headers,
            body,
            Direction::Response,
        )
        .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(%err, "response pipeline error; failing closed");
                return bad_gateway();
            }
        };

        crate::proxy::emit_decision_telemetry(
            &self.runtime,
            &self.metrics,
            &self.principal,
            Direction::Response,
            // hudsucker hooks the response separately from the request, so we
            // have no correlated request id / path here (D1.5 can thread one).
            "",
            "",
            &processed.policy,
            Some(status),
        );

        strip_framing_headers(&mut parts.headers);
        Response::from_parts(parts, Body::from(processed.sanitized_body))
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        // NOTE: hudsucker surfaces *upstream forward* failures here, not the
        // client rejecting our leaf cert (that handshake failure is internal to
        // the TLS accept layer and is not exposed by the handler trait in 0.24).
        // Automatic pin-marking from a client TLS reject is therefore deferred;
        // the `PinCache` gate in `should_intercept` is still honoured.
        tracing::warn!(error = %err, "upstream forward failed");
        bad_gateway()
    }
}

fn is_sse(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| ct.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false)
}

/// Drop length/transfer-framing headers after the body was rewritten, so the
/// re-forwarded message is framed correctly by hyper for the new body. (We
/// always hand hyper a known-length `Full` body, never a chunked stream.)
fn strip_framing_headers(headers: &mut http::HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

fn bad_gateway() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from("ctxward: upstream error"))
        .expect("static response builds")
}

fn blocked_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"error":{"type":"blocked_by_ctxward","message":"request blocked by privacy policy"}}"#,
        ))
        .expect("static response builds")
}
