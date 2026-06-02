use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_stream::stream;
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Query, Request, State},
    http::{
        HeaderMap, Response, StatusCode,
        header::{CONTENT_TYPE, HeaderName, HeaderValue},
    },
    response::IntoResponse,
};
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::{
    app::{AppError, AppState, RuntimeState},
    attachments::{AttachmentScanDeps, is_multipart_form},
    audit::{AuditFinding, AuditRecord, AuditSource, read_recent_audit_file},
    auth::Principal,
    observability::Metrics,
    opa::OpaInput,
    policy::{PolicyOutcome, ResolvedFinding},
    redact::redact_text,
    review::{NewReviewTicket, ReviewDecisionOverride, ReviewFilterStatus, ReviewStatus},
    types::{DecisionAction, Direction},
};

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];
const BODY_SIZE_HEADERS: &[&str] = &["content-length"];
const REVIEW_TICKET_HEADER: &str = "x-review-ticket-id";

struct RequestContext {
    state: Arc<AppState>,
    runtime: Arc<RuntimeState>,
    metrics: Arc<Metrics>,
    principal: Principal,
    request_id: String,
    path_and_query: String,
}

#[derive(Clone)]
struct AuditContext {
    request_id: String,
    path_and_query: String,
    session_id: Option<String>,
    session_escalated: bool,
}

#[derive(Clone)]
struct ResponseContext {
    runtime: Arc<RuntimeState>,
    metrics: Arc<Metrics>,
    principal: Principal,
    audit: AuditContext,
}

struct UpstreamResponseMeta {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    content_type: Option<String>,
}

pub async fn admin_reload(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> impl IntoResponse {
    match authenticate_request(&state, request.headers()) {
        Ok(principal) if principal.role == "admin" => match state.reload() {
            Ok(_) => {
                let runtime = state.current();
                Json(json!({
                    "status": "reloaded",
                    "config_path": state.config_path,
                    "upstream": runtime.upstream_base_url.as_str(),
                }))
                .into_response()
            }
            Err(err) => gateway_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "reload_failed",
                &err.to_string(),
                None,
            ),
        },
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

pub async fn admin_benchmarks_promote(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> impl IntoResponse {
    match authenticate_request(&state, request.headers()) {
        Ok(principal) if principal.role == "admin" => match state.promote_benchmark_baseline() {
            Ok(promotion) => Json(json!({
                "status": "baseline_promoted",
                "summary_path": promotion.summary_path,
                "baseline_path": promotion.baseline_path,
            }))
            .into_response(),
            Err(err) => gateway_error(
                StatusCode::FAILED_DEPENDENCY,
                "benchmark_promote_failed",
                &err.to_string(),
                None,
            ),
        },
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
    pub source: Option<String>,
    pub principal: Option<String>,
    pub decision: Option<String>,
    pub label: Option<String>,
    pub direction: Option<String>,
    pub session_id: Option<String>,
    pub policy_source: Option<String>,
    pub request_id: Option<String>,
    pub error_stage: Option<String>,
    pub error_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DetokenizeRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ReviewQuery {
    pub limit: Option<usize>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveReviewRequest {
    pub id: String,
    pub approve: bool,
    pub note: Option<String>,
}

pub async fn admin_status(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> impl IntoResponse {
    match authenticate_request(&state, request.headers()) {
        Ok(principal) if principal.role == "admin" => {
            let runtime = state.current();
            let benchmark_surface = state.benchmark_surface();
            let sessions = state.sessions.active_sessions(&runtime.config.session);
            let pending_reviews = state.reviews.pending_count();
            let opa_status = dependency_status_opa(runtime.opa.as_ref()).await;
            let presidio_status = dependency_status_presidio(runtime.presidio.as_ref()).await;
            state.metrics.update_sessions(sessions);
            state
                .metrics
                .update_review_queue(pending_reviews, runtime.config.review.capacity);
            state.metrics.update_dependency(
                "opa",
                opa_status
                    .get("configured")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                opa_status
                    .get("reachable")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                opa_status
                    .get("status_code")
                    .and_then(|value| value.as_i64()),
            );
            state.metrics.update_dependency(
                "presidio",
                presidio_status
                    .get("configured")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                presidio_status
                    .get("reachable")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                presidio_status
                    .get("status_code")
                    .and_then(|value| value.as_i64()),
            );
            Json(json!({
                "status": "ok",
                "config_path": state.config_path,
                "upstream": runtime.upstream_base_url.as_str(),
                "features": {
                    "opa": runtime.opa.is_some(),
                    "presidio": runtime.presidio.is_some(),
                    "tokenization": runtime.tokenizer.is_some(),
                    "attachment_scanning": runtime.attachments.enabled(),
                    "response_filtering": runtime.config.response_filtering.enabled,
                    "session_correlation": runtime.config.session.enabled,
                },
                "audit_buffer": {
                    "len": state.audit_store.len(),
                    "capacity": state.audit_store.capacity(),
                },
                "review_queue": {
                    "pending": pending_reviews,
                    "capacity": runtime.config.review.capacity,
                    "approval_ttl_secs": runtime.config.review.approval_ttl_secs,
                },
                "sessions": sessions,
                "dependencies": {
                    "opa": opa_status,
                    "presidio": presidio_status,
                },
                "observability": {
                    "metrics_path": "/metrics",
                    "benchmarks": benchmark_surface,
                    "runtime_summary": {
                        "sessions_active": sessions,
                        "review_queue_pending": pending_reviews,
                        "review_queue_capacity": runtime.config.review.capacity,
                        "dependency_ready": {
                            "opa": opa_status
                                .get("reachable")
                                .and_then(|value| value.as_bool())
                                .unwrap_or(false),
                            "presidio": presidio_status
                                .get("reachable")
                                .and_then(|value| value.as_bool())
                                .unwrap_or(false),
                        }
                    },
                    "metrics_summary": state.metrics.snapshot(),
                }
            }))
            .into_response()
        }
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

pub async fn admin_config_summary(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> impl IntoResponse {
    match authenticate_request(&state, request.headers()) {
        Ok(principal) if principal.role == "admin" => {
            let runtime = state.current();
            Json(build_admin_config_summary(&state, &runtime)).into_response()
        }
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

pub async fn admin_detokenize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DetokenizeRequest>,
) -> impl IntoResponse {
    match authenticate_request(&state, &headers) {
        Ok(principal) if principal.role == "admin" => {
            let runtime = state.current();
            let Some(tokenizer) = runtime.tokenizer.as_ref() else {
                return gateway_error(
                    StatusCode::FAILED_DEPENDENCY,
                    "tokenization_disabled",
                    "tokenization is not enabled in the current runtime",
                    None,
                );
            };
            match tokenizer.detokenize(&payload.token) {
                Ok(decoded) => Json(json!({
                    "status": "ok",
                    "label": decoded.label,
                    "value": decoded.value,
                    "token_prefix": tokenizer.token_prefix(),
                    "key_env": tokenizer.key_env(),
                }))
                .into_response(),
                Err(err) => gateway_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_token",
                    &err.to_string(),
                    None,
                ),
            }
        }
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

pub async fn admin_reviews(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ReviewQuery>,
    request: Request,
) -> impl IntoResponse {
    match authenticate_request(&state, request.headers()) {
        Ok(principal) if principal.role == "admin" => {
            let limit = query.limit.unwrap_or(50).min(500);
            let status = parse_review_status(query.status.as_deref());
            let tickets = state.reviews.list(status, limit);
            Json(json!({
                "status": match status {
                    ReviewFilterStatus::Pending => "pending",
                    ReviewFilterStatus::Approved => "approved",
                    ReviewFilterStatus::Rejected => "rejected",
                    ReviewFilterStatus::All => "all",
                },
                "count": tickets.len(),
                "records": tickets,
            }))
            .into_response()
        }
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

pub async fn admin_reviews_resolve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ResolveReviewRequest>,
) -> impl IntoResponse {
    match authenticate_request(&state, &headers) {
        Ok(principal) if principal.role == "admin" => {
            let status = if payload.approve {
                ReviewStatus::Approved
            } else {
                ReviewStatus::Rejected
            };
            match state.reviews.resolve(
                &payload.id,
                status,
                principal.name.clone(),
                payload.note.clone(),
                state.current().config.review.approval_ttl_secs,
            ) {
                Ok(ticket) => {
                    state.metrics.review_event(match status {
                        ReviewStatus::Approved => "approved",
                        ReviewStatus::Rejected => "rejected",
                        ReviewStatus::Pending => "pending",
                    });
                    state.metrics.update_review_queue(
                        state.reviews.pending_count(),
                        state.current().config.review.capacity,
                    );
                    Json(json!({
                        "status": "ok",
                        "record": ticket,
                    }))
                    .into_response()
                }
                Err(err) => gateway_error(
                    StatusCode::NOT_FOUND,
                    "review_resolve_failed",
                    &err.to_string(),
                    None,
                ),
            }
        }
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

pub async fn admin_audits(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditQuery>,
    request: Request,
) -> impl IntoResponse {
    match authenticate_request(&state, request.headers()) {
        Ok(principal) if principal.role == "admin" => {
            let limit = query.limit.unwrap_or(50).min(500);
            let source = parse_audit_source(query.source.as_deref());
            let records = match source {
                AuditSource::Memory => {
                    let mut records = state.audit_store.snapshot();
                    records.reverse();
                    records
                }
                AuditSource::File => read_recent_audit_file(state.current().audit.path(), limit)
                    .unwrap_or_default()
                    .into_iter()
                    .rev()
                    .collect(),
                AuditSource::Both => {
                    let mut memory = state.audit_store.snapshot();
                    let mut file = read_recent_audit_file(state.current().audit.path(), limit)
                        .unwrap_or_default();
                    memory.append(&mut file);
                    memory.sort_by_key(|record| std::cmp::Reverse(record.ts));
                    let mut seen = HashSet::new();
                    memory.retain(|record| seen.insert(record.clone()));
                    memory
                }
            };
            let filtered = records
                .into_iter()
                .filter(|record| match &query.principal {
                    Some(expected) => &record.principal == expected,
                    None => true,
                })
                .filter(|record| match &query.decision {
                    Some(expected) => &record.decision == expected,
                    None => true,
                })
                .filter(|record| match &query.policy_source {
                    Some(expected) => &record.policy_source == expected,
                    None => true,
                })
                .filter(|record| match &query.direction {
                    Some(expected) => &record.direction == expected,
                    None => true,
                })
                .filter(|record| match &query.request_id {
                    Some(expected) => &record.request_id == expected,
                    None => true,
                })
                .filter(|record| match &query.session_id {
                    Some(expected) => record.session_id.as_ref() == Some(expected),
                    None => true,
                })
                .filter(|record| match &query.label {
                    Some(expected) => record.matched_labels.iter().any(|label| label == expected),
                    None => true,
                })
                .filter(|record| match &query.error_stage {
                    Some(expected) => record.error_stage.as_ref() == Some(expected),
                    None => true,
                })
                .filter(|record| match &query.error_kind {
                    Some(expected) => record.error_kind.as_ref() == Some(expected),
                    None => true,
                })
                .take(limit)
                .collect::<Vec<_>>();

            Json(json!({
                "source": match source { AuditSource::Memory => "memory", AuditSource::File => "file", AuditSource::Both => "both" },
                "count": filtered.len(),
                "records": filtered,
            }))
            .into_response()
        }
        Ok(_) => gateway_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin role required",
            None,
        ),
        Err(err) => gateway_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &err.to_string(),
            None,
        ),
    }
}

fn parse_audit_source(raw: Option<&str>) -> AuditSource {
    match raw.unwrap_or("memory") {
        "file" => AuditSource::File,
        "both" => AuditSource::Both,
        _ => AuditSource::Memory,
    }
}

fn build_admin_config_summary(state: &Arc<AppState>, runtime: &Arc<RuntimeState>) -> Value {
    let config = &runtime.config;
    let upstream_auth_env_present = config
        .upstream
        .auth_value_env
        .as_ref()
        .map(|name| std::env::var_os(name).is_some())
        .unwrap_or(false);
    let tokenization_key_env_present = config
        .tokenization
        .as_ref()
        .map(|cfg| std::env::var_os(&cfg.key_env).is_some())
        .unwrap_or(false);
    let principals = config
        .auth
        .principals
        .iter()
        .map(|principal| {
            json!({
                "name": principal.name,
                "tenant_id": principal.tenant_id,
                "role": principal.role,
                "clearance": principal.clearance,
                "allowed_labels": sorted_strings(principal.allowed_labels.iter().cloned().collect()),
            })
        })
        .collect::<Vec<_>>();

    let rules = config
        .detection
        .rules
        .iter()
        .map(|rule| {
            json!({
                "name": rule.name,
                "label": rule.label,
                "severity": rule.severity,
                "authorized_action": rule.authorized_action,
                "unauthorized_action": rule.unauthorized_action,
                "min_clearance": rule.min_clearance,
                "masking": rule.masking,
                "pattern_preview": truncate_middle(&rule.pattern, 96),
            })
        })
        .collect::<Vec<_>>();

    let presidio_entities = config
        .detection
        .presidio
        .as_ref()
        .map(|presidio| {
            presidio
                .entities
                .iter()
                .map(|entity| {
                    json!({
                        "entity_type": entity.entity_type,
                        "label": entity.label,
                        "severity": entity.severity,
                        "authorized_action": entity.authorized_action,
                        "unauthorized_action": entity.unauthorized_action,
                        "min_clearance": entity.min_clearance,
                        "masking": entity.masking,
                        "min_score": entity.min_score,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let uses_tokenization = config
        .detection
        .rules
        .iter()
        .any(|rule| rule.masking == crate::types::MaskingStrategy::Tokenize)
        || config
            .detection
            .high_entropy
            .as_ref()
            .map(|rule| rule.masking == crate::types::MaskingStrategy::Tokenize)
            .unwrap_or(false)
        || config
            .detection
            .presidio
            .as_ref()
            .map(|presidio| {
                presidio
                    .entities
                    .iter()
                    .any(|entity| entity.masking == crate::types::MaskingStrategy::Tokenize)
            })
            .unwrap_or(false);

    json!({
        "status": "ok",
        "config_path": state.config_path,
        "runtime": {
            "bind": config.server.bind,
            "request_body_limit_bytes": config.server.request_body_limit_bytes,
            "upstream_base_url": runtime.upstream_base_url.as_str(),
            "upstream_forward_headers": sorted_strings(config.upstream.forward_headers.iter().cloned().collect()),
            "upstream_auth_header": config.upstream.auth_header,
            "upstream_auth_env_configured": config.upstream.auth_value_env.is_some(),
            "upstream_auth_env_present": upstream_auth_env_present,
        },
        "auth": {
            "header_name": config.auth.header_name,
            "principal_count": config.auth.principals.len(),
            "principals": principals,
        },
        "detection": {
            "ignore_json_pointers": sorted_strings(config.detection.ignore_json_pointers.iter().cloned().collect()),
            "regex_rule_count": rules.len(),
            "rules": rules,
            "high_entropy": config.detection.high_entropy.as_ref().map(|rule| json!({
                "enabled": rule.enabled,
                "min_length": rule.min_length,
                "min_entropy": rule.min_entropy,
                "label": rule.label,
                "severity": rule.severity,
                "authorized_action": rule.authorized_action,
                "unauthorized_action": rule.unauthorized_action,
                "min_clearance": rule.min_clearance,
                "masking": rule.masking,
            })),
            "presidio": config.detection.presidio.as_ref().map(|presidio| json!({
                "enabled": presidio.enabled,
                "analyzer_url": presidio.analyzer_url,
                "healthcheck_url": presidio.healthcheck_url,
                "timeout_ms": presidio.timeout_ms,
                "language": presidio.language,
                "entity_count": presidio.entities.len(),
                "entities": presidio_entities,
            })),
        },
        "tokenization": {
            "enabled": runtime.tokenizer.is_some(),
            "configured": config.tokenization.as_ref().map(|cfg| cfg.enabled).unwrap_or(false),
            "required_by_rules": uses_tokenization,
            "key_env": config.tokenization.as_ref().map(|cfg| cfg.key_env.clone()),
            "key_env_present": tokenization_key_env_present,
            "token_prefix": config.tokenization.as_ref().map(|cfg| cfg.token_prefix.clone()),
        },
        "session": {
            "enabled": config.session.enabled,
            "header_name": config.session.header_name,
            "ttl_secs": config.session.ttl_secs,
            "max_entries": config.session.max_entries,
            "correlation_threshold": config.session.correlation_threshold,
            "trigger_action": config.session.trigger_action,
        },
        "response_filtering": {
            "enabled": config.response_filtering.enabled,
            "scan_json": config.response_filtering.scan_json,
            "scan_sse": config.response_filtering.scan_sse,
        },
        "attachments": {
            "enabled": config.attachments.enabled,
            "max_bytes": config.attachments.max_bytes,
            "max_text_chars": config.attachments.max_text_chars,
            "allowed_media_types": config.attachments.allowed_media_types,
        },
        "review": {
            "capacity": config.review.capacity,
            "preview_chars": config.review.preview_chars,
            "approval_ttl_secs": config.review.approval_ttl_secs,
            "jsonl_path": config.review.jsonl_path,
        },
        "benchmarks": {
            "enabled": config.benchmarks.enabled,
            "summary_json_path": config.benchmarks.summary_json_path,
            "baseline_summary_json_path": config.benchmarks.baseline_summary_json_path,
            "gate_report_json_path": config.benchmarks.gate_report_json_path,
        },
        "audit": {
            "jsonl_path": config.audit.jsonl_path,
            "emit_stdout": config.audit.emit_stdout,
            "buffer_capacity": config.audit.buffer_capacity,
        },
        "policy_backend": {
            "opa": config.policy_backend.opa.as_ref().map(|opa| json!({
                "enabled": opa.enabled,
                "runtime_loaded": runtime.opa.is_some(),
                "url": opa.url,
                "healthcheck_url": opa.healthcheck_url,
                "timeout_ms": opa.timeout_ms,
                "fail_open": opa.fail_open,
            })),
        },
    })
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return value.to_string();
    }
    let head_len = max_chars.saturating_sub(3) / 2;
    let tail_len = max_chars.saturating_sub(3 + head_len);
    let head = chars[..head_len].iter().collect::<String>();
    let tail = chars[chars.len().saturating_sub(tail_len)..]
        .iter()
        .collect::<String>();
    format!("{head}...{tail}")
}

fn parse_review_status(raw: Option<&str>) -> ReviewFilterStatus {
    match raw.unwrap_or("pending") {
        "approved" => ReviewFilterStatus::Approved,
        "rejected" => ReviewFilterStatus::Rejected,
        "all" => ReviewFilterStatus::All,
        _ => ReviewFilterStatus::Pending,
    }
}

pub async fn dependency_status_opa(opa: Option<&crate::opa::OpaAuthorizer>) -> Value {
    let Some(opa) = opa else {
        return json!({
            "configured": false,
            "reachable": false,
        });
    };
    match opa.healthcheck().await {
        Ok(status) => json!({
            "configured": true,
            "reachable": (200..500).contains(&status),
            "status_code": status,
            "timeout_ms": opa.timeout_ms(),
            "url": opa.url(),
            "fail_open": opa.fail_open(),
        }),
        Err(err) => json!({
            "configured": true,
            "reachable": false,
            "timeout_ms": opa.timeout_ms(),
            "url": opa.url(),
            "fail_open": opa.fail_open(),
            "error": err.to_string(),
        }),
    }
}

pub async fn dependency_status_presidio(
    presidio: Option<&crate::presidio::PresidioAnalyzer>,
) -> Value {
    let Some(presidio) = presidio else {
        return json!({
            "configured": false,
            "reachable": false,
        });
    };
    match presidio.healthcheck().await {
        Ok(status) => json!({
            "configured": true,
            "reachable": (200..500).contains(&status),
            "status_code": status,
            "timeout_ms": presidio.timeout_ms(),
            "url": presidio.analyzer_url(),
        }),
        Err(err) => json!({
            "configured": true,
            "reachable": false,
            "timeout_ms": presidio.timeout_ms(),
            "url": presidio.analyzer_url(),
            "error": err.to_string(),
        }),
    }
}

pub async fn proxy_handler(State(state): State<Arc<AppState>>, request: Request) -> Response<Body> {
    let request_id = Uuid::new_v4().to_string();
    let runtime = state.current();
    let metrics = state.metrics.clone();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let session_header_name = state.current().config.session.header_name.clone();
    let session_id = request
        .headers()
        .get(&session_header_name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let principal = match authenticate_request(&state, request.headers()) {
        Ok(principal) => principal,
        Err(err) => {
            metrics.auth_failure("invalid_credentials");
            return gateway_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                &err.to_string(),
                Some(&request_id),
            );
        }
    };

    let context = RequestContext {
        state: state.clone(),
        runtime,
        metrics: metrics.clone(),
        principal: principal.clone(),
        path_and_query: path_and_query.clone(),
        request_id: request_id.clone(),
    };

    match handle_proxy(context, method, request).await {
        Ok(response) => response,
        Err(err) => {
            let error_kind = proxy_error_kind(&err);
            metrics.proxy_error("request_pre_upstream", error_kind);
            if should_emit_request_pre_upstream_error_audit(&err) {
                emit_request_pre_upstream_error_audit(
                    &state.current(),
                    RequestPreUpstreamErrorAudit {
                        principal: &principal,
                        request_id: &request_id,
                        path_and_query: &path_and_query,
                        session_id: session_id.clone(),
                        stage: "request_pre_upstream",
                        kind: error_kind,
                        err: &err,
                    },
                );
            }
            error!(error = %err, "proxy request failed");
            gateway_error(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                &err.to_string(),
                Some(&request_id),
            )
        }
    }
}

async fn handle_proxy(
    context: RequestContext,
    method: axum::http::Method,
    request: Request,
) -> Result<Response<Body>, AppError> {
    let RequestContext {
        state,
        runtime,
        metrics,
        principal,
        request_id,
        path_and_query,
    } = context;
    let headers = request.headers().clone();
    let session_id = runtime
        .config
        .session
        .enabled
        .then(|| {
            headers
                .get(&runtime.config.session.header_name)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .flatten();
    let limit = runtime.config.server.request_body_limit_bytes;
    let body = to_bytes(request.into_body(), limit).await.map_err(|err| {
        AppError::RuntimeIo(std::io::Error::other(format!(
            "failed reading request body: {err}"
        )))
    })?;

    let review_ticket_header = headers
        .get(REVIEW_TICKET_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let request_processing = process_payload(
        &runtime,
        &metrics,
        &principal,
        &body,
        headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Direction::Request,
    )
    .await?;
    let request_sha256 = sha256_hex_bytes(&body);

    let session_escalated = if let Some(session_id) = &session_id {
        let labels = request_processing
            .policy
            .findings
            .iter()
            .map(|finding| finding.label.clone())
            .collect::<Vec<_>>();
        state
            .sessions
            .record_and_check(session_id, labels, &runtime.config.session)
    } else {
        false
    };
    metrics.update_sessions(state.sessions.active_sessions(&runtime.config.session));
    metrics.update_review_queue(
        state.reviews.pending_count(),
        runtime.config.review.capacity,
    );
    let audit_context = AuditContext {
        request_id: request_id.clone(),
        path_and_query: path_and_query.clone(),
        session_id: session_id.clone(),
        session_escalated,
    };

    let request_decision = if session_escalated {
        request_processing
            .policy
            .decision
            .combine(runtime.config.session.trigger_action)
    } else {
        request_processing.policy.decision
    };
    let post_review_action = if request_processing.policy.decision == DecisionAction::Redact {
        DecisionAction::Redact
    } else {
        DecisionAction::Allow
    };
    let mut request_policy = request_processing.policy;
    request_policy.decision = request_decision;
    request_policy = apply_opa_policy(
        &runtime,
        &principal,
        Direction::Request,
        &path_and_query,
        session_escalated,
        request_policy,
    )
    .await?;
    let review_fingerprint = review_fingerprint(&principal, &path_and_query, &request_sha256);
    if let Some(ticket) = review_ticket_header
        .as_deref()
        .and_then(|ticket_id| state.reviews.get(ticket_id))
        .filter(|ticket| {
            ticket.status != ReviewStatus::Pending
                && ticket.principal == principal.name
                && ticket.path == path_and_query
                && ticket.request_sha256 == request_sha256
        })
    {
        match ticket.status {
            ReviewStatus::Approved => {
                request_policy.decision = ticket.post_approval_action;
                request_policy.source = "review_override_approved".to_string();
                request_policy.reason =
                    Some(format!("request approved via review ticket {}", ticket.id));
            }
            ReviewStatus::Rejected => {
                request_policy.decision = DecisionAction::Block;
                request_policy.source = "review_override_rejected".to_string();
                request_policy.reason =
                    Some(format!("request rejected via review ticket {}", ticket.id));
            }
            ReviewStatus::Pending => {}
        }
    } else if let Some(override_decision) = state.reviews.lookup_override(&review_fingerprint) {
        match override_decision {
            ReviewDecisionOverride::Approved { action, .. } => {
                request_policy.decision = action;
                request_policy.source = "review_override_approved".to_string();
                request_policy.reason =
                    Some("request previously approved by admin review".to_string());
            }
            ReviewDecisionOverride::Rejected { .. } => {
                request_policy.decision = DecisionAction::Block;
                request_policy.source = "review_override_rejected".to_string();
                request_policy.reason =
                    Some("request previously rejected by admin review".to_string());
            }
        }
    }

    emit_metrics_for_findings(&metrics, Direction::Request, &request_policy.findings);

    if matches!(
        request_policy.decision,
        DecisionAction::Block | DecisionAction::Review
    ) {
        let mut review_ticket_id = None::<String>;
        let mut review_post_approval_action = None::<DecisionAction>;
        if request_policy.decision == DecisionAction::Review {
            let preview = preview_text(
                std::str::from_utf8(&request_processing.sanitized_body)
                    .unwrap_or("[binary request body]"),
                runtime.config.review.preview_chars,
            );
            let ticket = state.reviews.upsert_pending(NewReviewTicket {
                request_id: request_id.clone(),
                principal: principal.name.clone(),
                tenant_id: principal.tenant_id.clone(),
                direction: "request".to_string(),
                path: path_and_query.clone(),
                policy_source: request_policy.source.clone(),
                decision_reason: request_policy.reason.clone(),
                matched_labels: request_policy
                    .findings
                    .iter()
                    .map(|finding| finding.label.clone())
                    .collect(),
                matched_rules: request_policy
                    .findings
                    .iter()
                    .map(|finding| finding.rule_name.clone())
                    .collect(),
                findings: request_policy
                    .findings
                    .iter()
                    .map(|finding| AuditFinding {
                        label: finding.label.clone(),
                        rule_name: finding.rule_name.clone(),
                        action: action_name(finding.action).to_string(),
                        pointer: finding.pointer.clone(),
                        severity: format!("{:?}", finding.severity).to_lowercase(),
                        matched_sha256: finding.matched_sha256.clone(),
                        matched_len: finding.matched_len,
                    })
                    .collect(),
                session_id: session_id.clone(),
                session_escalated,
                request_sha256: request_sha256.clone(),
                sanitized_preview: Some(preview),
                post_approval_action: post_review_action,
                fingerprint: review_fingerprint.clone(),
            })?;
            metrics.review_event("created");
            metrics.update_review_queue(
                state.reviews.pending_count(),
                runtime.config.review.capacity,
            );
            review_ticket_id = Some(ticket.id.clone());
            review_post_approval_action = Some(post_review_action);
            request_policy.reason = Some(format!(
                "{}; review_ticket_id={}",
                request_policy
                    .reason
                    .clone()
                    .unwrap_or_else(|| "admin approval required".to_string()),
                ticket.id
            ));
        }
        runtime.audit.emit(build_audit_record(
            &principal,
            Direction::Request,
            request_policy.decision,
            &request_policy,
            &audit_context,
            Some(decision_status(request_policy.decision).as_u16()),
        ));
        emit_processing_fallback_metric(&metrics, &request_policy.source);
        emit_review_override_metric(&metrics, &request_policy.source);
        metrics.policy_decision(
            "request",
            action_name(request_policy.decision),
            &request_policy.source,
        );
        return Ok(if request_policy.decision == DecisionAction::Review {
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": {
                        "code": action_code(request_policy.decision),
                        "message": "request requires admin approval before forwarding upstream",
                    },
                    "request_id": request_id,
                    "review": {
                        "ticket_id": review_ticket_id.unwrap_or_default(),
                        "post_approval_action": action_name(
                            review_post_approval_action.unwrap_or(DecisionAction::Allow)
                        ),
                    }
                })),
            )
                .into_response()
        } else {
            gateway_error(
                decision_status(request_policy.decision),
                action_code(request_policy.decision),
                "request contains sensitive data not permitted by policy",
                Some(&request_id),
            )
        });
    }

    let outbound_body = match request_policy.decision {
        DecisionAction::Redact => request_processing.sanitized_body.clone(),
        _ => body.clone(),
    };

    runtime.audit.emit(build_audit_record(
        &principal,
        Direction::Request,
        request_policy.decision,
        &request_policy,
        &audit_context,
        None,
    ));
    emit_processing_fallback_metric(&metrics, &request_policy.source);
    emit_review_override_metric(&metrics, &request_policy.source);
    metrics.policy_decision(
        "request",
        action_name(request_policy.decision),
        &request_policy.source,
    );

    let upstream_url = runtime
        .upstream_base_url
        .join(path_and_query.trim_start_matches('/'))
        .map_err(|_| AppError::InvalidUpstreamUrl(path_and_query.clone()))?;

    let upstream_method = Method::from_bytes(method.as_str().as_bytes()).map_err(|err| {
        AppError::RuntimeIo(std::io::Error::other(format!(
            "invalid method for reqwest: {err}"
        )))
    })?;
    let mut upstream_request = runtime.client.request(upstream_method, upstream_url);
    upstream_request = attach_forward_headers(
        upstream_request,
        &headers,
        &runtime.config.upstream.forward_headers,
        &request_id,
    );
    if let (Some(header_name), Some(env_name)) = (
        runtime.config.upstream.auth_header.as_ref(),
        runtime.config.upstream.auth_value_env.as_ref(),
    ) && let Ok(secret) = std::env::var(env_name)
    {
        upstream_request = upstream_request.header(header_name, secret);
    }
    let timer = metrics.upstream_timer(&path_and_query);
    let upstream_response = upstream_request
        .body(outbound_body)
        .send()
        .await
        .map_err(|err| {
            AppError::RuntimeIo(std::io::Error::other(format!(
                "upstream request failed: {err}"
            )))
        })?;
    timer.observe_duration();

    let content_type = upstream_response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let response_meta = UpstreamResponseMeta {
        status: upstream_response.status(),
        headers: upstream_response.headers().clone(),
        content_type,
    };
    let response_context = ResponseContext {
        runtime,
        metrics,
        principal,
        audit: audit_context,
    };

    let response = if is_sse(response_meta.content_type.as_deref())
        && response_context.runtime.config.response_filtering.scan_sse
    {
        response_from_sse_stream(response_context, upstream_response, response_meta).await
    } else {
        response_from_buffered_body(response_context, upstream_response, response_meta).await
    };

    Ok(response)
}

async fn response_from_buffered_body(
    context: ResponseContext,
    upstream_response: reqwest::Response,
    response_meta: UpstreamResponseMeta,
) -> Response<Body> {
    let body = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            return gateway_error(
                StatusCode::BAD_GATEWAY,
                "upstream_read_failed",
                &err.to_string(),
                Some(&context.audit.request_id),
            );
        }
    };

    let processed = if context.runtime.config.response_filtering.enabled {
        process_payload(
            &context.runtime,
            &context.metrics,
            &context.principal,
            &body,
            response_meta.content_type.as_deref(),
            Direction::Response,
        )
        .await
        .unwrap_or_else(ProcessedPayload::error_fallback)
    } else {
        ProcessedPayload::passthrough(body.clone())
    };
    let base_policy = processed.policy.clone();
    let base_source = base_policy.source.clone();
    emit_processing_fallback_metric(&context.metrics, &base_source);
    let final_policy = finalize_response_policy(
        &context.runtime,
        &context.principal,
        &context.audit.path_and_query,
        context.audit.session_escalated,
        base_policy,
    )
    .await;

    emit_metrics_for_findings(
        &context.metrics,
        Direction::Response,
        &final_policy.findings,
    );
    let (body_out, response_decision) = resolve_buffered_response_body(
        response_meta.content_type.as_deref(),
        &body,
        processed.sanitized_body,
        processed.policy.decision,
        final_policy.decision,
    );

    context.runtime.audit.emit(build_audit_record(
        &context.principal,
        Direction::Response,
        response_decision,
        &final_policy,
        &context.audit,
        Some(response_meta.status.as_u16()),
    ));
    if final_policy.source != base_source {
        emit_processing_fallback_metric(&context.metrics, &final_policy.source);
    }
    context.metrics.policy_decision(
        "response",
        action_name(response_decision),
        &final_policy.source,
    );

    build_upstream_response(
        response_meta.status.as_u16(),
        &response_meta.headers,
        body_out,
        Some(("x-privacy-gateway-action", action_name(response_decision))),
    )
}

async fn response_from_sse_stream(
    context: ResponseContext,
    upstream_response: reqwest::Response,
    response_meta: UpstreamResponseMeta,
) -> Response<Body> {
    let mut raw_stream = upstream_response.bytes_stream();
    let audit_runtime = context.runtime.clone();
    let audit_principal = context.principal.clone();
    let audit_context = context.audit.clone();
    let audit_metrics = context.metrics.clone();
    let status = response_meta.status;
    let body_stream = stream! {
        let mut audit_policy = PolicyOutcome {
            decision: DecisionAction::Allow,
            findings: Vec::new(),
            source: "builtin".to_string(),
            reason: None,
        };
        let mut buffer = Vec::<u8>::new();
        while let Some(chunk) = raw_stream.next().await {
            match chunk {
                Ok(chunk) => {
                    buffer.extend_from_slice(&chunk);
                    while let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
                        let line = buffer.drain(..=position).collect::<Vec<_>>();
                        let line_str = String::from_utf8_lossy(&line);
                        let transformed = transform_sse_line(
                            &audit_runtime,
                            &audit_principal,
                            &audit_context.path_and_query,
                            audit_context.session_escalated,
                            &line_str,
                        ).await;
                        audit_policy = merge_policy_outcomes(audit_policy, transformed.policy);
                        yield Ok::<Bytes, std::io::Error>(Bytes::from(transformed.line));
                    }
                }
                Err(err) => {
                    warn!(error = %err, "failed to read sse chunk");
                    break;
                }
            }
        }
        if !buffer.is_empty() {
            let line_str = String::from_utf8_lossy(&buffer);
            let transformed = transform_sse_line(
                &audit_runtime,
                &audit_principal,
                &audit_context.path_and_query,
                audit_context.session_escalated,
                &line_str,
            ).await;
            audit_policy = merge_policy_outcomes(audit_policy, transformed.policy);
            yield Ok::<Bytes, std::io::Error>(Bytes::from(transformed.line));
        }

        emit_metrics_for_findings(&audit_metrics, Direction::Response, &audit_policy.findings);
        let decision = normalize_response_decision(audit_policy.decision);
        emit_processing_fallback_metric(&audit_metrics, &audit_policy.source);
        audit_runtime.audit.emit(build_audit_record(
            &audit_principal,
            Direction::Response,
            decision,
            &audit_policy,
            &audit_context,
            Some(status.as_u16()),
        ));
        audit_metrics.policy_decision("response", action_name(decision), &audit_policy.source);
    };

    let mut response = build_upstream_response(
        status.as_u16(),
        &response_meta.headers,
        Bytes::new(),
        Some(("x-privacy-gateway-action", "stream")),
    );
    *response.body_mut() = Body::from_stream(body_stream);
    response
}

struct SseTransformResult {
    line: String,
    policy: PolicyOutcome,
}

async fn transform_sse_line(
    runtime: &RuntimeState,
    principal: &Principal,
    path: &str,
    session_escalated: bool,
    line: &str,
) -> SseTransformResult {
    if !line.starts_with("data:") {
        return SseTransformResult {
            line: line.to_string(),
            policy: PolicyOutcome {
                decision: DecisionAction::Allow,
                findings: Vec::new(),
                source: "builtin".to_string(),
                reason: None,
            },
        };
    }
    let payload = line.trim_start_matches("data:").trim();
    if payload.is_empty() || payload == "[DONE]" {
        return SseTransformResult {
            line: line.to_string(),
            policy: PolicyOutcome {
                decision: DecisionAction::Allow,
                findings: Vec::new(),
                source: "builtin".to_string(),
                reason: None,
            },
        };
    }

    let mut is_json_payload = false;

    let (rendered_payload, base_policy) = if let Ok(mut value) =
        serde_json::from_str::<Value>(payload)
    {
        is_json_payload = true;
        let processed = sanitize_json_value(runtime, principal, &mut value, Direction::Response)
            .await
            .unwrap_or_else(JsonProcessResult::error_fallback);
        (
            serde_json::to_string(&processed.redacted_value)
                .unwrap_or_else(|_| generic_redacted_sse_payload(true)),
            processed.policy,
        )
    } else {
        let processed = process_text(runtime, principal, payload, "/sse", Direction::Response)
            .await
            .unwrap_or_else(|_| TextProcessResult::error_fallback());
        (processed.redacted_text, processed.policy)
    };
    let final_policy = finalize_response_policy(
        runtime,
        principal,
        path,
        session_escalated,
        base_policy.clone(),
    )
    .await;
    let final_payload =
        if should_force_full_response_redaction(base_policy.decision, final_policy.decision) {
            generic_redacted_sse_payload(is_json_payload)
        } else {
            rendered_payload
        };

    SseTransformResult {
        line: format!("data: {final_payload}\n"),
        policy: final_policy,
    }
}

pub(crate) async fn process_payload(
    runtime: &RuntimeState,
    metrics: &Metrics,
    principal: &Principal,
    body: &Bytes,
    content_type: Option<&str>,
    direction: Direction,
) -> Result<ProcessedPayload, AppError> {
    let direction_label = match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    };
    if direction == Direction::Request
        && is_multipart_form(content_type)
        && let Some(scan) = {
            let timer = metrics.payload_processing_timer(direction_label, "multipart");
            let result = runtime
                .attachments
                .scan_request(
                    AttachmentScanDeps {
                        detector: &runtime.detector,
                        presidio: runtime.presidio.as_ref(),
                        policy_engine: &runtime.policy,
                        tokenizer: runtime.tokenizer.as_ref(),
                    },
                    principal,
                    body,
                    content_type,
                )
                .await?;
            timer.observe_duration();
            result
        }
    {
        return Ok(ProcessedPayload {
            sanitized_body: scan.sanitized_body,
            policy: scan.policy,
        });
    }

    if is_json(content_type) {
        let timer = metrics.payload_processing_timer(direction_label, "json");
        if let Ok(mut value) = serde_json::from_slice::<Value>(body) {
            let processed = sanitize_json_value(runtime, principal, &mut value, direction).await?;
            timer.observe_duration();
            return Ok(ProcessedPayload {
                sanitized_body: Bytes::from(
                    serde_json::to_vec(&processed.redacted_value).unwrap_or_else(|_| body.to_vec()),
                ),
                policy: processed.policy,
            });
        }
        timer.observe_duration();
    }

    if let Ok(text) = std::str::from_utf8(body) {
        let timer = metrics.payload_processing_timer(direction_label, "text");
        let text_processed = process_text(runtime, principal, text, "/", direction).await?;
        timer.observe_duration();
        return Ok(ProcessedPayload {
            sanitized_body: Bytes::from(text_processed.redacted_text),
            policy: text_processed.policy,
        });
    }

    let timer = metrics.payload_processing_timer(direction_label, "passthrough");
    timer.observe_duration();
    Ok(ProcessedPayload::passthrough(body.clone()))
}

struct JsonProcessResult {
    redacted_value: Value,
    policy: PolicyOutcome,
}

impl JsonProcessResult {
    fn error_fallback(_: AppError) -> Self {
        Self {
            redacted_value: json!({"error":"response redacted by gateway"}),
            policy: PolicyOutcome {
                decision: DecisionAction::Redact,
                findings: Vec::new(),
                source: "json_processing_error_fallback".to_string(),
                reason: Some("json payload processing failed".to_string()),
            },
        }
    }
}

async fn sanitize_json_value(
    runtime: &RuntimeState,
    principal: &Principal,
    value: &mut Value,
    direction: Direction,
) -> Result<JsonProcessResult, AppError> {
    let mut collected_findings = Vec::<ResolvedFinding>::new();
    for (pointer, original) in collect_string_nodes(value, "") {
        if runtime.detector.should_ignore_pointer(&pointer) {
            continue;
        }
        let result = process_text(runtime, principal, &original, &pointer, direction).await?;
        if let Some(slot) = value.pointer_mut(&pointer) {
            *slot = Value::String(result.redacted_text);
        }
        collected_findings.extend(result.policy.findings);
    }
    let decision = collected_findings
        .iter()
        .fold(DecisionAction::Allow, |acc, finding| {
            acc.combine(finding.action)
        });
    Ok(JsonProcessResult {
        redacted_value: value.clone(),
        policy: PolicyOutcome {
            decision,
            findings: collected_findings,
            source: "builtin".to_string(),
            reason: None,
        },
    })
}

fn collect_string_nodes(value: &Value, pointer: &str) -> Vec<(String, String)> {
    let mut nodes = Vec::new();
    match value {
        Value::String(text) => {
            nodes.push((pointer.to_string(), text.clone()));
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let next = format!("{pointer}/{index}");
                nodes.extend(collect_string_nodes(item, &next));
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter() {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                let next = format!("{pointer}/{escaped}");
                nodes.extend(collect_string_nodes(item, &next));
            }
        }
        _ => {}
    }
    nodes
}

struct TextProcessResult {
    redacted_text: String,
    policy: PolicyOutcome,
}

impl TextProcessResult {
    fn error_fallback() -> Self {
        Self {
            redacted_text: "[REDACTED]".to_string(),
            policy: PolicyOutcome {
                decision: DecisionAction::Redact,
                findings: Vec::new(),
                source: "presidio_error_fallback".to_string(),
                reason: Some("presidio analysis failed".to_string()),
            },
        }
    }
}

async fn process_text(
    runtime: &RuntimeState,
    principal: &Principal,
    text: &str,
    pointer: &str,
    direction: Direction,
) -> Result<TextProcessResult, AppError> {
    let mut findings = runtime.detector.scan_text(text, pointer);
    if let Some(presidio) = runtime.presidio.as_ref() {
        findings.extend(presidio.analyze(text, pointer).await?);
    }
    let policy = runtime.policy.resolve(principal, findings, direction);
    let redacted_text = redact_text(text, &policy.findings, runtime.tokenizer.as_ref())?;
    Ok(TextProcessResult {
        redacted_text,
        policy,
    })
}

pub(crate) struct ProcessedPayload {
    pub(crate) sanitized_body: Bytes,
    pub(crate) policy: PolicyOutcome,
}

impl ProcessedPayload {
    fn passthrough(body: Bytes) -> Self {
        Self {
            sanitized_body: body,
            policy: PolicyOutcome {
                decision: DecisionAction::Allow,
                findings: Vec::new(),
                source: "builtin".to_string(),
                reason: None,
            },
        }
    }

    fn error_fallback(_: AppError) -> Self {
        Self {
            sanitized_body: generic_redacted_body(Some("application/json")),
            policy: PolicyOutcome {
                decision: DecisionAction::Redact,
                findings: Vec::new(),
                source: "processing_error_fallback".to_string(),
                reason: Some("payload processing failed".to_string()),
            },
        }
    }
}

async fn finalize_response_policy(
    runtime: &RuntimeState,
    principal: &Principal,
    path: &str,
    session_escalated: bool,
    base_policy: PolicyOutcome,
) -> PolicyOutcome {
    apply_opa_policy(
        runtime,
        principal,
        Direction::Response,
        path,
        session_escalated,
        base_policy.clone(),
    )
    .await
    .unwrap_or_else(|_| PolicyOutcome {
        decision: DecisionAction::Redact,
        findings: base_policy.findings,
        source: "opa_error_fallback".to_string(),
        reason: Some("opa failed during response filtering".to_string()),
    })
}

fn resolve_buffered_response_body(
    content_type: Option<&str>,
    original_body: &Bytes,
    sanitized_body: Bytes,
    base_decision: DecisionAction,
    final_decision: DecisionAction,
) -> (Bytes, DecisionAction) {
    let response_decision = normalize_response_decision(final_decision);
    if response_decision == DecisionAction::Allow {
        return (original_body.clone(), DecisionAction::Allow);
    }
    if should_force_full_response_redaction(base_decision, final_decision) {
        return (generic_redacted_body(content_type), DecisionAction::Redact);
    }
    (sanitized_body, DecisionAction::Redact)
}

fn should_force_full_response_redaction(
    base_decision: DecisionAction,
    final_decision: DecisionAction,
) -> bool {
    final_decision != DecisionAction::Allow && final_decision.rank() > base_decision.rank()
}

fn normalize_response_decision(decision: DecisionAction) -> DecisionAction {
    if decision == DecisionAction::Allow {
        DecisionAction::Allow
    } else {
        DecisionAction::Redact
    }
}

fn generic_redacted_body(content_type: Option<&str>) -> Bytes {
    if is_json(content_type) {
        Bytes::from_static(b"{\"error\":\"response redacted by gateway\"}")
    } else {
        Bytes::from_static(b"[REDACTED]")
    }
}

fn generic_redacted_sse_payload(is_json_payload: bool) -> String {
    if is_json_payload {
        "{\"error\":\"response redacted by gateway\"}".to_string()
    } else {
        "[REDACTED]".to_string()
    }
}

fn merge_policy_outcomes(mut current: PolicyOutcome, mut next: PolicyOutcome) -> PolicyOutcome {
    let current_rank = current.decision.rank();
    let next_rank = next.decision.rank();
    let next_is_more_relevant = next_rank > current_rank
        || (next_rank == current_rank && current.source == "builtin" && next.source != "builtin")
        || (current.reason.is_none() && next.reason.is_some());

    current.decision = current.decision.combine(next.decision);
    if next_is_more_relevant {
        current.source = next.source;
        current.reason = next.reason;
    }
    current.findings.append(&mut next.findings);
    current
}

async fn apply_opa_policy(
    runtime: &RuntimeState,
    principal: &Principal,
    direction: Direction,
    path: &str,
    session_escalated: bool,
    base: PolicyOutcome,
) -> Result<PolicyOutcome, AppError> {
    let Some(opa) = runtime.opa.as_ref() else {
        return Ok(base);
    };
    let input = OpaInput {
        principal,
        direction,
        path,
        session_escalated,
        current_decision: base.decision,
        findings: &base.findings,
    };
    match opa.evaluate(input).await {
        Ok(Some(decision)) => Ok(decision.merge(base)),
        Ok(None) => Ok(base),
        Err(err) if opa.fail_open() => Ok(PolicyOutcome {
            source: "builtin_fail_open".to_string(),
            reason: Some(format!("opa error ignored: {err}")),
            ..base
        }),
        Err(err) => Err(AppError::Opa(err)),
    }
}

fn authenticate_request(state: &AppState, headers: &HeaderMap) -> Result<Principal, AppError> {
    let runtime = state.current();
    authenticate_with(&runtime.auth, headers)
}

/// Authenticate against an [`Authenticator`] directly, without an [`AppState`].
///
/// Used by the MITM proxy path, which holds a `RuntimeState` but no `AppState`.
pub(crate) fn authenticate_with(
    auth: &crate::auth::Authenticator,
    headers: &HeaderMap,
) -> Result<Principal, AppError> {
    auth.authenticate(headers).map_err(AppError::Auth)
}

fn emit_metrics_for_findings(
    metrics: &Metrics,
    direction: Direction,
    findings: &[ResolvedFinding],
) {
    let direction = match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    };
    for finding in findings {
        metrics.detection(direction, &finding.label);
    }
}

fn emit_processing_fallback_metric(metrics: &Metrics, source: &str) {
    if matches!(
        source,
        "attachment_review_fallback"
            | "json_processing_error_fallback"
            | "presidio_error_fallback"
            | "processing_error_fallback"
            | "opa_error_fallback"
            | "builtin_fail_open"
    ) {
        metrics.processing_fallback(source);
    }
}

fn emit_review_override_metric(metrics: &Metrics, source: &str) {
    match source {
        "review_override_approved" => metrics.review_event("override_approved"),
        "review_override_rejected" => metrics.review_event("override_rejected"),
        _ => {}
    }
}

fn proxy_error_kind(err: &AppError) -> &'static str {
    match err {
        AppError::Attachment(_) => "attachment",
        AppError::Presidio(_) => "presidio",
        AppError::Opa(_) => "opa",
        AppError::Tokenization(_) => "tokenization",
        AppError::Detector(_) => "detector",
        AppError::RuntimeIo(_) => "runtime_io",
        AppError::InvalidUpstreamUrl(_) => "upstream_url",
        AppError::Auth(_) => "auth",
        AppError::ReviewStore(_) => "review_store",
        AppError::Config(_) => "config",
        AppError::BuildClient(_) => "build_client",
        AppError::Metrics(_) => "metrics",
        AppError::AuditInit(_) => "audit",
        AppError::Bind(_) => "bind",
        AppError::Serve(_) => "serve",
        AppError::ProxyConfigMissing => "proxy_config_missing",
        AppError::ProxyListenAddr(_) => "proxy_listen_addr",
        AppError::Ca(_) => "proxy_ca",
        AppError::Proxy(_) => "proxy_serve",
    }
}

fn request_pre_upstream_error_reason(stage: &str, kind: &str, err: &AppError) -> String {
    format!("{stage}/{kind}: {err}")
}

fn should_emit_request_pre_upstream_error_audit(err: &AppError) -> bool {
    matches!(
        err,
        AppError::Attachment(_)
            | AppError::Presidio(_)
            | AppError::Opa(_)
            | AppError::Tokenization(_)
            | AppError::Detector(_)
            | AppError::ReviewStore(_)
    )
}

struct RequestPreUpstreamErrorAudit<'a> {
    principal: &'a Principal,
    request_id: &'a str,
    path_and_query: &'a str,
    session_id: Option<String>,
    stage: &'a str,
    kind: &'a str,
    err: &'a AppError,
}

fn build_request_pre_upstream_error_audit(input: RequestPreUpstreamErrorAudit<'_>) -> AuditRecord {
    AuditRecord {
        ts: Utc::now(),
        request_id: input.request_id.to_string(),
        principal: input.principal.name.clone(),
        tenant_id: input.principal.tenant_id.clone(),
        direction: "request".to_string(),
        path: input.path_and_query.to_string(),
        decision: "block".to_string(),
        policy_source: "request_pre_upstream_error".to_string(),
        decision_reason: Some(request_pre_upstream_error_reason(
            input.stage,
            input.kind,
            input.err,
        )),
        matched_labels: Vec::new(),
        matched_rules: Vec::new(),
        findings: Vec::new(),
        session_id: input.session_id,
        session_escalated: false,
        status_code: Some(StatusCode::BAD_GATEWAY.as_u16()),
        error_stage: Some(input.stage.to_string()),
        error_kind: Some(input.kind.to_string()),
    }
}

fn emit_request_pre_upstream_error_audit(
    runtime: &RuntimeState,
    input: RequestPreUpstreamErrorAudit<'_>,
) {
    runtime
        .audit
        .emit(build_request_pre_upstream_error_audit(input));
}

fn build_audit_record(
    principal: &Principal,
    direction: Direction,
    decision: DecisionAction,
    outcome: &PolicyOutcome,
    context: &AuditContext,
    status_code: Option<u16>,
) -> AuditRecord {
    let matched_labels = outcome
        .findings
        .iter()
        .map(|finding| finding.label.clone())
        .collect::<Vec<_>>();
    let matched_rules = outcome
        .findings
        .iter()
        .map(|finding| finding.rule_name.clone())
        .collect::<Vec<_>>();
    let findings = outcome
        .findings
        .iter()
        .map(|finding| AuditFinding {
            label: finding.label.clone(),
            rule_name: finding.rule_name.clone(),
            action: action_name(finding.action).to_string(),
            pointer: finding.pointer.clone(),
            severity: format!("{:?}", finding.severity).to_lowercase(),
            matched_sha256: finding.matched_sha256.clone(),
            matched_len: finding.matched_len,
        })
        .collect::<Vec<_>>();
    AuditRecord {
        ts: Utc::now(),
        request_id: context.request_id.clone(),
        principal: principal.name.clone(),
        tenant_id: principal.tenant_id.clone(),
        direction: match direction {
            Direction::Request => "request".to_string(),
            Direction::Response => "response".to_string(),
        },
        path: context.path_and_query.clone(),
        decision: action_name(decision).to_string(),
        policy_source: outcome.source.clone(),
        decision_reason: outcome.reason.clone(),
        matched_labels,
        matched_rules,
        findings,
        session_id: context.session_id.clone(),
        session_escalated: context.session_escalated,
        status_code,
        error_stage: None,
        error_kind: None,
    }
}

/// Emit detection metrics, an audit record, and the policy-decision metric for
/// one processed payload. Shared by the reverse-proxy and the MITM proxy paths
/// so both data planes produce identical observability + audit output.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_decision_telemetry(
    runtime: &RuntimeState,
    metrics: &Metrics,
    principal: &Principal,
    direction: Direction,
    request_id: &str,
    path_and_query: &str,
    policy: &PolicyOutcome,
    status_code: Option<u16>,
) {
    emit_metrics_for_findings(metrics, direction, &policy.findings);
    let audit_context = AuditContext {
        request_id: request_id.to_string(),
        path_and_query: path_and_query.to_string(),
        session_id: None,
        session_escalated: false,
    };
    runtime.audit.emit(build_audit_record(
        principal,
        direction,
        policy.decision,
        policy,
        &audit_context,
        status_code,
    ));
    emit_processing_fallback_metric(metrics, &policy.source);
    let direction_str = match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    };
    metrics.policy_decision(direction_str, action_name(policy.decision), &policy.source);
}

fn build_upstream_response(
    status_code: u16,
    headers: &reqwest::header::HeaderMap,
    body: impl Into<Bytes>,
    extra_header: Option<(&str, &str)>,
) -> Response<Body> {
    let mut response = Response::builder().status(status_code);
    {
        let headers_mut = response.headers_mut().expect("response builder headers");
        copy_response_headers(headers, headers_mut);
        if let Some((name, value)) = extra_header
            && let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            )
        {
            headers_mut.insert(name, value);
        }
    }
    response
        .body(Body::from(body.into()))
        .unwrap_or_else(|_| Response::new(Body::from(Bytes::new())))
}

fn attach_forward_headers(
    mut request: reqwest::RequestBuilder,
    headers: &HeaderMap,
    allowlist: &std::collections::HashSet<String>,
    request_id: &str,
) -> reqwest::RequestBuilder {
    let mut forwarded = HashMap::<String, String>::new();
    for (name, value) in headers {
        let name_str = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&name_str.as_str()) || !allowlist.contains(&name_str) {
            continue;
        }
        if let Ok(value_str) = value.to_str() {
            forwarded.insert(name_str, value_str.to_string());
        }
    }
    forwarded.insert("x-request-id".to_string(), request_id.to_string());
    debug!(headers = ?forwarded.keys().collect::<Vec<_>>(), "forwarding upstream headers");
    for (name, value) in forwarded {
        request = request.header(name, value);
    }
    request
}

fn copy_response_headers(source: &reqwest::header::HeaderMap, target: &mut axum::http::HeaderMap) {
    for (name, value) in source {
        if HOP_BY_HOP_HEADERS.contains(&name.as_str()) || BODY_SIZE_HEADERS.contains(&name.as_str())
        {
            continue;
        }
        target.insert(name.clone(), value.clone());
    }
}

fn is_json(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.contains("application/json") || value.contains("+json"))
        .unwrap_or(false)
}

fn is_sse(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false)
}

fn gateway_error(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: Option<&str>,
) -> Response<Body> {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "error".to_string(),
        json!({"code": code, "message": message}),
    );
    if let Some(request_id) = request_id {
        payload.insert("request_id".to_string(), json!(request_id));
    }
    let body = serde_json::to_vec(&Value::Object(payload)).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn sha256_hex_bytes(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex::encode(digest)
}

fn review_fingerprint(principal: &Principal, path: &str, request_sha256: &str) -> String {
    let material = format!("{}|{}|{}", principal.tenant_id, path, request_sha256);
    sha256_hex_bytes(material.as_bytes())
}

fn preview_text(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in input.chars().take(max_chars) {
        out.push(ch);
    }
    out
}

fn action_name(action: DecisionAction) -> &'static str {
    match action {
        DecisionAction::Allow => "allow",
        DecisionAction::Redact => "redact",
        DecisionAction::Review => "review",
        DecisionAction::Block => "block",
    }
}

fn action_code(action: DecisionAction) -> &'static str {
    match action {
        DecisionAction::Allow => "allow",
        DecisionAction::Redact => "redact",
        DecisionAction::Review => "review_required",
        DecisionAction::Block => "blocked_sensitive_payload",
    }
}

fn decision_status(action: DecisionAction) -> StatusCode {
    match action {
        DecisionAction::Allow | DecisionAction::Redact => StatusCode::OK,
        DecisionAction::Review => StatusCode::CONFLICT,
        DecisionAction::Block => StatusCode::FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read, Write},
        path::PathBuf,
        sync::Arc,
    };

    use axum::{
        Json, Router,
        body::Body,
        http::{HeaderValue, Response, StatusCode, header::CONTENT_TYPE},
        routing::post,
    };
    use bytes::Bytes;
    use chrono::Utc;
    use http_body_util::BodyExt;
    use lopdf::Document as LopdfDocument;
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use tower::ServiceExt;
    use zip::{ZipWriter, write::FileOptions};

    use crate::{
        app::{build_router, build_state},
        audit::AuditRecord,
        config::{AppConfig, TokenizationConfig},
        review::{NewReviewTicket, ReviewDecisionOverride, ReviewStatus},
        types::{DecisionAction, MaskingStrategy},
    };

    fn build_ooxml_fixture(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut zip_cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut zip_cursor);
            let options = FileOptions::default();
            writer.start_file("[Content_Types].xml", options).unwrap();
            writer
                .write_all(br#"<?xml version="1.0" encoding="UTF-8"?><Types></Types>"#)
                .unwrap();
            for (path, xml) in entries {
                writer.start_file(*path, options).unwrap();
                writer.write_all(xml.as_bytes()).unwrap();
            }
            writer.finish().unwrap();
        }
        zip_cursor.into_inner()
    }

    #[tokio::test]
    async fn readyz_exposes_dependency_and_audit_buffer_status() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        std::fs::write(&config_path, include_str!("../config/example.yaml")).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["ready"], true);
        assert!(
            payload["runtime"]["audit_buffer"]["capacity"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert_eq!(
            payload["runtime"]["dependencies"]["opa"]["configured"],
            false
        );
    }

    #[tokio::test]
    async fn admin_status_embeds_benchmark_surface_when_summary_exists() {
        let temp = tempfile::tempdir().unwrap();
        let bench_summary_path = temp.path().join("bench-summary.json");
        std::fs::write(
            &bench_summary_path,
            r#"{
  "generated_at": "2026-05-22T12:11:24Z",
  "scenario_count": 1,
  "scenarios": [
    {
      "scenario": "json-redact",
      "description": "JSON request/response redact hot path",
      "generated_at": "2026-05-22T12:11:18Z",
      "requests": 80,
      "concurrency": 8,
      "throughput_rps": 1618.98,
      "latency_ms": {"min": 1.0, "p50": 2.0, "p95": 3.0, "max": 4.0, "avg": 2.5},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.9,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["builtin"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": false
      },
      "artifacts_root": ".tmp-smoke/bench-matrix/json-redact",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    }
  ]
}"#,
        )
        .unwrap();

        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.benchmarks.enabled = true;
        config.benchmarks.summary_json_path = bench_summary_path.display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/status")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["observability"]["benchmarks"]["enabled"], true);
        assert_eq!(payload["observability"]["benchmarks"]["loaded"], true);
        assert_eq!(payload["observability"]["benchmarks"]["scenario_count"], 1);
        assert_eq!(
            payload["observability"]["benchmarks"]["scenarios"][0]["scenario"],
            "json-redact"
        );
    }

    #[tokio::test]
    async fn admin_status_embeds_benchmark_baseline_drift_surface() {
        let temp = tempfile::tempdir().unwrap();
        let bench_summary_path = temp.path().join("bench-summary.json");
        let baseline_path = temp.path().join("baseline.json");
        let gate_report_path = temp.path().join("gate-report.json");
        std::fs::write(
            &bench_summary_path,
            r#"{
  "generated_at": "2026-05-22T12:40:21.488828+00:00",
  "scenario_count": 4,
  "scenarios": [
    {
      "scenario": "json-redact",
      "description": "regression candidate",
      "generated_at": "2026-05-22T12:11:18Z",
      "requests": 80,
      "concurrency": 8,
      "throughput_rps": 1500.0,
      "latency_ms": {"min": 1.0, "p50": 3.8, "p95": 6.0, "max": 7.0, "avg": 4.2},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.5,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["builtin"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": false
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/json-redact",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    },
    {
      "scenario": "json-tokenize",
      "description": "improvement candidate",
      "generated_at": "2026-05-22T12:11:18Z",
      "requests": 80,
      "concurrency": 8,
      "throughput_rps": 1500.0,
      "latency_ms": {"min": 3.0, "p50": 5.0, "p95": 8.0, "max": 9.0, "avg": 6.0},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.5,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["builtin"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": true
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/json-tokenize",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    },
    {
      "scenario": "json-review-replay",
      "description": "unchanged candidate",
      "generated_at": "2026-05-22T12:11:18Z",
      "requests": 60,
      "concurrency": 6,
      "throughput_rps": 1020.0,
      "latency_ms": {"min": 3.0, "p50": 4.8, "p95": 6.1, "max": 7.0, "avg": 5.2},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.5,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["review_override_approved"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": true,
        "tokenization": false
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/json-review-replay",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    },
    {
      "scenario": "pdf-redact",
      "description": "new scenario not in baseline",
      "generated_at": "2026-05-22T12:11:18Z",
      "requests": 20,
      "concurrency": 2,
      "throughput_rps": 280.0,
      "latency_ms": {"min": 4.0, "p50": 6.0, "p95": 9.0, "max": 11.0, "avg": 7.0},
      "payload_request_avg_ms": 2.1,
      "payload_response_avg_ms": 0.15,
      "upstream_avg_ms": 3.0,
      "request_payload_kind": "multipart",
      "decision_sources": {"request": ["builtin"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": true,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": false
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/pdf-redact",
      "thresholds": {
        "throughput_rps_min": 10.0,
        "avg_ms_max": 180.0,
        "p95_ms_max": 800.0,
        "payload_request_avg_ms_max": 80.0,
        "payload_response_avg_ms_max": 10.0,
        "upstream_avg_ms_max": 30.0
      },
      "ok": true
    }
  ]
}"#,
        )
        .unwrap();
        std::fs::write(
            &gate_report_path,
            r#"{
  "status": "pass",
  "summary_path": "./summary.json",
  "baseline_path": "./baseline.json",
  "summary_generated_at": "2026-05-22T12:40:21.488828+00:00",
  "baseline_generated_at": "2026-05-21T10:01:00+00:00",
  "scenario_count": 4,
  "baseline_scenario_count": 3,
  "regressions": 0,
  "improvements": 1,
  "unchanged": 2,
  "new_scenarios": 1,
  "thresholds": {
    "max_regressions": 0,
    "fail_on_new": false,
    "throughput_regression_pct": 5.0,
    "avg_latency_regression_pct": 10.0,
    "p95_latency_regression_pct": 10.0,
    "avg_latency_floor_ms": 0.25,
    "p95_latency_floor_ms": 0.5,
    "throughput_improvement_pct": 5.0,
    "latency_improvement_pct": 10.0
  },
  "rows": [
    {
      "scenario": "json-tokenize",
      "classification": "improvement",
      "throughput_rps_current": 1500.0,
      "throughput_rps_baseline": 1200.0,
      "throughput_delta_pct": 25.0,
      "avg_ms_current": 6.0,
      "avg_ms_baseline": 8.0,
      "avg_delta_pct": -25.0,
      "p95_ms_current": 8.0,
      "p95_ms_baseline": 10.0,
      "p95_delta_pct": -20.0,
      "ok": true
    }
  ],
  "failures": []
}"#,
        )
        .unwrap();
        std::fs::write(
            &baseline_path,
            r#"{
  "generated_at": "2026-05-21T10:01:00+00:00",
  "scenario_count": 3,
  "scenarios": [
    {
      "scenario": "json-redact",
      "description": "regression candidate",
      "generated_at": "2026-05-21T10:00:30Z",
      "requests": 80,
      "concurrency": 8,
      "throughput_rps": 2000.0,
      "latency_ms": {"min": 1.0, "p50": 2.0, "p95": 4.0, "max": 5.0, "avg": 3.0},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.5,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["builtin"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": false
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/json-redact",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    },
    {
      "scenario": "json-tokenize",
      "description": "improvement candidate",
      "generated_at": "2026-05-21T10:00:30Z",
      "requests": 80,
      "concurrency": 8,
      "throughput_rps": 1200.0,
      "latency_ms": {"min": 4.0, "p50": 6.0, "p95": 10.0, "max": 12.0, "avg": 8.0},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.5,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["builtin"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": false,
        "tokenization": true
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/json-tokenize",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    },
    {
      "scenario": "json-review-replay",
      "description": "unchanged candidate",
      "generated_at": "2026-05-21T10:00:30Z",
      "requests": 60,
      "concurrency": 6,
      "throughput_rps": 1000.0,
      "latency_ms": {"min": 3.0, "p50": 4.5, "p95": 6.0, "max": 7.0, "avg": 5.0},
      "payload_request_avg_ms": 0.1,
      "payload_response_avg_ms": 0.2,
      "upstream_avg_ms": 2.5,
      "request_payload_kind": "json",
      "decision_sources": {"request": ["review_override_approved"], "response": ["builtin"]},
      "dependency_ready": {"opa": false, "presidio": false},
      "features": {
        "attachment_scanning": false,
        "opa": false,
        "presidio": false,
        "response_filtering": true,
        "session_correlation": true,
        "tokenization": false
      },
      "artifacts_root": ".tmp-smoke/smoke-bench-drift/json-review-replay",
      "thresholds": {
        "throughput_rps_min": 100.0,
        "avg_ms_max": 40.0,
        "p95_ms_max": 250.0,
        "payload_request_avg_ms_max": 5.0,
        "payload_response_avg_ms_max": 5.0,
        "upstream_avg_ms_max": 20.0
      },
      "ok": true
    }
  ]
}"#,
        )
        .unwrap();

        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.benchmarks.enabled = true;
        config.benchmarks.summary_json_path = bench_summary_path.display().to_string();
        config.benchmarks.baseline_summary_json_path = Some(baseline_path.display().to_string());
        config.benchmarks.gate_report_json_path = Some(gate_report_path.display().to_string());
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/status")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();

        let baseline = &payload["observability"]["benchmarks"]["baseline"];
        let gate = &payload["observability"]["benchmarks"]["gate"];
        let scenarios = baseline["scenarios"].as_array().unwrap();
        let scenario = |name: &str| {
            scenarios
                .iter()
                .find(|item| item["scenario"] == name)
                .unwrap_or_else(|| panic!("missing benchmark scenario {name}"))
        };

        assert_eq!(baseline["loaded"], true);
        assert_eq!(baseline["scenario_count"], 3);
        assert_eq!(baseline["regressions"], 1);
        assert_eq!(baseline["improvements"], 1);
        assert_eq!(baseline["unchanged"], 1);
        assert_eq!(baseline["missing_in_baseline"], 1);
        assert_eq!(scenario("json-redact")["classification"], "regression");
        assert_eq!(scenario("json-tokenize")["classification"], "improvement");
        assert_eq!(
            scenario("json-review-replay")["classification"],
            "unchanged"
        );
        assert_eq!(scenario("pdf-redact")["classification"], "new");
        assert!(
            scenario("json-redact")["throughput_delta_pct"]
                .as_f64()
                .unwrap()
                < -20.0
        );
        assert!(scenario("json-tokenize")["avg_delta_pct"].as_f64().unwrap() < -20.0);
        assert!(scenario("pdf-redact")["throughput_delta_pct"].is_null());
        assert_eq!(gate["loaded"], true);
        assert_eq!(gate["fresh"], true);
        assert_eq!(gate["status"], "pass");
        assert_eq!(gate["improvements"], 1);
        assert_eq!(gate["rows"][0]["scenario"], "json-tokenize");
    }

    #[tokio::test]
    async fn admin_status_exposes_attachment_feature_flag() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.attachments.enabled = true;
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/status")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["features"]["attachment_scanning"], true);
        assert_eq!(payload["observability"]["metrics_path"], "/metrics");
        assert_eq!(
            payload["observability"]["runtime_summary"]["review_queue_capacity"],
            1000
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["gauges"]["review_queue_capacity"],
            1000
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["dependencies"]["opa"]["configured"],
            0
        );
    }

    #[tokio::test]
    async fn admin_config_summary_exposes_benchmark_summary_path() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.benchmarks.enabled = true;
        config.benchmarks.summary_json_path =
            temp.path().join("bench-summary.json").display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/config-summary")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["benchmarks"]["enabled"], true);
        assert!(
            payload["benchmarks"]["summary_json_path"]
                .as_str()
                .unwrap()
                .contains("bench-summary.json")
        );
        assert!(
            payload["benchmarks"]["baseline_summary_json_path"]
                .as_str()
                .unwrap()
                .contains("baseline.json")
        );
        assert!(
            payload["benchmarks"]["gate_report_json_path"]
                .as_str()
                .unwrap()
                .contains("gate-report.json")
        );
    }

    #[tokio::test]
    async fn admin_config_summary_exposes_effective_policy_surface_without_secrets() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.attachments.enabled = true;
        config.tokenization = Some(TokenizationConfig {
            enabled: true,
            key_env: "CUSTOM_TOKEN_KEY".to_string(),
            token_prefix: "CGX1".to_string(),
        });
        config.detection.rules[0].masking = MaskingStrategy::Tokenize;
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        unsafe {
            std::env::set_var(
                "CUSTOM_TOKEN_KEY",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            );
        }
        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/config-summary")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["runtime"]["upstream_auth_env_configured"], true);
        assert!(payload["runtime"]["upstream_auth_env_present"].is_boolean());
        assert_eq!(payload["auth"]["principal_count"], 2);
        assert_eq!(payload["tokenization"]["enabled"], true);
        assert_eq!(payload["tokenization"]["required_by_rules"], true);
        assert_eq!(payload["tokenization"]["key_env"], "CUSTOM_TOKEN_KEY");
        assert_eq!(payload["tokenization"]["key_env_present"], true);
        assert_eq!(payload["attachments"]["enabled"], true);
        assert_eq!(payload["detection"]["regex_rule_count"], 10);
        assert_eq!(payload["policy_backend"]["opa"]["runtime_loaded"], false);
        assert_eq!(
            payload["auth"]["principals"][0]["allowed_labels"],
            json!(["email"])
        );
        let rule_names = payload["detection"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|rule| rule["name"].as_str())
            .collect::<std::collections::HashSet<_>>();
        for expected in [
            "email",
            "phone_cn",
            "china_national_id",
            "ip_address",
            "mac_address",
            "imei",
            "vin",
            "bank_card",
            "openai_key",
            "bearer_token",
        ] {
            assert!(rule_names.contains(expected), "missing rule {expected}");
        }
        assert_eq!(
            payload["runtime"]["upstream_forward_headers"],
            json!([
                "accept",
                "content-type",
                "openai-organization",
                "openai-project",
                "x-request-id"
            ])
        );
        let rendered = payload.to_string();
        assert!(!rendered.contains("demo-secret"));
        assert!(!rendered.contains("admin-secret"));
        assert!(!rendered.contains("0001020304050607"));
    }

    #[tokio::test]
    async fn admin_console_serves_embedded_html_shell() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        std::fs::write(&config_path, include_str!("../config/example.yaml")).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            HeaderValue::from_static("no-store")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Context Gurd · Control Plane"));
        assert!(html.contains("/admin/status"));
        assert!(html.contains("/admin/config-summary"));
        assert!(html.contains("/admin/reviews"));
        assert!(html.contains("性能基线矩阵"));
        assert!(html.contains("Top regressions / drift watchlist"));
        assert!(html.contains("benchmarkDriftTable"));
        assert!(html.contains("benchmarkDriftSummary"));
        assert!(html.contains("/admin/benchmarks/promote"));
        assert!(html.contains("admin token"));
        assert!(html.contains("Proxy hard-fails"));
        assert!(html.contains("Pre-upstream failure radar"));
        assert!(html.contains("proxyErrorTable"));
        assert!(html.contains("Latest hard-fails"));
        assert!(html.contains("latestHardFailsList"));
        assert!(html.contains("data-hard-fail-focus"));
        assert!(html.contains("auditPolicySource"));
        assert!(html.contains("auditRequestId"));
        assert!(html.contains("auditErrorStage"));
        assert!(html.contains("auditErrorKind"));
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_runtime_and_dependency_series() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let metrics = String::from_utf8_lossy(&body);
        assert!(metrics.contains("gateway_review_queue_pending 0"));
        assert!(metrics.contains("gateway_review_queue_capacity 1000"));
        assert!(metrics.contains("gateway_active_sessions 0"));
        assert!(metrics.contains("gateway_dependency_configured{dependency=\"opa\"} 0"));
        assert!(metrics.contains("gateway_dependency_ready{dependency=\"opa\"} 0"));
        assert!(metrics.contains("gateway_dependency_status_code{dependency=\"opa\"} 0"));
    }

    #[tokio::test]
    async fn request_preprocessing_failures_surface_in_metrics_summary_and_error_response() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async { Json(json!({"ok": true})) }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.attachments.enabled = true;
        config.detection.rules.clear();
        config.detection.high_entropy = None;
        config.detection.presidio = Some(crate::config::PresidioConfig {
            enabled: true,
            analyzer_url: "http://127.0.0.1:9/analyze".to_string(),
            healthcheck_url: Some("http://127.0.0.1:9/health".to_string()),
            timeout_ms: 50,
            language: "en".to_string(),
            entities: vec![crate::config::PresidioEntityConfig {
                entity_type: "EMAIL_ADDRESS".to_string(),
                label: "email".to_string(),
                severity: crate::types::Severity::Medium,
                authorized_action: DecisionAction::Allow,
                unauthorized_action: DecisionAction::Redact,
                min_clearance: crate::types::Clearance::Internal,
                masking: crate::types::MaskingStrategy::PartialEmail,
                min_score: 0.35,
            }],
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state.clone());
        let boundary = "preprocess-hard-fail";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\n邮箱 admin@example.com\r\n--{boundary}--\r\n"
        );

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let payload: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(payload["error"]["code"], "upstream_error");
        assert!(
            payload["request_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            payload["error"]["message"]
                .as_str()
                .unwrap()
                .contains("attachment text analysis failed")
        );

        let status_request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/status")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(status_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            payload["observability"]["metrics_summary"]["counters"]["proxy_errors_total"]["request_pre_upstream"]
                ["attachment"],
            1
        );

        let metrics_request = axum::http::Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(metrics_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let metrics =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .into_owned();
        assert!(metrics.contains(
            "gateway_proxy_errors_total{kind=\"attachment\",stage=\"request_pre_upstream\"} 1"
        ));
    }

    #[tokio::test]
    async fn request_preprocessing_failures_emit_skeleton_audit_record() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async { Json(json!({"ok": true})) }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.attachments.enabled = true;
        config.detection.rules.clear();
        config.detection.high_entropy = None;
        config.detection.presidio = Some(crate::config::PresidioConfig {
            enabled: true,
            analyzer_url: "http://127.0.0.1:9/analyze".to_string(),
            healthcheck_url: Some("http://127.0.0.1:9/health".to_string()),
            timeout_ms: 50,
            language: "en".to_string(),
            entities: vec![crate::config::PresidioEntityConfig {
                entity_type: "EMAIL_ADDRESS".to_string(),
                label: "email".to_string(),
                severity: crate::types::Severity::Medium,
                authorized_action: DecisionAction::Allow,
                unauthorized_action: DecisionAction::Redact,
                min_clearance: crate::types::Clearance::Internal,
                masking: crate::types::MaskingStrategy::PartialEmail,
                min_score: 0.35,
            }],
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state.clone());
        let boundary = "audit-hard-fail";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\n邮箱 admin@example.com\r\n--{boundary}--\r\n"
        );

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("x-session-id", "hard-fail-1")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let audits = state.audit_store.snapshot();
        assert_eq!(audits.len(), 1, "{audits:?}");
        let record = &audits[0];
        assert_eq!(record.direction, "request");
        assert_eq!(record.decision, "block");
        assert_eq!(record.policy_source, "request_pre_upstream_error");
        assert_eq!(record.path, "/v1/chat/completions");
        assert_eq!(record.session_id.as_deref(), Some("hard-fail-1"));
        assert_eq!(record.status_code, Some(502));
        assert!(record.findings.is_empty());
        assert!(record.matched_labels.is_empty());
        assert!(record.matched_rules.is_empty());
        assert!(
            record
                .decision_reason
                .as_deref()
                .is_some_and(|value| value.contains("request_pre_upstream/attachment"))
        );
        assert!(
            record
                .decision_reason
                .as_deref()
                .is_some_and(|value| value.contains("presidio request failed"))
        );
        let rendered = serde_json::to_string(record).unwrap();
        assert!(!rendered.contains("admin@example.com"), "{rendered}");
    }

    #[tokio::test]
    async fn blocks_request_with_phone() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        std::fs::write(&config_path, include_str!("../config/example.yaml")).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"我的手机号是13812341234"}]})
                    .to_string(),
            ))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn redacts_email_before_upstream() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Value>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |Json(payload): Json<Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().await = Some(payload.clone());
                    Json(json!({"ok": true, "echo": payload}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"邮箱admin@example.com"}]}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["ok"], true);

        let forwarded = received.lock().await.clone().unwrap();
        assert_eq!(
            forwarded["messages"][0]["content"],
            Value::String("邮箱a***@example.com".to_string())
        );
    }

    #[tokio::test]
    async fn redacts_text_attachment_before_upstream() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |request: axum::extract::Request| {
                let received = received_clone.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), 2 * 1024 * 1024)
                        .await
                        .unwrap();
                    *received.lock().await = Some(body);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.attachments.enabled = true;
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let boundary = "upload-demo";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nsummarize\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\n邮箱 admin@example.com\r\n--{boundary}--\r\n"
        );

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = received.lock().await.clone().unwrap();
        let forwarded_str = String::from_utf8_lossy(&forwarded);
        assert!(forwarded_str.contains("a***@example.com"));
        assert!(!forwarded_str.contains("admin@example.com"));
    }

    #[tokio::test]
    async fn redacts_sensitive_docx_attachment_before_upstream() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |request: axum::extract::Request| {
                let received = received_clone.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), 2 * 1024 * 1024)
                        .await
                        .unwrap();
                    *received.lock().await = Some(body);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.attachments.enabled = true;
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let docx = build_ooxml_fixture(&[(
            "word/document.xml",
            "<w:document xmlns:w=\"urn:x\"><w:body><w:p><w:r><w:t>邮箱 admin@example.com</w:t></w:r></w:p></w:body></w:document>",
        )]);
        let boundary = "docx-review";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.docx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&docx);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(
                &response.into_body().collect().await.unwrap().to_bytes()
            )
            .unwrap()["ok"],
            true
        );

        let forwarded = received.lock().await.clone().unwrap();
        let boundary_marker = format!("\r\n--{boundary}--").into_bytes();
        let start = forwarded
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let end = forwarded
            .windows(boundary_marker.len())
            .rposition(|window| window == boundary_marker.as_slice())
            .unwrap();
        let docx = &forwarded[start..end];
        let mut archive = zip::ZipArchive::new(Cursor::new(docx)).unwrap();
        let mut document = archive.by_name("word/document.xml").unwrap();
        let mut xml = String::new();
        document.read_to_string(&mut xml).unwrap();
        assert!(xml.contains("a***@example.com"));
        assert!(!xml.contains("admin@example.com"));
    }

    #[tokio::test]
    async fn redacts_sensitive_xlsx_attachment_before_upstream() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |request: axum::extract::Request| {
                let received = received_clone.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), 2 * 1024 * 1024)
                        .await
                        .unwrap();
                    *received.lock().await = Some(body);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.attachments.enabled = true;
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let xlsx = build_ooxml_fixture(&[(
            "xl/sharedStrings.xml",
            "<sst xmlns=\"urn:x\"><si><t>邮箱 admin@example.com</t></si></sst>",
        )]);
        let boundary = "xlsx-redact";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.xlsx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&xlsx);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let forwarded = received.lock().await.clone().unwrap();
        let boundary_marker = format!("\r\n--{boundary}--").into_bytes();
        let start = forwarded
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let end = forwarded
            .windows(boundary_marker.len())
            .rposition(|window| window == boundary_marker.as_slice())
            .unwrap();
        let xlsx = &forwarded[start..end];
        let mut archive = zip::ZipArchive::new(Cursor::new(xlsx)).unwrap();
        let mut xml_entry = archive.by_name("xl/sharedStrings.xml").unwrap();
        let mut xml = String::new();
        xml_entry.read_to_string(&mut xml).unwrap();
        assert!(xml.contains("a***@example.com"));
        assert!(!xml.contains("admin@example.com"));
    }

    #[tokio::test]
    async fn redacts_sensitive_pptx_attachment_before_upstream() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |request: axum::extract::Request| {
                let received = received_clone.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), 2 * 1024 * 1024)
                        .await
                        .unwrap();
                    *received.lock().await = Some(body);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.attachments.enabled = true;
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let pptx = build_ooxml_fixture(&[(
            "ppt/slides/slide1.xml",
            "<p:sld xmlns:p=\"urn:x\"><p:cSld><p:spTree><p:sp><p:txBody><a:p xmlns:a=\"urn:y\"><a:r><a:t>邮箱 admin@example.com</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>",
        )]);
        let boundary = "pptx-redact";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.pptx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.presentationml.presentation\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&pptx);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let forwarded = received.lock().await.clone().unwrap();
        let boundary_marker = format!("\r\n--{boundary}--").into_bytes();
        let start = forwarded
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let end = forwarded
            .windows(boundary_marker.len())
            .rposition(|window| window == boundary_marker.as_slice())
            .unwrap();
        let pptx = &forwarded[start..end];
        let mut archive = zip::ZipArchive::new(Cursor::new(pptx)).unwrap();
        let mut xml_entry = archive.by_name("ppt/slides/slide1.xml").unwrap();
        let mut xml = String::new();
        xml_entry.read_to_string(&mut xml).unwrap();
        assert!(xml.contains("a***@example.com"));
        assert!(!xml.contains("admin@example.com"));
    }

    #[tokio::test]
    async fn redacts_simple_pdf_attachment_before_upstream() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |request: axum::extract::Request| {
                let received = received_clone.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), 2 * 1024 * 1024)
                        .await
                        .unwrap();
                    *received.lock().await = Some(body);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.attachments.enabled = true;
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let pdf = crate::attachments::build_pdf_bytes_for_test("邮箱 admin@example.com");
        let boundary = "pdf-redact";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&pdf);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let forwarded = received.lock().await.clone().unwrap();
        let boundary_marker = format!("\r\n--{boundary}--").into_bytes();
        let start = forwarded
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let end = forwarded
            .windows(boundary_marker.len())
            .rposition(|window| window == boundary_marker.as_slice())
            .unwrap();
        let pdf = &forwarded[start..end];
        let parsed = LopdfDocument::load_mem(pdf).unwrap();
        let text = parsed.extract_text(&[1]).unwrap();
        assert!(text.contains("a***@example.com"));
        assert!(!text.contains("admin@example.com"));
    }

    #[tokio::test]
    async fn escalates_multi_turn_sensitive_session_to_review() {
        let received = Arc::new(tokio::sync::Mutex::new(0usize));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move || {
                let received = received_clone.clone();
                async move {
                    *received.lock().await += 1;
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state.clone());

        let req1 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .header("x-session-id", "sess-1")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"邮箱 admin@example.com"}]})
                    .to_string(),
            ))
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::OK);

        let req2 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .header("x-session-id", "sess-1")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"手机号13812341234"}]}).to_string(),
            ))
            .unwrap();
        let res2 = app.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::CONFLICT);

        let body = res2.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], "review_required");
        assert_eq!(*received.lock().await, 1);
        assert_eq!(
            state
                .sessions
                .active_sessions(&state.current().config.session),
            1
        );
    }

    #[tokio::test]
    async fn redacts_sensitive_response_payload() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                Json(json!({
                    "id": "resp_1",
                    "choices": [{
                        "message": {"role":"assistant","content":"联系 admin@example.com 或 13812341234"}
                    }]
                }))
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.auth.principals[0].allowed_labels.clear();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"hi"}]}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-privacy-gateway-action"],
            HeaderValue::from_static("redact")
        );
        assert!(response.headers().get(CONTENT_TYPE).is_some());
        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let expected_len = body.len().to_string();
        assert_eq!(content_length.as_deref(), Some(expected_len.as_str()));
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["choices"][0]["message"]["content"],
            "联系 a***@example.com 或 138****1234"
        );
    }

    #[tokio::test]
    async fn opa_can_escalate_request_to_review() {
        let received = Arc::new(tokio::sync::Mutex::new(0usize));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move || {
                let received = received_clone.clone();
                async move {
                    *received.lock().await += 1;
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let opa = Router::new().route(
            "/v1/data/llm/privacy/decision",
            post(|| async {
                Json(json!({
                    "result": {
                        "action": "review",
                        "reason": "policy requires approval"
                    }
                }))
            }),
        );
        let opa_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let opa_addr = opa_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(opa_listener, opa).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.policy_backend.opa = Some(crate::config::OpaConfig {
            enabled: true,
            url: format!("http://{opa_addr}/v1/data/llm/privacy/decision"),
            healthcheck_url: Some(format!("http://{opa_addr}/health")),
            timeout_ms: 300,
            fail_open: false,
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"普通文本"}]}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], "review_required");
        assert_eq!(*received.lock().await, 0);
    }

    #[tokio::test]
    async fn opa_fail_open_preserves_builtin_allow() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async { Json(json!({"ok": true})) }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.policy_backend.opa = Some(crate::config::OpaConfig {
            enabled: true,
            url: "http://127.0.0.1:9/v1/data/llm/privacy/decision".to_string(),
            healthcheck_url: Some("http://127.0.0.1:9/health".to_string()),
            timeout_ms: 50,
            fail_open: true,
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"邮箱 admin@example.com"}]})
                    .to_string(),
            ))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let metrics_request = axum::http::Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(metrics_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let metrics = String::from_utf8_lossy(&body);
        assert!(
            metrics.contains("gateway_processing_fallback_total{kind=\"builtin_fail_open\"} 2")
        );
        assert!(metrics.contains(
            "gateway_policy_decisions_total{decision=\"allow\",direction=\"request\",source=\"builtin_fail_open\"} 1"
        ));
        assert!(metrics.contains(
            "gateway_policy_decisions_total{decision=\"allow\",direction=\"response\",source=\"builtin_fail_open\"} 1"
        ));
    }

    #[tokio::test]
    async fn presidio_sidecar_can_redact_person_entity() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Value>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |Json(payload): Json<Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().await = Some(payload.clone());
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let presidio = Router::new().route(
            "/analyze",
            post(|| async {
                Json(json!([{ "start": 0, "end": 4, "score": 0.91, "entity_type": "PERSON" }]))
            }),
        );
        let presidio_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let presidio_addr = presidio_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(presidio_listener, presidio).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.auth.principals[0].allowed_labels.clear();
        config.detection.presidio = Some(crate::config::PresidioConfig {
            enabled: true,
            analyzer_url: format!("http://{presidio_addr}/analyze"),
            healthcheck_url: Some(format!("http://{presidio_addr}/health")),
            timeout_ms: 300,
            language: "en".to_string(),
            entities: vec![crate::config::PresidioEntityConfig {
                entity_type: "PERSON".to_string(),
                label: "person".to_string(),
                severity: crate::types::Severity::Medium,
                authorized_action: DecisionAction::Redact,
                unauthorized_action: DecisionAction::Redact,
                min_clearance: crate::types::Clearance::Internal,
                masking: crate::types::MaskingStrategy::Placeholder,
                min_score: 0.35,
            }],
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"John shared an update"}]}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = received.lock().await.clone().unwrap();
        assert_eq!(
            forwarded["messages"][0]["content"],
            Value::String("[PERSON] shared an update".to_string())
        );
    }

    #[tokio::test]
    async fn opa_can_escalate_response_to_full_redaction() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                Json(json!({
                    "id": "resp_opa",
                    "choices": [{
                        "message": {"role":"assistant","content":"普通响应内容"}
                    }]
                }))
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let opa = Router::new().route(
            "/v1/data/llm/privacy/decision",
            post(|Json(payload): Json<Value>| async move {
                let direction = payload["input"]["direction"].as_str().unwrap_or_default();
                let result = if direction == "response" {
                    json!({
                        "action": "review",
                        "reason": "response requires approval"
                    })
                } else {
                    Value::Null
                };
                Json(json!({ "result": result }))
            }),
        );
        let opa_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let opa_addr = opa_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(opa_listener, opa).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.policy_backend.opa = Some(crate::config::OpaConfig {
            enabled: true,
            url: format!("http://{opa_addr}/v1/data/llm/privacy/decision"),
            healthcheck_url: Some(format!("http://{opa_addr}/health")),
            timeout_ms: 300,
            fail_open: false,
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"hi"}]}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-privacy-gateway-action"],
            HeaderValue::from_static("redact")
        );
        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let expected_len = body.len().to_string();
        assert_eq!(content_length.as_deref(), Some(expected_len.as_str()));
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"], json!("response redacted by gateway"));
    }

    #[tokio::test]
    async fn opa_can_escalate_sse_line_to_redacted_sentinel() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/event-stream")
                    .body(Body::from(
                        "data: {\"choices\":[{\"delta\":{\"content\":\"普通响应内容\"}}]}\n\ndata: [DONE]\n",
                    ))
                    .unwrap()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let opa = Router::new().route(
            "/v1/data/llm/privacy/decision",
            post(|Json(payload): Json<Value>| async move {
                let direction = payload["input"]["direction"].as_str().unwrap_or_default();
                let result = if direction == "response" {
                    json!({
                        "action": "block",
                        "reason": "stream policy denied"
                    })
                } else {
                    Value::Null
                };
                Json(json!({ "result": result }))
            }),
        );
        let opa_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let opa_addr = opa_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(opa_listener, opa).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.policy_backend.opa = Some(crate::config::OpaConfig {
            enabled: true,
            url: format!("http://{opa_addr}/v1/data/llm/privacy/decision"),
            healthcheck_url: Some(format!("http://{opa_addr}/health")),
            timeout_ms: 300,
            fail_open: false,
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state.clone());
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"hi"}]}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-privacy-gateway-action"],
            HeaderValue::from_static("stream")
        );
        assert!(response.headers().get("content-length").is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("data: {\"error\":\"response redacted by gateway\"}\n"));
        assert!(!body_str.contains("普通响应内容"));
        assert!(body_str.contains("data: [DONE]"));

        let audits = state.audit_store.snapshot();
        let response_audit = audits
            .iter()
            .find(|record| record.direction == "response")
            .unwrap();
        assert_eq!(response_audit.decision, "redact");
        assert_eq!(response_audit.policy_source, "opa");
    }

    #[tokio::test]
    async fn sse_json_processing_error_fallback_returns_redacted_sentinel() {
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/event-stream")
                    .body(Body::from(
                        "data: {\"choices\":[{\"delta\":{\"content\":\"普通响应内容\"}}]}\n\ndata: [DONE]\n",
                    ))
                    .unwrap()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.auth.principals[0].allowed_labels.clear();
        config.detection.rules.clear();
        config.detection.high_entropy = None;
        config.detection.presidio = Some(crate::config::PresidioConfig {
            enabled: true,
            analyzer_url: "http://127.0.0.1:9/analyze".to_string(),
            healthcheck_url: Some("http://127.0.0.1:9/health".to_string()),
            timeout_ms: 50,
            language: "en".to_string(),
            entities: vec![crate::config::PresidioEntityConfig {
                entity_type: "EMAIL_ADDRESS".to_string(),
                label: "email".to_string(),
                severity: crate::types::Severity::Medium,
                authorized_action: DecisionAction::Allow,
                unauthorized_action: DecisionAction::Redact,
                min_clearance: crate::types::Clearance::Internal,
                masking: crate::types::MaskingStrategy::PartialEmail,
                min_score: 0.35,
            }],
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state.clone());
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"model":"gpt-4.1-mini","stream":true}).to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-privacy-gateway-action"],
            HeaderValue::from_static("stream")
        );
        assert!(response.headers().get("content-length").is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("data: {\"error\":\"response redacted by gateway\"}\n"));
        assert!(!body_str.contains("普通响应内容"));
        assert!(body_str.contains("data: [DONE]"));

        let audits = state.audit_store.snapshot();
        let response_audit = audits
            .iter()
            .find(|record| record.direction == "response")
            .unwrap();
        assert_eq!(response_audit.decision, "redact");
        assert_eq!(
            response_audit.policy_source,
            "json_processing_error_fallback"
        );
    }

    #[tokio::test]
    async fn admin_audits_returns_buffered_records() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        std::fs::write(&config_path, include_str!("../config/example.yaml")).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"我的手机号是13812341234"}]})
                    .to_string(),
            ))
            .unwrap();
        let _ = app.clone().oneshot(req).await.unwrap();

        let audits = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/audits?limit=10&decision=block")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(audits).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert!(payload["count"].as_u64().unwrap() >= 1);
        assert_eq!(payload["records"][0]["decision"], "block");
    }

    #[tokio::test]
    async fn admin_audits_can_read_from_file_source() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let audit_path = temp.path().join("audit.log");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.audit.jsonl_path = audit_path.display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"我的手机号是13812341234"}]})
                    .to_string(),
            ))
            .unwrap();
        let _ = app.clone().oneshot(req).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let audits = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/audits?limit=5&decision=block&source=file")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(audits).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["source"], "file");
        assert!(payload["count"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn admin_audits_both_deduplicates_memory_and_file_records() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let audit_path = temp.path().join("audit.log");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.audit.jsonl_path = audit_path.display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(config_path).unwrap();
        let app = build_router(state);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"我的手机号是13812341234"}]})
                    .to_string(),
            ))
            .unwrap();
        let _ = app.clone().oneshot(req).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let audits = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/audits?limit=5&decision=block&source=both")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(audits).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["source"], "both");
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["records"][0]["matched_labels"][0], "phone");
    }

    #[tokio::test]
    async fn admin_audits_can_filter_request_pre_upstream_error_fields() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let audit_path = temp.path().join("audit.log");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.audit.jsonl_path = audit_path.display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        state.audit_store.push(AuditRecord {
            ts: Utc::now(),
            request_id: "req-hard-fail".to_string(),
            principal: "demo-app".to_string(),
            tenant_id: "engineering".to_string(),
            direction: "request".to_string(),
            path: "/v1/chat/completions".to_string(),
            decision: "block".to_string(),
            policy_source: "request_pre_upstream_error".to_string(),
            decision_reason: Some(
                "request_pre_upstream/attachment: presidio request failed".to_string(),
            ),
            matched_labels: vec![],
            matched_rules: vec![],
            findings: vec![],
            session_id: None,
            session_escalated: false,
            status_code: Some(502),
            error_stage: Some("request_pre_upstream".to_string()),
            error_kind: Some("attachment".to_string()),
        });

        let app = build_router(state);
        let audits = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/audits?policy_source=request_pre_upstream_error&request_id=req-hard-fail&error_stage=request_pre_upstream&error_kind=attachment")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(audits).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["count"], 1, "{payload}");
        let record = &payload["records"][0];
        assert_eq!(record["policy_source"], "request_pre_upstream_error");
        assert_eq!(record["request_id"], "req-hard-fail");
        assert_eq!(record["error_stage"], "request_pre_upstream");
        assert_eq!(record["error_kind"], "attachment");
    }

    #[test]
    fn build_state_rejects_tokenize_masking_without_tokenization_config() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config
            .detection
            .rules
            .iter_mut()
            .find(|rule| rule.label == "email")
            .unwrap()
            .masking = MaskingStrategy::Tokenize;
        config.tokenization = None;
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let err = build_state(config_path)
            .err()
            .expect("expected build_state error");
        assert!(
            err.to_string()
                .contains("tokenization is required by masking rules but not configured")
        );
    }

    #[tokio::test]
    async fn admin_detokenize_reveals_tokenized_value_for_admin() {
        let received = Arc::new(tokio::sync::Mutex::new(None::<Value>));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move |Json(payload): Json<Value>| {
                let received = received_clone.clone();
                async move {
                    *received.lock().await = Some(payload.clone());
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.auth.principals[0].allowed_labels.clear();
        config
            .detection
            .rules
            .iter_mut()
            .find(|rule| rule.label == "email")
            .unwrap()
            .masking = MaskingStrategy::Tokenize;
        config.tokenization = Some(TokenizationConfig {
            enabled: true,
            key_env: "CONTEXT_GURD_TEST_TOKEN_KEY_ROUTE".to_string(),
            token_prefix: "TST1".to_string(),
        });
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        unsafe {
            std::env::set_var(
                "CONTEXT_GURD_TEST_TOKEN_KEY_ROUTE",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            );
        }
        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer demo-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"messages":[{"role":"user","content":"邮箱admin@example.com"}]}).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let forwarded = received.lock().await.clone().unwrap();
        let token = forwarded["messages"][0]["content"]
            .as_str()
            .unwrap()
            .strip_prefix("邮箱")
            .unwrap()
            .to_string();
        assert!(token.starts_with("[EMAIL_TOKEN:TST1."));

        let detokenize = axum::http::Request::builder()
            .method("POST")
            .uri("/admin/detokenize")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "token": token }).to_string()))
            .unwrap();
        let response = app.oneshot(detokenize).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["label"], "email");
        assert_eq!(payload["value"], "admin@example.com");
        assert_eq!(payload["token_prefix"], "TST1");

        unsafe {
            std::env::remove_var("CONTEXT_GURD_TEST_TOKEN_KEY_ROUTE");
        }
    }

    #[tokio::test]
    async fn admin_benchmark_promote_copies_summary_to_baseline() {
        let temp = tempfile::tempdir().unwrap();
        let summary_path = temp.path().join("summary.json");
        let baseline_path = temp.path().join("baseline").join("baseline.json");
        std::fs::write(
            &summary_path,
            r#"{
  "generated_at": "2026-05-22T12:11:24Z",
  "scenario_count": 1,
  "scenarios": []
}"#,
        )
        .unwrap();

        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.benchmarks.enabled = true;
        config.benchmarks.summary_json_path = summary_path.display().to_string();
        config.benchmarks.baseline_summary_json_path = Some(baseline_path.display().to_string());
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/admin/benchmarks/promote")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["status"], "baseline_promoted");
        assert!(baseline_path.exists());
        assert_eq!(
            std::fs::read_to_string(summary_path).unwrap(),
            std::fs::read_to_string(baseline_path).unwrap()
        );
    }

    #[tokio::test]
    async fn admin_reviews_can_list_and_resolve_ticket_then_replay_request() {
        let received = Arc::new(tokio::sync::Mutex::new(0usize));
        let received_clone = received.clone();
        let upstream = Router::new().route(
            "/v1/chat/completions",
            post(move || {
                let received = received_clone.clone();
                async move {
                    *received.lock().await += 1;
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.upstream.base_url = format!("http://{upstream_addr}/");
        config.audit.jsonl_path = temp.path().join("audit.log").display().to_string();
        config.review.jsonl_path = temp.path().join("review.log").display().to_string();
        config.session.correlation_threshold = 1;
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let app = build_router(state.clone());
        let request_body =
            json!({"messages":[{"role":"user","content":"邮箱 admin@example.com"}]}).to_string();

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .header("x-session-id", "review-1")
            .body(Body::from(request_body.clone()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let ticket_id = payload["review"]["ticket_id"].as_str().unwrap().to_string();
        assert_eq!(payload["error"]["code"], "review_required");
        assert_eq!(*received.lock().await, 0);

        let list = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/reviews?status=pending")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(list).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["records"][0]["id"], ticket_id);

        let resolve = axum::http::Request::builder()
            .method("POST")
            .uri("/admin/reviews/resolve")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "id": ticket_id,
                    "approve": true,
                    "note": "approved for test replay"
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(resolve).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["record"]["status"], "approved");

        let replay = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer admin-secret")
            .header("content-type", "application/json")
            .header("x-session-id", "review-1")
            .header(super::REVIEW_TICKET_HEADER, ticket_id.as_str())
            .body(Body::from(request_body))
            .unwrap();
        let response = app.clone().oneshot(replay).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*received.lock().await, 1);
        let audits = state.audit_store.snapshot();
        assert!(audits.iter().any(|record| {
            record.decision == "allow" && record.policy_source == "review_override_approved"
        }));

        let status_request = axum::http::Request::builder()
            .method("GET")
            .uri("/admin/status")
            .header("authorization", "Bearer admin-secret")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(status_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["observability"]["metrics_summary"]["counters"]["review_events_total"]["created"],
            1
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["counters"]["review_events_total"]["approved"],
            1
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["counters"]["review_events_total"]["override_approved"],
            1
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["gauges"]["review_queue_pending"],
            0
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]
                ["review"]["builtin"],
            1
        );
        assert_eq!(
            payload["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]
                ["allow"]["review_override_approved"],
            1
        );

        let metrics_request = axum::http::Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(metrics_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let metrics = String::from_utf8_lossy(&body);
        assert!(metrics.contains("gateway_review_events_total{event=\"created\"} 1"));
        assert!(metrics.contains("gateway_review_events_total{event=\"approved\"} 1"));
        assert!(metrics.contains("gateway_review_events_total{event=\"override_approved\"} 1"));
        assert!(metrics.contains("gateway_review_queue_pending 0"));
        assert!(metrics.contains(
            "gateway_policy_decisions_total{decision=\"review\",direction=\"request\",source=\"builtin\"} 1"
        ));
        assert!(metrics.contains(
            "gateway_policy_decisions_total{decision=\"allow\",direction=\"request\",source=\"review_override_approved\"} 1"
        ));
    }

    #[tokio::test]
    async fn review_tickets_survive_store_reload() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.yaml");
        let review_path = temp.path().join("review.log");
        let mut config: AppConfig =
            serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
        config.review.jsonl_path = review_path.display().to_string();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

        let state = build_state(PathBuf::from(&config_path)).unwrap();
        let ticket = state
            .reviews
            .upsert_pending(NewReviewTicket {
                request_id: "req-1".to_string(),
                principal: "security-admin".to_string(),
                tenant_id: "secops".to_string(),
                direction: "request".to_string(),
                path: "/v1/chat/completions".to_string(),
                policy_source: "builtin".to_string(),
                decision_reason: Some("manual review".to_string()),
                matched_labels: vec!["email".to_string()],
                matched_rules: vec!["email".to_string()],
                findings: vec![],
                session_id: Some("sess-1".to_string()),
                session_escalated: true,
                request_sha256: "sha-1".to_string(),
                sanitized_preview: Some("preview".to_string()),
                post_approval_action: DecisionAction::Allow,
                fingerprint: "fp-1".to_string(),
            })
            .unwrap();
        state
            .reviews
            .resolve(
                &ticket.id,
                ReviewStatus::Approved,
                "security-admin".to_string(),
                Some("persisted".to_string()),
                900,
            )
            .unwrap();

        let reloaded = build_state(PathBuf::from(&config_path)).unwrap();
        let approved = reloaded.reviews.get(&ticket.id).unwrap();
        assert_eq!(approved.status, ReviewStatus::Approved);
        assert_eq!(
            approved.resolution.as_ref().unwrap().resolved_by,
            "security-admin"
        );
        assert!(matches!(
            reloaded.reviews.lookup_override("fp-1"),
            Some(ReviewDecisionOverride::Approved { .. })
        ));
    }
}
