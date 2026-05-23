use axum::{extract::State, http::StatusCode, response::IntoResponse};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use serde_json::{Map, Number, Value, json};
use std::sync::Arc;

use crate::app::AppState;

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    policy_decisions_total: IntCounterVec,
    proxy_errors_total: IntCounterVec,
    detections_total: IntCounterVec,
    auth_failures_total: IntCounterVec,
    review_events_total: IntCounterVec,
    processing_fallback_total: IntCounterVec,
    payload_processing_duration_seconds: HistogramVec,
    upstream_duration_seconds: HistogramVec,
    active_sessions: IntGauge,
    review_queue_pending: IntGauge,
    review_queue_capacity: IntGauge,
    dependency_configured: IntGaugeVec,
    dependency_ready: IntGaugeVec,
    dependency_status_code: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let requests_total = IntCounterVec::new(
            Opts::new(
                "gateway_requests_total",
                "Gateway requests by direction and decision",
            ),
            &["direction", "decision"],
        )?;
        let policy_decisions_total = IntCounterVec::new(
            Opts::new(
                "gateway_policy_decisions_total",
                "Gateway policy decisions by direction, decision, and source",
            ),
            &["direction", "decision", "source"],
        )?;
        let proxy_errors_total = IntCounterVec::new(
            Opts::new(
                "gateway_proxy_errors_total",
                "Gateway proxy pipeline hard failures by stage and kind",
            ),
            &["stage", "kind"],
        )?;
        let detections_total = IntCounterVec::new(
            Opts::new("gateway_detections_total", "Sensitive detections by label"),
            &["direction", "label"],
        )?;
        let auth_failures_total = IntCounterVec::new(
            Opts::new("gateway_auth_failures_total", "Authentication failures"),
            &["reason"],
        )?;
        let review_events_total = IntCounterVec::new(
            Opts::new(
                "gateway_review_events_total",
                "Review workflow events by event type",
            ),
            &["event"],
        )?;
        let processing_fallback_total = IntCounterVec::new(
            Opts::new(
                "gateway_processing_fallback_total",
                "Processing fallback executions by kind",
            ),
            &["kind"],
        )?;
        let payload_processing_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "gateway_payload_processing_duration_seconds",
                "Gateway payload processing latency before upstream emission",
            ),
            &["direction", "kind"],
        )?;
        let upstream_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "gateway_upstream_duration_seconds",
                "Upstream request latency",
            ),
            &["path"],
        )?;
        let active_sessions = IntGauge::new(
            "gateway_active_sessions",
            "Active correlated sessions in cache",
        )?;
        let review_queue_pending = IntGauge::new(
            "gateway_review_queue_pending",
            "Pending review tickets currently queued",
        )?;
        let review_queue_capacity = IntGauge::new(
            "gateway_review_queue_capacity",
            "Configured review queue capacity",
        )?;
        let dependency_configured = IntGaugeVec::new(
            Opts::new(
                "gateway_dependency_configured",
                "Whether an optional dependency is configured",
            ),
            &["dependency"],
        )?;
        let dependency_ready = IntGaugeVec::new(
            Opts::new(
                "gateway_dependency_ready",
                "Whether an optional dependency is ready to serve requests",
            ),
            &["dependency"],
        )?;
        let dependency_status_code = IntGaugeVec::new(
            Opts::new(
                "gateway_dependency_status_code",
                "Last observed dependency healthcheck status code, or 0 when unavailable",
            ),
            &["dependency"],
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(policy_decisions_total.clone()))?;
        registry.register(Box::new(proxy_errors_total.clone()))?;
        registry.register(Box::new(detections_total.clone()))?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        registry.register(Box::new(review_events_total.clone()))?;
        registry.register(Box::new(processing_fallback_total.clone()))?;
        registry.register(Box::new(payload_processing_duration_seconds.clone()))?;
        registry.register(Box::new(upstream_duration_seconds.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;
        registry.register(Box::new(review_queue_pending.clone()))?;
        registry.register(Box::new(review_queue_capacity.clone()))?;
        registry.register(Box::new(dependency_configured.clone()))?;
        registry.register(Box::new(dependency_ready.clone()))?;
        registry.register(Box::new(dependency_status_code.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            policy_decisions_total,
            proxy_errors_total,
            detections_total,
            auth_failures_total,
            review_events_total,
            processing_fallback_total,
            payload_processing_duration_seconds,
            upstream_duration_seconds,
            active_sessions,
            review_queue_pending,
            review_queue_capacity,
            dependency_configured,
            dependency_ready,
            dependency_status_code,
        })
    }

    pub fn request(&self, direction: &str, decision: &str) {
        self.requests_total
            .with_label_values(&[direction, decision])
            .inc();
    }

    pub fn policy_decision(&self, direction: &str, decision: &str, source: &str) {
        self.request(direction, decision);
        self.policy_decisions_total
            .with_label_values(&[direction, decision, source])
            .inc();
    }

    pub fn proxy_error(&self, stage: &str, kind: &str) {
        self.proxy_errors_total
            .with_label_values(&[stage, kind])
            .inc();
    }

    pub fn detection(&self, direction: &str, label: &str) {
        self.detections_total
            .with_label_values(&[direction, label])
            .inc();
    }

    pub fn auth_failure(&self, reason: &str) {
        self.auth_failures_total.with_label_values(&[reason]).inc();
    }

    pub fn review_event(&self, event: &str) {
        self.review_events_total.with_label_values(&[event]).inc();
    }

    pub fn processing_fallback(&self, kind: &str) {
        self.processing_fallback_total
            .with_label_values(&[kind])
            .inc();
    }

    pub fn payload_processing_timer(
        &self,
        direction: &str,
        kind: &str,
    ) -> prometheus::HistogramTimer {
        self.payload_processing_duration_seconds
            .with_label_values(&[direction, kind])
            .start_timer()
    }

    pub fn upstream_timer(&self, path: &str) -> prometheus::HistogramTimer {
        self.upstream_duration_seconds
            .with_label_values(&[path])
            .start_timer()
    }

    pub fn update_sessions(&self, count: usize) {
        self.active_sessions.set(count as i64);
    }

    pub fn update_review_queue(&self, pending: usize, capacity: usize) {
        self.review_queue_pending.set(pending as i64);
        self.review_queue_capacity.set(capacity as i64);
    }

    pub fn update_dependency(
        &self,
        dependency: &str,
        configured: bool,
        ready: bool,
        status_code: Option<i64>,
    ) {
        self.dependency_configured
            .with_label_values(&[dependency])
            .set(if configured { 1 } else { 0 });
        self.dependency_ready
            .with_label_values(&[dependency])
            .set(if ready { 1 } else { 0 });
        self.dependency_status_code
            .with_label_values(&[dependency])
            .set(status_code.unwrap_or_default());
    }

    pub fn snapshot(&self) -> Value {
        let families = self.registry.gather();
        json!({
            "gauges": {
                "active_sessions": gauge_value(&families, "gateway_active_sessions"),
                "review_queue_pending": gauge_value(&families, "gateway_review_queue_pending"),
                "review_queue_capacity": gauge_value(&families, "gateway_review_queue_capacity"),
            },
            "dependencies": dependency_snapshot(&families),
            "counters": {
                "requests_total": counter_map_2(
                    &families,
                    "gateway_requests_total",
                    "direction",
                    "decision",
                ),
                "policy_decisions_total": counter_map_3(
                    &families,
                    "gateway_policy_decisions_total",
                    "direction",
                    "decision",
                    "source",
                ),
                "proxy_errors_total": counter_map_2(
                    &families,
                    "gateway_proxy_errors_total",
                    "stage",
                    "kind",
                ),
                "detections_total": counter_map_2(
                    &families,
                    "gateway_detections_total",
                    "direction",
                    "label",
                ),
                "auth_failures_total": counter_map_1(
                    &families,
                    "gateway_auth_failures_total",
                    "reason",
                ),
                "review_events_total": counter_map_1(
                    &families,
                    "gateway_review_events_total",
                    "event",
                ),
                "processing_fallback_total": counter_map_1(
                    &families,
                    "gateway_processing_fallback_total",
                    "kind",
                ),
            },
            "latency": {
                "payload_processing_duration_seconds": histogram_summary_2(
                    &families,
                    "gateway_payload_processing_duration_seconds",
                    "direction",
                    "kind",
                ),
                "upstream_duration_seconds": histogram_summary(
                    &families,
                    "gateway_upstream_duration_seconds",
                    "path",
                ),
            }
        })
    }
}

pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.refresh_metrics().await;
    let families = state.metrics.registry.gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    match encoder.encode(&families, &mut buffer) {
        Ok(_) => (
            StatusCode::OK,
            [("content-type", encoder.format_type().to_string())],
            buffer,
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode metrics: {err}"),
        )
            .into_response(),
    }
}

fn metric_family<'a>(
    families: &'a [prometheus::proto::MetricFamily],
    name: &str,
) -> Option<&'a prometheus::proto::MetricFamily> {
    families.iter().find(|family| family.name() == name)
}

fn label_value(metric: &prometheus::proto::Metric, name: &str) -> Option<String> {
    metric
        .get_label()
        .iter()
        .find(|label| label.name() == name)
        .map(|label| label.value().to_string())
}

#[inline]
fn counter_value_of(metric: &prometheus::proto::Metric) -> f64 {
    metric
        .get_counter()
        .as_ref()
        .map(|counter| counter.value())
        .unwrap_or_default()
}

#[inline]
fn gauge_value_of(metric: &prometheus::proto::Metric) -> f64 {
    metric
        .get_gauge()
        .as_ref()
        .map(|gauge| gauge.value())
        .unwrap_or_default()
}

fn gauge_value(families: &[prometheus::proto::MetricFamily], name: &str) -> Value {
    let value = metric_family(families, name)
        .and_then(|family| family.get_metric().first())
        .map(gauge_value_of)
        .unwrap_or_default();
    numeric_value(value)
}

fn dependency_snapshot(families: &[prometheus::proto::MetricFamily]) -> Value {
    let mut output = Map::new();
    for dependency in ["opa", "presidio"] {
        output.insert(
            dependency.to_string(),
            json!({
                "configured": labeled_gauge_value(
                    families,
                    "gateway_dependency_configured",
                    "dependency",
                    dependency,
                ),
                "ready": labeled_gauge_value(
                    families,
                    "gateway_dependency_ready",
                    "dependency",
                    dependency,
                ),
                "status_code": labeled_gauge_value(
                    families,
                    "gateway_dependency_status_code",
                    "dependency",
                    dependency,
                ),
            }),
        );
    }
    Value::Object(output)
}

fn labeled_gauge_value(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    label_name: &str,
    label_value_expected: &str,
) -> Value {
    let value = metric_family(families, name)
        .and_then(|family| {
            family.get_metric().iter().find(|metric| {
                label_value(metric, label_name).as_deref() == Some(label_value_expected)
            })
        })
        .map(gauge_value_of)
        .unwrap_or_default();
    numeric_value(value)
}

fn counter_map_1(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    label_name: &str,
) -> Value {
    let mut output = Map::new();
    if let Some(family) = metric_family(families, name) {
        for metric in family.get_metric() {
            if let Some(key) = label_value(metric, label_name) {
                output.insert(key, numeric_value(counter_value_of(metric)));
            }
        }
    }
    Value::Object(output)
}

fn counter_map_2(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    label_1: &str,
    label_2: &str,
) -> Value {
    let mut output = Map::new();
    if let Some(family) = metric_family(families, name) {
        for metric in family.get_metric() {
            let Some(key_1) = label_value(metric, label_1) else {
                continue;
            };
            let Some(key_2) = label_value(metric, label_2) else {
                continue;
            };
            let entry = output
                .entry(key_1)
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(child) = entry else {
                continue;
            };
            child.insert(key_2, numeric_value(counter_value_of(metric)));
        }
    }
    Value::Object(output)
}

fn counter_map_3(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    label_1: &str,
    label_2: &str,
    label_3: &str,
) -> Value {
    let mut output = Map::new();
    if let Some(family) = metric_family(families, name) {
        for metric in family.get_metric() {
            let Some(key_1) = label_value(metric, label_1) else {
                continue;
            };
            let Some(key_2) = label_value(metric, label_2) else {
                continue;
            };
            let Some(key_3) = label_value(metric, label_3) else {
                continue;
            };
            let level_1 = output
                .entry(key_1)
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(level_1_map) = level_1 else {
                continue;
            };
            let level_2 = level_1_map
                .entry(key_2)
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(level_2_map) = level_2 else {
                continue;
            };
            level_2_map.insert(key_3, numeric_value(counter_value_of(metric)));
        }
    }
    Value::Object(output)
}

fn histogram_summary(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    label_name: &str,
) -> Value {
    let mut output = Map::new();
    if let Some(family) = metric_family(families, name) {
        for metric in family.get_metric() {
            let Some(key) = label_value(metric, label_name) else {
                continue;
            };
            let histogram = metric.get_histogram();
            output.insert(
                key,
                json!({
                    "count": histogram.get_sample_count(),
                    "sum_seconds": numeric_value(histogram.get_sample_sum()),
                }),
            );
        }
    }
    Value::Object(output)
}

fn histogram_summary_2(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    label_1: &str,
    label_2: &str,
) -> Value {
    let mut output = Map::new();
    if let Some(family) = metric_family(families, name) {
        for metric in family.get_metric() {
            let Some(key_1) = label_value(metric, label_1) else {
                continue;
            };
            let Some(key_2) = label_value(metric, label_2) else {
                continue;
            };
            let level_1 = output
                .entry(key_1)
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(level_1_map) = level_1 else {
                continue;
            };
            let histogram = metric.get_histogram();
            level_1_map.insert(
                key_2,
                json!({
                    "count": histogram.get_sample_count(),
                    "sum_seconds": numeric_value(histogram.get_sample_sum()),
                }),
            );
        }
    }
    Value::Object(output)
}

fn numeric_value(value: f64) -> Value {
    if value.fract() == 0.0 && value.is_finite() {
        Value::from(value as i64)
    } else if let Some(number) = Number::from_f64(value) {
        Value::Number(number)
    } else {
        Value::Null
    }
}
