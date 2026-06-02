use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use parking_lot::RwLock;
use reqwest::Client;
use serde_json::json;
use thiserror::Error;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

use crate::{
    admin_ui::admin_console,
    attachments::{AttachmentEngine, AttachmentError},
    audit::{AuditSink, AuditStore},
    auth::{AuthError, Authenticator},
    benchmarks::{load_benchmark_surface, promote_benchmark_baseline},
    config::{AppConfig, ConfigError},
    detect::{Detector, DetectorError},
    observability::{Metrics, metrics_handler},
    opa::{OpaAuthorizer, OpaError},
    policy::PolicyEngine,
    presidio::{PresidioAnalyzer, PresidioError},
    proxy::{
        admin_audits, admin_benchmarks_promote, admin_config_summary, admin_detokenize,
        admin_reload, admin_reviews, admin_reviews_resolve, admin_status, dependency_status_opa,
        dependency_status_presidio, proxy_handler,
    },
    review::{ReviewStore, ReviewStoreError},
    session::SessionStore,
    tokenize::{TokenizationError, Tokenizer},
    types::MaskingStrategy,
};

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Detector(#[from] DetectorError),
    #[error(transparent)]
    Opa(#[from] OpaError),
    #[error(transparent)]
    Presidio(#[from] PresidioError),
    #[error(transparent)]
    Tokenization(#[from] TokenizationError),
    #[error(transparent)]
    ReviewStore(#[from] ReviewStoreError),
    #[error(transparent)]
    Attachment(#[from] AttachmentError),
    #[error("invalid upstream base url: {0}")]
    InvalidUpstreamUrl(String),
    #[error("failed to build reqwest client: {0}")]
    BuildClient(reqwest::Error),
    #[error("failed to initialize metrics: {0}")]
    Metrics(prometheus::Error),
    #[error("failed to initialize audit sink: {0}")]
    AuditInit(std::io::Error),
    #[error("runtime io error: {0}")]
    RuntimeIo(std::io::Error),
    #[error("failed to bind listener: {0}")]
    Bind(std::io::Error),
    #[error("server failed: {0}")]
    Serve(std::io::Error),
    #[error("mode is proxy but no proxy config was provided")]
    ProxyConfigMissing,
    #[error("invalid proxy listen address {0}")]
    ProxyListenAddr(String),
    #[error(transparent)]
    Ca(#[from] crate::mitm::ca::CaError),
    #[error("proxy server failed: {0}")]
    Proxy(hudsucker::Error),
}

#[derive(Clone)]
pub struct RuntimeState {
    pub config: AppConfig,
    pub upstream_base_url: Url,
    pub auth: Authenticator,
    pub detector: Detector,
    pub presidio: Option<PresidioAnalyzer>,
    pub policy: PolicyEngine,
    pub opa: Option<OpaAuthorizer>,
    pub tokenizer: Option<Tokenizer>,
    pub attachments: AttachmentEngine,
    pub client: Client,
    pub audit_store: Arc<AuditStore>,
    pub audit: AuditSink,
}

impl RuntimeState {
    fn from_config(config: AppConfig, audit_store: Arc<AuditStore>) -> Result<Self, AppError> {
        ensure_tokenization_configuration(&config)?;
        let upstream_base_url = Url::parse(&config.upstream.base_url)
            .map_err(|_| AppError::InvalidUpstreamUrl(config.upstream.base_url.clone()))?;
        let auth = Authenticator::new(&config.auth)?;
        let detector = Detector::new(&config.detection)?;
        let presidio = match config.detection.presidio.as_ref() {
            Some(presidio_config) => PresidioAnalyzer::from_config(presidio_config)?,
            None => None,
        };
        let policy = PolicyEngine;
        let opa = match config.policy_backend.opa.as_ref() {
            Some(opa_config) => OpaAuthorizer::from_config(opa_config)?,
            None => None,
        };
        let tokenizer = Tokenizer::from_config(config.tokenization.as_ref())?;
        let attachments = AttachmentEngine::from_config(&config.attachments);
        let client = Client::builder()
            .timeout(Duration::from_millis(config.upstream.timeout_ms))
            .connect_timeout(Duration::from_millis(config.upstream.connect_timeout_ms))
            .use_rustls_tls()
            .build()
            .map_err(AppError::BuildClient)?;
        audit_store.set_capacity(config.audit.buffer_capacity);
        let audit = AuditSink::new(
            &config.audit.jsonl_path,
            config.audit.emit_stdout,
            audit_store.clone(),
        )
        .map_err(AppError::AuditInit)?;
        Ok(Self {
            config,
            upstream_base_url,
            auth,
            detector,
            presidio,
            policy,
            opa,
            tokenizer,
            attachments,
            client,
            audit_store,
            audit,
        })
    }
}

fn ensure_tokenization_configuration(config: &AppConfig) -> Result<(), TokenizationError> {
    let tokenization_enabled = config
        .tokenization
        .as_ref()
        .map(|cfg| cfg.enabled)
        .unwrap_or(false);
    let requires_tokenization = config
        .detection
        .rules
        .iter()
        .any(|rule| rule.masking == MaskingStrategy::Tokenize)
        || config
            .detection
            .high_entropy
            .as_ref()
            .map(|rule| rule.masking == MaskingStrategy::Tokenize)
            .unwrap_or(false)
        || config
            .detection
            .presidio
            .as_ref()
            .map(|presidio| {
                presidio
                    .entities
                    .iter()
                    .any(|entity| entity.masking == MaskingStrategy::Tokenize)
            })
            .unwrap_or(false);

    if requires_tokenization && !tokenization_enabled {
        return Err(TokenizationError::RequiredButDisabled);
    }
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub runtime: Arc<RwLock<Arc<RuntimeState>>>,
    pub sessions: Arc<SessionStore>,
    pub reviews: Arc<ReviewStore>,
    pub metrics: Arc<Metrics>,
    pub audit_store: Arc<AuditStore>,
}

impl AppState {
    pub fn current(&self) -> Arc<RuntimeState> {
        self.runtime.read().clone()
    }

    pub async fn refresh_metrics(&self) {
        let runtime = self.current();
        let sessions = self.sessions.active_sessions(&runtime.config.session);
        self.metrics.update_sessions(sessions);
        self.metrics
            .update_review_queue(self.reviews.pending_count(), runtime.config.review.capacity);

        let opa_status = dependency_status_opa(runtime.opa.as_ref()).await;
        self.metrics.update_dependency(
            "opa",
            dependency_configured(&opa_status),
            dependency_reachable(&opa_status),
            dependency_status_code(&opa_status),
        );

        let presidio_status = dependency_status_presidio(runtime.presidio.as_ref()).await;
        self.metrics.update_dependency(
            "presidio",
            dependency_configured(&presidio_status),
            dependency_reachable(&presidio_status),
            dependency_status_code(&presidio_status),
        );
    }

    pub fn reload(&self) -> Result<(), AppError> {
        let config = AppConfig::load(&self.config_path)?;
        let runtime = Arc::new(RuntimeState::from_config(config, self.audit_store.clone())?);
        *self.runtime.write() = runtime;
        Ok(())
    }

    pub fn benchmark_surface(&self) -> crate::benchmarks::BenchmarkSurface {
        let runtime = self.current();
        load_benchmark_surface(&runtime.config.benchmarks)
    }

    pub fn promote_benchmark_baseline(
        &self,
    ) -> Result<
        crate::benchmarks::BenchmarkBaselinePromotion,
        crate::benchmarks::BenchmarkSummaryError,
    > {
        let runtime = self.current();
        promote_benchmark_baseline(&runtime.config.benchmarks)
    }
}

pub fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .try_init();
}

pub fn build_state(config_path: PathBuf) -> Result<Arc<AppState>, AppError> {
    let config = AppConfig::load(&config_path)?;
    let audit_store = Arc::new(AuditStore::new(config.audit.buffer_capacity));
    let review_capacity = config.review.capacity;
    let review_path = config.review.jsonl_path.clone();
    let runtime = Arc::new(RuntimeState::from_config(config, audit_store.clone())?);
    let metrics = Arc::new(Metrics::new().map_err(AppError::Metrics)?);
    Ok(Arc::new(AppState {
        config_path,
        runtime: Arc::new(RwLock::new(runtime)),
        sessions: Arc::new(SessionStore::new()),
        reviews: Arc::new(ReviewStore::new(review_path, review_capacity)?),
        metrics,
        audit_store,
    }))
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/admin", get(admin_console))
        .route("/admin/", get(admin_console))
        .route("/admin/status", get(admin_status))
        .route("/admin/config-summary", get(admin_config_summary))
        .route("/admin/audits", get(admin_audits))
        .route("/admin/reviews", get(admin_reviews))
        .route("/admin/reviews/resolve", post(admin_reviews_resolve))
        .route("/admin/detokenize", post(admin_detokenize))
        .route("/admin/reload", post(admin_reload))
        .route("/admin/benchmarks/promote", post(admin_benchmarks_promote))
        .fallback(proxy_handler)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response<Body> {
    let active = state.current();
    let sessions = state.sessions.active_sessions(&active.config.session);
    let opa_status = dependency_status_opa(active.opa.as_ref()).await;
    let presidio_status = dependency_status_presidio(active.presidio.as_ref()).await;
    state.metrics.update_sessions(sessions);
    state
        .metrics
        .update_review_queue(state.reviews.pending_count(), active.config.review.capacity);
    let opa_ready = dependency_ready(&opa_status);
    state.metrics.update_dependency(
        "opa",
        dependency_configured(&opa_status),
        dependency_reachable(&opa_status),
        dependency_status_code(&opa_status),
    );
    let presidio_ready = dependency_ready(&presidio_status);
    state.metrics.update_dependency(
        "presidio",
        dependency_configured(&presidio_status),
        dependency_reachable(&presidio_status),
        dependency_status_code(&presidio_status),
    );
    let ready = opa_ready && presidio_ready;
    let readiness = json!({
        "status": "ready",
        "upstream": active.upstream_base_url.as_str(),
        "sessions": sessions,
        "audit_buffer": {
            "len": state.audit_store.len(),
            "capacity": state.audit_store.capacity(),
        },
        "dependencies": {
            "opa": opa_status,
            "presidio": presidio_status,
        }
    });
    Json(json!({
        "ready": ready,
        "runtime": readiness,
    }))
    .into_response()
}

fn dependency_configured(status: &serde_json::Value) -> bool {
    status
        .get("configured")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn dependency_ready(status: &serde_json::Value) -> bool {
    match (
        status.get("configured").and_then(|value| value.as_bool()),
        status.get("reachable").and_then(|value| value.as_bool()),
    ) {
        (Some(true), Some(reachable)) => reachable,
        _ => true,
    }
}

fn dependency_reachable(status: &serde_json::Value) -> bool {
    match (
        status.get("configured").and_then(|value| value.as_bool()),
        status.get("reachable").and_then(|value| value.as_bool()),
    ) {
        (Some(true), Some(reachable)) => reachable,
        _ => false,
    }
}

fn dependency_status_code(status: &serde_json::Value) -> Option<i64> {
    status.get("status_code").and_then(|value| value.as_i64())
}

pub async fn run(config_path: PathBuf) -> Result<(), AppError> {
    init_tracing();
    let state = build_state(config_path)?;
    crate::proxy_mode::serve(state).await
}

/// Serve the reverse-proxy (axum) data plane. This is the compat shell; the
/// transparent MITM proxy lives in [`crate::proxy_mode`].
pub async fn serve_reverse(state: Arc<AppState>) -> Result<(), AppError> {
    let bind = state.current().config.server.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(AppError::Bind)?;
    tracing::info!(bind = %bind, "context-gurd listening (reverse mode)");
    axum::serve(listener, build_router(state))
        .await
        .map_err(|err| AppError::Serve(std::io::Error::other(err)))
}
