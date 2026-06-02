use std::{collections::HashSet, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{Clearance, DecisionAction, MaskingStrategy, Severity};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse yaml config {path}: {source}")]
    ParseYaml {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to parse toml config {path}: {source}")]
    ParseToml {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("unsupported config extension for {0}, expected .yaml/.yml/.toml")]
    UnsupportedExtension(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppConfig {
    /// Operating mode. Defaults to `Reverse` so every existing config keeps working.
    #[serde(default)]
    pub mode: Mode,
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub auth: AuthConfig,
    pub detection: DetectionConfig,
    #[serde(default)]
    pub attachments: AttachmentConfig,
    #[serde(default)]
    pub tokenization: Option<TokenizationConfig>,
    #[serde(default)]
    pub policy_backend: PolicyBackendConfig,
    pub session: SessionConfig,
    pub response_filtering: ResponseFilteringConfig,
    #[serde(default)]
    pub review: ReviewConfig,
    #[serde(default)]
    pub benchmarks: BenchmarkConfig,
    pub audit: AuditConfig,
    /// Transparent forward MITM proxy settings. Activated when `mode = proxy`.
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
}

/// How the gateway accepts traffic.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Existing axum reverse proxy: callers point their base URL at us (compat shell).
    #[default]
    Reverse,
    /// Transparent forward MITM proxy: intercept LLM traffic system-wide (main line).
    Proxy,
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let path_str = path.display().to_string();
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("yaml") | Some("yml") => {
                serde_yaml::from_str(&raw).map_err(|source| ConfigError::ParseYaml {
                    path: path_str,
                    source,
                })
            }
            Some("toml") => toml::from_str(&raw).map_err(|source| ConfigError::ParseToml {
                path: path_str,
                source,
            }),
            _ => Err(ConfigError::UnsupportedExtension(path_str)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind: String,
    #[serde(default = "default_request_body_limit_bytes")]
    pub request_body_limit_bytes: usize,
}

fn default_request_body_limit_bytes() -> usize {
    1024 * 1024
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub base_url: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub auth_value_env: Option<String>,
    #[serde(default)]
    pub forward_headers: HashSet<String>,
}

fn default_timeout_ms() -> u64 {
    60_000
}

fn default_connect_timeout_ms() -> u64 {
    5_000
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_header_name")]
    pub header_name: String,
    #[serde(default)]
    pub principals: Vec<PrincipalConfig>,
}

fn default_auth_header_name() -> String {
    "authorization".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrincipalConfig {
    pub name: String,
    pub tenant_id: String,
    pub role: String,
    #[serde(default)]
    pub clearance: Clearance,
    pub secret_sha256: String,
    #[serde(default)]
    pub allowed_labels: HashSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DetectionConfig {
    #[serde(default)]
    pub ignore_json_pointers: HashSet<String>,
    #[serde(default)]
    pub high_entropy: Option<HighEntropyRuleConfig>,
    #[serde(default)]
    pub presidio: Option<PresidioConfig>,
    #[serde(default)]
    pub rules: Vec<DetectionRuleConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttachmentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_attachment_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_attachment_max_text_chars")]
    pub max_text_chars: usize,
    #[serde(default = "default_attachment_media_types")]
    pub allowed_media_types: Vec<String>,
}

impl Default for AttachmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: default_attachment_max_bytes(),
            max_text_chars: default_attachment_max_text_chars(),
            allowed_media_types: default_attachment_media_types(),
        }
    }
}

fn default_attachment_max_bytes() -> usize {
    5 * 1024 * 1024
}

fn default_attachment_max_text_chars() -> usize {
    32_768
}

fn default_attachment_media_types() -> Vec<String> {
    vec![
        "text/*".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
        "text/csv".to_string(),
        "application/pdf".to_string(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation".to_string(),
    ]
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HighEntropyRuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_entropy_length")]
    pub min_length: usize,
    #[serde(default = "default_entropy_score")]
    pub min_entropy: f64,
    pub label: String,
    #[serde(default = "default_high_entropy_severity")]
    pub severity: Severity,
    pub authorized_action: DecisionAction,
    pub unauthorized_action: DecisionAction,
    #[serde(default)]
    pub min_clearance: Clearance,
    pub masking: MaskingStrategy,
}

fn default_true() -> bool {
    true
}

fn default_entropy_length() -> usize {
    20
}

fn default_entropy_score() -> f64 {
    3.6
}

fn default_high_entropy_severity() -> Severity {
    Severity::High
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DetectionRuleConfig {
    pub name: String,
    pub label: String,
    pub pattern: String,
    #[serde(default = "default_rule_severity")]
    pub severity: Severity,
    pub authorized_action: DecisionAction,
    pub unauthorized_action: DecisionAction,
    #[serde(default)]
    pub min_clearance: Clearance,
    pub masking: MaskingStrategy,
}

fn default_rule_severity() -> Severity {
    Severity::Medium
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresidioConfig {
    #[serde(default)]
    pub enabled: bool,
    pub analyzer_url: String,
    #[serde(default)]
    pub healthcheck_url: Option<String>,
    #[serde(default = "default_presidio_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_presidio_language")]
    pub language: String,
    #[serde(default)]
    pub entities: Vec<PresidioEntityConfig>,
}

fn default_presidio_timeout_ms() -> u64 {
    250
}

fn default_presidio_language() -> String {
    "en".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresidioEntityConfig {
    pub entity_type: String,
    pub label: String,
    #[serde(default = "default_rule_severity")]
    pub severity: Severity,
    pub authorized_action: DecisionAction,
    pub unauthorized_action: DecisionAction,
    #[serde(default)]
    pub min_clearance: Clearance,
    pub masking: MaskingStrategy,
    #[serde(default = "default_presidio_min_score")]
    pub min_score: f64,
}

fn default_presidio_min_score() -> f64 {
    0.35
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenizationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tokenization_key_env")]
    pub key_env: String,
    #[serde(default = "default_tokenization_prefix")]
    pub token_prefix: String,
}

fn default_tokenization_key_env() -> String {
    "CONTEXT_GURD_TOKENIZATION_KEY".to_string()
}

fn default_tokenization_prefix() -> String {
    "CGT1".to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PolicyBackendConfig {
    #[serde(default)]
    pub opa: Option<OpaConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaConfig {
    #[serde(default)]
    pub enabled: bool,
    pub url: String,
    #[serde(default)]
    pub healthcheck_url: Option<String>,
    #[serde(default = "default_opa_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_true")]
    pub fail_open: bool,
}

fn default_opa_timeout_ms() -> u64 {
    150
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_session_header_name")]
    pub header_name: String,
    #[serde(default = "default_session_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_session_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_correlation_threshold")]
    pub correlation_threshold: usize,
    #[serde(default = "default_session_trigger_action")]
    pub trigger_action: DecisionAction,
}

fn default_session_header_name() -> String {
    "x-session-id".to_string()
}

fn default_session_ttl_secs() -> u64 {
    1800
}

fn default_session_max_entries() -> usize {
    5000
}

fn default_correlation_threshold() -> usize {
    2
}

fn default_session_trigger_action() -> DecisionAction {
    DecisionAction::Review
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseFilteringConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub scan_json: bool,
    #[serde(default = "default_true")]
    pub scan_sse: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReviewConfig {
    #[serde(default = "default_review_capacity")]
    pub capacity: usize,
    #[serde(default = "default_review_preview_chars")]
    pub preview_chars: usize,
    #[serde(default = "default_review_approval_ttl_secs")]
    pub approval_ttl_secs: u64,
    #[serde(default = "default_review_jsonl_path")]
    pub jsonl_path: String,
}

fn default_review_capacity() -> usize {
    1000
}

fn default_review_preview_chars() -> usize {
    256
}

fn default_review_approval_ttl_secs() -> u64 {
    900
}

fn default_review_jsonl_path() -> String {
    "./review.jsonl".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BenchmarkConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_benchmark_summary_json_path")]
    pub summary_json_path: String,
    #[serde(default)]
    pub baseline_summary_json_path: Option<String>,
    #[serde(default)]
    pub gate_report_json_path: Option<String>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            summary_json_path: default_benchmark_summary_json_path(),
            baseline_summary_json_path: Some(default_benchmark_baseline_json_path()),
            gate_report_json_path: Some(default_benchmark_gate_report_json_path()),
        }
    }
}

fn default_benchmark_summary_json_path() -> String {
    "./.tmp-smoke/bench-matrix/summary.json".to_string()
}

fn default_benchmark_baseline_json_path() -> String {
    "./.tmp-smoke/bench-matrix/baseline.json".to_string()
}

fn default_benchmark_gate_report_json_path() -> String {
    "./.tmp-smoke/bench-matrix/gate-report.json".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditConfig {
    pub jsonl_path: String,
    #[serde(default)]
    pub emit_stdout: bool,
    #[serde(default = "default_audit_buffer_capacity")]
    pub buffer_capacity: usize,
}

fn default_audit_buffer_capacity() -> usize {
    1000
}

/// Transparent forward MITM proxy configuration (mode = proxy).
///
/// Only LLM-provider SNI in `intercept` are TLS-terminated and run through the
/// detection/redaction pipeline; everything else is an opaque passthrough tunnel.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_listen_addr")]
    pub listen_addr: String,
    /// Directory holding the local root CA. Key is generated on first run, chmod 600, never exported.
    #[serde(default = "default_ca_dir")]
    pub ca_dir: String,
    #[serde(default)]
    pub ca_key_path: Option<String>,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    /// Env var that overrides the CA key path, mirroring the tokenization key-env convention.
    #[serde(default = "default_ca_key_path_env")]
    pub ca_key_path_env: String,
    #[serde(default = "default_leaf_ttl_days")]
    pub leaf_ttl_days: u32,
    #[serde(default = "default_cert_cache_size")]
    pub cert_cache_size: u64,
    /// Tier-1 allowlist: hosts to TLS-terminate and run the pipeline on.
    #[serde(default = "default_intercept_hosts")]
    pub intercept: Vec<HostPattern>,
    /// Tier-2 explicit passthrough: web chat, auth flows, known cert-pinned apps.
    #[serde(default = "default_passthrough_hosts")]
    pub passthrough: Vec<HostPattern>,
    /// Action for SNI matching neither list. Defaults to passthrough (fail-open).
    #[serde(default)]
    pub default_action: ProxyAction,
    /// Hosts whose upstream-signed request body must not be modified (e.g. AWS
    /// SigV4): intercepted for detection/audit, but the request body is never
    /// redacted (that would invalidate the signature → 4xx).
    #[serde(default = "default_signs_body_hosts")]
    pub signs_body: Vec<HostPattern>,
    #[serde(default)]
    pub per_app_rules: Vec<PerAppRule>,
    #[serde(default)]
    pub pin_fallback: PinFallbackConfig,
    /// Optional signed, hot-updatable remote rule-set (D4).
    #[serde(default)]
    pub ruleset_url: Option<String>,
    /// Hex-encoded ed25519 public key that signs the remote rule-set. Required
    /// for `ruleset_url` to take effect (unverified feeds are rejected).
    #[serde(default)]
    pub ruleset_pubkey: Option<String>,
    #[serde(default = "default_ruleset_poll_secs")]
    pub ruleset_poll_secs: u64,
}

/// A host-matching rule for the intercept/passthrough lists.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum HostPattern {
    /// Exact host match, e.g. `api.openai.com`.
    Exact(String),
    /// Single-level wildcard, e.g. `*.openai.azure.com`.
    Wildcard(String),
    /// Anchored regex over the full host, e.g. `^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$`.
    Regex(String),
}

/// What to do with an intercepted connection.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAction {
    /// TLS-terminate and run the detection/redaction pipeline.
    Intercept,
    /// Opaque TCP tunnel: no cert signed, no decrypt, zero privacy contact.
    #[default]
    Passthrough,
}

/// Per-client-process rule override (best-effort process attribution).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PerAppRule {
    pub process: String,
    pub action: ProxyAction,
}

/// Behaviour when a client rejects our leaf cert (cert-pinned target).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PinFallbackConfig {
    #[serde(default = "default_pin_block_ttl_secs")]
    pub block_ttl_secs: u64,
    #[serde(default = "default_true")]
    pub auto_splice_on_alert: bool,
}

impl Default for PinFallbackConfig {
    fn default() -> Self {
        Self {
            block_ttl_secs: default_pin_block_ttl_secs(),
            auto_splice_on_alert: true,
        }
    }
}

fn default_proxy_listen_addr() -> String {
    "127.0.0.1:8888".to_string()
}

fn default_ca_dir() -> String {
    "./certs".to_string()
}

fn default_ca_key_path_env() -> String {
    "CONTEXT_GURD_PROXY_CA_KEY_PATH".to_string()
}

fn default_leaf_ttl_days() -> u32 {
    7
}

fn default_cert_cache_size() -> u64 {
    1000
}

fn default_ruleset_poll_secs() -> u64 {
    300
}

fn default_pin_block_ttl_secs() -> u64 {
    300
}

/// Baked-in offline fallback intercept list (LLM provider API hostnames).
///
/// Also used as the **immutable floor** for hot-updated rule-sets: these hosts
/// are always intercepted, so a rolled-back, minimal, or hijacked-but-signed
/// rule-set can never stop scanning the core providers.
pub(crate) fn default_intercept_hosts() -> Vec<HostPattern> {
    vec![
        HostPattern::Exact("api.openai.com".into()),
        HostPattern::Wildcard("*.openai.azure.com".into()),
        HostPattern::Wildcard("*.cognitiveservices.azure.com".into()),
        HostPattern::Wildcard("*.services.ai.azure.com".into()),
        HostPattern::Exact("api.anthropic.com".into()),
        HostPattern::Exact("generativelanguage.googleapis.com".into()),
        HostPattern::Exact("aiplatform.googleapis.com".into()),
        // AWS Bedrock (bedrock-runtime.*) signs the request body with SigV4, so
        // it is also listed in `default_signs_body_hosts`: intercepted for
        // detection/audit but with the request body preserved (never redacted).
        HostPattern::Regex(r"^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$".into()),
        HostPattern::Exact("api.deepseek.com".into()),
        HostPattern::Exact("api.moonshot.ai".into()),
        HostPattern::Exact("api.moonshot.cn".into()),
        HostPattern::Exact("api.groq.com".into()),
        HostPattern::Exact("api.mistral.ai".into()),
        HostPattern::Exact("api.cohere.com".into()),
        HostPattern::Exact("api.x.ai".into()),
        HostPattern::Exact("openrouter.ai".into()),
    ]
}

/// Baked-in offline fallback passthrough list (web chat / auth / pinned apps).
fn default_passthrough_hosts() -> Vec<HostPattern> {
    vec![
        HostPattern::Exact("chatgpt.com".into()),
        HostPattern::Wildcard("*.chatgpt.com".into()),
        HostPattern::Exact("chat.openai.com".into()),
        HostPattern::Wildcard("*.auth0.com".into()),
        HostPattern::Exact("challenges.cloudflare.com".into()),
        HostPattern::Exact("desktop.chat.openai.com".into()),
        HostPattern::Exact("ios.chat.openai.com".into()),
        HostPattern::Exact("android.chat.openai.com".into()),
        HostPattern::Exact("claude.ai".into()),
        HostPattern::Wildcard("*.claude.com".into()),
        HostPattern::Exact("gemini.google.com".into()),
        HostPattern::Exact("aistudio.google.com".into()),
    ]
}

/// Hosts whose upstream-signed request body must be preserved (intercept for
/// detection/audit, never redact the request body).
///
/// Also the immutable signs_body floor for hot-updated rule-sets: a rule-set
/// can add signs_body hosts but can never drop a baked-in one (so e.g. Bedrock
/// stays signature-safe regardless of the feed).
pub(crate) fn default_signs_body_hosts() -> Vec<HostPattern> {
    vec![
        HostPattern::Regex(r"^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$".into()),
        HostPattern::Regex(r"^bedrock-mantle\.[a-z0-9-]+\.api\.aws$".into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, Mode, ProxyAction};

    #[test]
    fn loads_opa_policy_backend_config() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
server:
  bind: 127.0.0.1:8080
upstream:
  base_url: https://api.openai.com/
auth:
  principals: []
detection:
  rules: []
tokenization:
  enabled: true
  key_env: CUSTOM_TOKEN_KEY
  token_prefix: TKN1
policy_backend:
  opa:
    enabled: true
    url: http://127.0.0.1:8181/v1/data/llm/privacy/decision
    healthcheck_url: http://127.0.0.1:8181/health
    timeout_ms: 123
    fail_open: false
session:
  enabled: false
response_filtering:
  enabled: true
  scan_json: true
  scan_sse: true
attachments:
  enabled: true
  max_bytes: 2048
  max_text_chars: 4096
review:
  capacity: 77
  preview_chars: 88
  approval_ttl_secs: 120
  jsonl_path: ./review.log
benchmarks:
  enabled: true
  summary_json_path: ./bench-matrix/summary.json
  baseline_summary_json_path: ./bench-matrix/baseline.json
audit:
  jsonl_path: ./audit.log
  buffer_capacity: 77
"#,
        )
        .unwrap();

        let opa = config.policy_backend.opa.expect("opa config");
        assert!(opa.enabled);
        assert_eq!(opa.timeout_ms, 123);
        assert!(!opa.fail_open);
        assert_eq!(
            opa.healthcheck_url.as_deref(),
            Some("http://127.0.0.1:8181/health")
        );
        assert_eq!(config.audit.buffer_capacity, 77);
        assert_eq!(config.review.capacity, 77);
        assert_eq!(config.review.preview_chars, 88);
        assert!(config.attachments.enabled);
        assert_eq!(config.attachments.max_bytes, 2048);
        assert_eq!(config.attachments.max_text_chars, 4096);
        assert_eq!(config.review.approval_ttl_secs, 120);
        assert_eq!(config.review.jsonl_path, "./review.log");
        assert!(config.benchmarks.enabled);
        assert_eq!(
            config.benchmarks.summary_json_path,
            "./bench-matrix/summary.json"
        );
        assert_eq!(
            config.benchmarks.baseline_summary_json_path.as_deref(),
            Some("./bench-matrix/baseline.json")
        );
        let tokenization = config.tokenization.expect("tokenization config");
        assert!(tokenization.enabled);
        assert_eq!(tokenization.key_env, "CUSTOM_TOKEN_KEY");
        assert_eq!(tokenization.token_prefix, "TKN1");
    }

    #[test]
    fn defaults_to_reverse_mode_without_proxy() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
server:
  bind: 127.0.0.1:8080
upstream:
  base_url: https://api.openai.com/
auth:
  principals: []
detection:
  rules: []
session:
  enabled: false
response_filtering:
  enabled: true
audit:
  jsonl_path: ./audit.log
"#,
        )
        .unwrap();

        assert_eq!(config.mode, Mode::Reverse);
        assert!(config.proxy.is_none());
    }

    #[test]
    fn loads_proxy_mode_config() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
mode: proxy
server:
  bind: 127.0.0.1:8080
upstream:
  base_url: https://api.openai.com/
auth:
  principals: []
detection:
  rules: []
session:
  enabled: false
response_filtering:
  enabled: true
audit:
  jsonl_path: ./audit.log
proxy:
  listen_addr: 127.0.0.1:8888
  intercept:
    - kind: exact
      value: api.openai.com
    - kind: wildcard
      value: "*.openai.azure.com"
  passthrough:
    - kind: exact
      value: claude.ai
  default_action: passthrough
"#,
        )
        .unwrap();

        assert_eq!(config.mode, Mode::Proxy);
        let proxy = config.proxy.expect("proxy config");
        assert_eq!(proxy.listen_addr, "127.0.0.1:8888");
        assert_eq!(proxy.default_action, ProxyAction::Passthrough);
        assert_eq!(proxy.intercept.len(), 2);
        assert_eq!(proxy.passthrough.len(), 1);
        // defaults still populate untouched fields
        assert_eq!(proxy.leaf_ttl_days, 7);
        assert_eq!(proxy.pin_fallback.block_ttl_secs, 300);
    }

    #[test]
    fn proxy_defaults_populate_baked_in_lists() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
mode: proxy
server:
  bind: 127.0.0.1:8080
upstream:
  base_url: https://api.openai.com/
auth:
  principals: []
detection:
  rules: []
session:
  enabled: false
response_filtering:
  enabled: true
audit:
  jsonl_path: ./audit.log
proxy: {}
"#,
        )
        .unwrap();

        let proxy = config.proxy.expect("proxy config");
        assert_eq!(proxy.listen_addr, "127.0.0.1:8888");
        assert!(!proxy.intercept.is_empty(), "baked-in intercept list");
        assert!(!proxy.passthrough.is_empty(), "baked-in passthrough list");
        assert_eq!(proxy.default_action, ProxyAction::Passthrough);
    }
}
