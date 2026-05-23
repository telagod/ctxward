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

#[cfg(test)]
mod tests {
    use super::AppConfig;

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
}
