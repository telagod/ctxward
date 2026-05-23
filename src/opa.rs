use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    auth::Principal,
    config::OpaConfig,
    policy::{PolicyOutcome, ResolvedFinding},
    types::{DecisionAction, Direction},
};

#[derive(Debug, Error)]
pub enum OpaError {
    #[error("failed to build opa client: {0}")]
    BuildClient(reqwest::Error),
    #[error("opa request failed: {0}")]
    Request(reqwest::Error),
    #[error("opa returned non-success status {status}: {body}")]
    Response { status: u16, body: String },
}

#[derive(Clone)]
pub struct OpaAuthorizer {
    client: Client,
    url: String,
    healthcheck_url: String,
    fail_open: bool,
    timeout_ms: u64,
}

impl OpaAuthorizer {
    pub fn from_config(config: &OpaConfig) -> Result<Option<Self>, OpaError> {
        if !config.enabled {
            return Ok(None);
        }
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .use_rustls_tls()
            .build()
            .map_err(OpaError::BuildClient)?;
        Ok(Some(Self {
            client,
            url: config.url.clone(),
            healthcheck_url: config
                .healthcheck_url
                .clone()
                .unwrap_or_else(|| format!("{}/health", config.url.trim_end_matches('/'))),
            fail_open: config.fail_open,
            timeout_ms: config.timeout_ms,
        }))
    }

    pub fn fail_open(&self) -> bool {
        self.fail_open
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn healthcheck(&self) -> Result<u16, OpaError> {
        let response = self
            .client
            .get(&self.healthcheck_url)
            .send()
            .await
            .map_err(OpaError::Request)?;
        Ok(response.status().as_u16())
    }

    pub async fn evaluate(&self, input: OpaInput<'_>) -> Result<Option<OpaDecision>, OpaError> {
        let response = self
            .client
            .post(&self.url)
            .json(&OpaEnvelope { input })
            .send()
            .await
            .map_err(OpaError::Request)?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(OpaError::Response {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: OpaResponse = response.json().await.map_err(OpaError::Request)?;
        Ok(parsed.result)
    }
}

#[derive(Serialize)]
struct OpaEnvelope<'a> {
    input: OpaInput<'a>,
}

#[derive(Clone, Serialize)]
pub struct OpaInput<'a> {
    pub principal: &'a Principal,
    pub direction: Direction,
    pub path: &'a str,
    pub session_escalated: bool,
    pub current_decision: DecisionAction,
    pub findings: &'a [ResolvedFinding],
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpaResponse {
    pub result: Option<OpaDecision>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpaDecision {
    pub action: DecisionAction,
    #[serde(default)]
    pub reason: Option<String>,
}

impl OpaDecision {
    pub fn merge(self, base: PolicyOutcome) -> PolicyOutcome {
        PolicyOutcome {
            decision: base.decision.combine(self.action),
            findings: base.findings,
            source: "opa".to_string(),
            reason: self.reason,
        }
    }
}
