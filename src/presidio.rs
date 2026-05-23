use std::{collections::HashMap, time::Duration};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::{PresidioConfig, PresidioEntityConfig},
    detect::{DetectionFinding, RuleMetadata},
};

#[derive(Debug, Error)]
pub enum PresidioError {
    #[error("failed to build presidio client: {0}")]
    BuildClient(reqwest::Error),
    #[error("presidio request failed: {0}")]
    Request(reqwest::Error),
    #[error("presidio returned non-success status {status}: {body}")]
    Response { status: u16, body: String },
}

#[derive(Clone)]
pub struct PresidioAnalyzer {
    client: Client,
    analyzer_url: String,
    healthcheck_url: String,
    language: String,
    entity_map: HashMap<String, PresidioEntityConfig>,
    timeout_ms: u64,
}

impl PresidioAnalyzer {
    pub fn from_config(config: &PresidioConfig) -> Result<Option<Self>, PresidioError> {
        if !config.enabled {
            return Ok(None);
        }
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .use_rustls_tls()
            .build()
            .map_err(PresidioError::BuildClient)?;

        Ok(Some(Self {
            client,
            analyzer_url: config.analyzer_url.clone(),
            healthcheck_url: config
                .healthcheck_url
                .clone()
                .unwrap_or_else(|| config.analyzer_url.clone()),
            language: config.language.clone(),
            entity_map: config
                .entities
                .iter()
                .cloned()
                .map(|entity| (entity.entity_type.clone(), entity))
                .collect(),
            timeout_ms: config.timeout_ms,
        }))
    }

    pub fn analyzer_url(&self) -> &str {
        &self.analyzer_url
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub async fn healthcheck(&self) -> Result<u16, PresidioError> {
        let response = self
            .client
            .get(&self.healthcheck_url)
            .send()
            .await
            .map_err(PresidioError::Request)?;
        Ok(response.status().as_u16())
    }

    pub async fn analyze(
        &self,
        text: &str,
        pointer: &str,
    ) -> Result<Vec<DetectionFinding>, PresidioError> {
        if text.trim().is_empty() || self.entity_map.is_empty() {
            return Ok(Vec::new());
        }

        let body = AnalyzeRequest {
            text,
            language: &self.language,
            entities: self.entity_map.keys().cloned().collect(),
        };
        let response = self
            .client
            .post(&self.analyzer_url)
            .json(&body)
            .send()
            .await
            .map_err(PresidioError::Request)?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(PresidioError::Response { status, body });
        }

        let items: Vec<AnalyzerResult> = response.json().await.map_err(PresidioError::Request)?;
        let char_boundaries = character_boundaries(text);
        let mut findings = Vec::new();
        for item in items {
            let Some(entity) = self.entity_map.get(&item.entity_type) else {
                continue;
            };
            if item.score < entity.min_score {
                continue;
            }
            let start = char_offset_to_byte_index(&char_boundaries, item.start, text.len());
            let end = char_offset_to_byte_index(&char_boundaries, item.end, text.len());
            if start >= end {
                continue;
            }
            let matched = text[start..end].to_string();
            findings.push(DetectionFinding::new(
                start,
                end,
                matched,
                pointer.to_string(),
                RuleMetadata {
                    rule_name: format!("presidio:{}", entity.entity_type),
                    label: entity.label.clone(),
                    severity: entity.severity,
                    authorized_action: entity.authorized_action,
                    unauthorized_action: entity.unauthorized_action,
                    min_clearance: entity.min_clearance,
                    masking: entity.masking,
                },
            ));
        }

        Ok(findings)
    }
}

fn character_boundaries(text: &str) -> Vec<usize> {
    let mut offsets = text
        .char_indices()
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    offsets.push(text.len());
    offsets
}

fn char_offset_to_byte_index(boundaries: &[usize], char_offset: usize, text_len: usize) -> usize {
    boundaries.get(char_offset).copied().unwrap_or(text_len)
}

#[derive(Serialize)]
struct AnalyzeRequest<'a> {
    text: &'a str,
    language: &'a str,
    entities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AnalyzerResult {
    start: usize,
    end: usize,
    score: f64,
    entity_type: String,
}

#[cfg(test)]
mod tests {
    use super::{char_offset_to_byte_index, character_boundaries};

    #[test]
    fn converts_presidio_character_offsets_to_utf8_byte_offsets() {
        let text = "邮箱 admin@example.com";
        let boundaries = character_boundaries(text);

        let start = char_offset_to_byte_index(&boundaries, 3, text.len());
        let end = char_offset_to_byte_index(&boundaries, 20, text.len());

        assert_eq!(&text[start..end], "admin@example.com");
    }

    #[test]
    fn clamps_out_of_range_character_offsets() {
        let text = "邮箱 admin@example.com";
        let boundaries = character_boundaries(text);

        let start = char_offset_to_byte_index(&boundaries, 999, text.len());
        let end = char_offset_to_byte_index(&boundaries, 1000, text.len());

        assert_eq!(start, text.len());
        assert_eq!(end, text.len());
    }
}
