use std::collections::HashSet;

use hex::ToHex;
use regex::{Regex, RegexSet};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    config::{DetectionConfig, DetectionRuleConfig, HighEntropyRuleConfig},
    types::{Clearance, DecisionAction, MaskingStrategy, Severity},
};

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("invalid detection regex for rule {rule}: {source}")]
    InvalidRegex {
        rule: String,
        #[source]
        source: regex::Error,
    },
}

#[derive(Clone, Debug)]
pub struct RuleMetadata {
    pub rule_name: String,
    pub label: String,
    pub severity: Severity,
    pub authorized_action: DecisionAction,
    pub unauthorized_action: DecisionAction,
    pub min_clearance: Clearance,
    pub masking: MaskingStrategy,
}

#[derive(Clone, Debug)]
pub struct DetectionFinding {
    pub start: usize,
    pub end: usize,
    pub matched: String,
    pub matched_sha256: String,
    pub pointer: String,
    pub metadata: RuleMetadata,
}

impl DetectionFinding {
    pub fn new(
        start: usize,
        end: usize,
        matched: String,
        pointer: String,
        metadata: RuleMetadata,
    ) -> Self {
        Self {
            start,
            end,
            matched_sha256: sha256_hex(&matched),
            matched,
            pointer,
            metadata,
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledRule {
    regex: Regex,
    metadata: RuleMetadata,
}

#[derive(Clone, Debug)]
pub struct Detector {
    ignore_json_pointers: HashSet<String>,
    rules: Vec<CompiledRule>,
    rule_set: Option<RegexSet>,
    high_entropy: Option<CompiledHighEntropyRule>,
}

#[derive(Clone, Debug)]
struct CompiledHighEntropyRule {
    min_length: usize,
    min_entropy: f64,
    metadata: RuleMetadata,
}

impl Detector {
    pub fn new(config: &DetectionConfig) -> Result<Self, DetectorError> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            rules.push(CompiledRule {
                regex: Regex::new(&rule.pattern).map_err(|source| DetectorError::InvalidRegex {
                    rule: rule.name.clone(),
                    source,
                })?,
                metadata: to_metadata(rule),
            });
        }
        let rule_set = (!config.rules.is_empty())
            .then(|| RegexSet::new(config.rules.iter().map(|rule| rule.pattern.as_str())))
            .transpose()
            .map_err(|source| DetectorError::InvalidRegex {
                rule: "__regex_set__".to_string(),
                source,
            })?;

        let high_entropy = config.high_entropy.as_ref().and_then(|rule| {
            rule.enabled.then(|| CompiledHighEntropyRule {
                min_length: rule.min_length,
                min_entropy: rule.min_entropy,
                metadata: to_high_entropy_metadata(rule),
            })
        });

        Ok(Self {
            ignore_json_pointers: config.ignore_json_pointers.clone(),
            rules,
            rule_set,
            high_entropy,
        })
    }

    pub fn should_ignore_pointer(&self, pointer: &str) -> bool {
        self.ignore_json_pointers.contains(pointer)
    }

    pub fn scan_text(&self, text: &str, pointer: &str) -> Vec<DetectionFinding> {
        let mut findings = Vec::new();

        if let Some(rule_set) = &self.rule_set {
            for idx in rule_set.matches(text).iter() {
                let rule = &self.rules[idx];
                if rule.regex.captures_len() > 1 {
                    for captures in rule.regex.captures_iter(text) {
                        let Some(matched) = captures.get(1).or_else(|| captures.get(0)) else {
                            continue;
                        };
                        let snippet = matched.as_str().to_string();
                        findings.push(DetectionFinding::new(
                            matched.start(),
                            matched.end(),
                            snippet,
                            pointer.to_string(),
                            rule.metadata.clone(),
                        ));
                    }
                } else {
                    for matched in rule.regex.find_iter(text) {
                        let snippet = matched.as_str().to_string();
                        findings.push(DetectionFinding::new(
                            matched.start(),
                            matched.end(),
                            snippet,
                            pointer.to_string(),
                            rule.metadata.clone(),
                        ));
                    }
                }
            }
        }

        if let Some(entropy_rule) = &self.high_entropy {
            for token in
                high_entropy_tokens(text, entropy_rule.min_length, entropy_rule.min_entropy)
            {
                findings.push(DetectionFinding::new(
                    token.start,
                    token.end,
                    token.value.to_string(),
                    pointer.to_string(),
                    entropy_rule.metadata.clone(),
                ));
            }
        }

        findings
    }
}

fn to_metadata(rule: &DetectionRuleConfig) -> RuleMetadata {
    RuleMetadata {
        rule_name: rule.name.clone(),
        label: rule.label.clone(),
        severity: rule.severity,
        authorized_action: rule.authorized_action,
        unauthorized_action: rule.unauthorized_action,
        min_clearance: rule.min_clearance,
        masking: rule.masking,
    }
}

fn to_high_entropy_metadata(rule: &HighEntropyRuleConfig) -> RuleMetadata {
    RuleMetadata {
        rule_name: "high_entropy".to_string(),
        label: rule.label.clone(),
        severity: rule.severity,
        authorized_action: rule.authorized_action,
        unauthorized_action: rule.unauthorized_action,
        min_clearance: rule.min_clearance,
        masking: rule.masking,
    }
}

fn sha256_hex(input: &str) -> String {
    Sha256::digest(input.as_bytes()).encode_hex::<String>()
}

struct EntropyToken<'a> {
    start: usize,
    end: usize,
    value: &'a str,
}

fn high_entropy_tokens(input: &str, min_length: usize, min_entropy: f64) -> Vec<EntropyToken<'_>> {
    let mut tokens = Vec::new();
    let mut start = None;

    for (idx, ch) in input.char_indices() {
        if is_entropy_char(ch) {
            start.get_or_insert(idx);
        } else if let Some(begin) = start.take() {
            let token = &input[begin..idx];
            if token.len() >= min_length && shannon_entropy(token) >= min_entropy {
                tokens.push(EntropyToken {
                    start: begin,
                    end: idx,
                    value: token,
                });
            }
        }
    }

    if let Some(begin) = start {
        let token = &input[begin..];
        if token.len() >= min_length && shannon_entropy(token) >= min_entropy {
            tokens.push(EntropyToken {
                start: begin,
                end: input.len(),
                value: token,
            });
        }
    }

    tokens
}

fn is_entropy_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | '+' | '=')
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0u32; 256];
    for byte in value.bytes() {
        counts[byte as usize] += 1;
    }
    let len = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{DetectionConfig, DetectionRuleConfig, HighEntropyRuleConfig},
        types::{Clearance, DecisionAction, MaskingStrategy, Severity},
    };

    use super::Detector;

    #[test]
    fn detects_regex_and_entropy() {
        let detector = Detector::new(&DetectionConfig {
            ignore_json_pointers: Default::default(),
            presidio: None,
            high_entropy: Some(HighEntropyRuleConfig {
                enabled: true,
                min_length: 20,
                min_entropy: 3.0,
                label: "secret_like".into(),
                severity: Severity::High,
                authorized_action: DecisionAction::Redact,
                unauthorized_action: DecisionAction::Block,
                min_clearance: Clearance::Confidential,
                masking: MaskingStrategy::Hash,
            }),
            rules: vec![DetectionRuleConfig {
                name: "email".into(),
                label: "email".into(),
                pattern: r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b".into(),
                severity: Severity::Medium,
                authorized_action: DecisionAction::Allow,
                unauthorized_action: DecisionAction::Redact,
                min_clearance: Clearance::Internal,
                masking: MaskingStrategy::PartialEmail,
            }],
        })
        .unwrap();

        let findings = detector.scan_text(
            "contact admin@example.com and sk-ABCDEFGH1234567890qrstuv",
            "/messages/0/content",
        );

        assert!(findings.iter().any(|hit| hit.metadata.label == "email"));
        assert!(
            findings
                .iter()
                .any(|hit| hit.metadata.label == "secret_like")
        );
    }

    #[test]
    fn uses_first_capture_group_as_effective_sensitive_span() {
        let detector = Detector::new(&DetectionConfig {
            ignore_json_pointers: Default::default(),
            presidio: None,
            high_entropy: None,
            rules: vec![DetectionRuleConfig {
                name: "phone_cn".into(),
                label: "phone".into(),
                pattern: r"(?:^|[^0-9])(1[3-9]\d{9})(?:$|[^0-9])".into(),
                severity: Severity::High,
                authorized_action: DecisionAction::Allow,
                unauthorized_action: DecisionAction::Block,
                min_clearance: Clearance::Confidential,
                masking: MaskingStrategy::PartialPhone,
            }],
        })
        .unwrap();

        let findings = detector.scan_text("我的手机号是13800138000", "/messages/0/content");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].matched, "13800138000");
        assert_eq!(findings[0].start, "我的手机号是".len());
        assert_eq!(findings[0].end, "我的手机号是13800138000".len());
    }

    #[test]
    fn detects_extended_builtin_regex_matrix() {
        let detector = Detector::new(&DetectionConfig {
            ignore_json_pointers: Default::default(),
            presidio: None,
            high_entropy: None,
            rules: vec![
                DetectionRuleConfig {
                    name: "ip_address".into(),
                    label: "ip_address".into(),
                    pattern: r"(?:^|[^0-9.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:$|[^0-9.])".into(),
                    severity: Severity::Medium,
                    authorized_action: DecisionAction::Allow,
                    unauthorized_action: DecisionAction::Redact,
                    min_clearance: Clearance::Internal,
                    masking: MaskingStrategy::Placeholder,
                },
                DetectionRuleConfig {
                    name: "mac_address".into(),
                    label: "mac_address".into(),
                    pattern: r"(?i)(?:^|[^0-9A-F])((?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2})(?:$|[^0-9A-F])".into(),
                    severity: Severity::High,
                    authorized_action: DecisionAction::Allow,
                    unauthorized_action: DecisionAction::Redact,
                    min_clearance: Clearance::Confidential,
                    masking: MaskingStrategy::Placeholder,
                },
                DetectionRuleConfig {
                    name: "imei".into(),
                    label: "imei".into(),
                    pattern: r"(?:^|[^0-9])(\d{15})(?:$|[^0-9])".into(),
                    severity: Severity::Critical,
                    authorized_action: DecisionAction::Allow,
                    unauthorized_action: DecisionAction::Block,
                    min_clearance: Clearance::Restricted,
                    masking: MaskingStrategy::KeepLast4,
                },
                DetectionRuleConfig {
                    name: "vin".into(),
                    label: "vin".into(),
                    pattern: r"(?i)(?:^|[^A-HJ-NPR-Z0-9])([A-HJ-NPR-Z0-9]{17})(?:$|[^A-HJ-NPR-Z0-9])".into(),
                    severity: Severity::High,
                    authorized_action: DecisionAction::Allow,
                    unauthorized_action: DecisionAction::Redact,
                    min_clearance: Clearance::Confidential,
                    masking: MaskingStrategy::Placeholder,
                },
                DetectionRuleConfig {
                    name: "bank_card".into(),
                    label: "bank_card".into(),
                    pattern: r"(?:^|[^0-9])(\d{16,19})(?:$|[^0-9])".into(),
                    severity: Severity::Critical,
                    authorized_action: DecisionAction::Redact,
                    unauthorized_action: DecisionAction::Block,
                    min_clearance: Clearance::Restricted,
                    masking: MaskingStrategy::KeepLast4,
                },
            ],
        })
        .unwrap();

        let findings = detector.scan_text(
            "服务器 10.20.30.40 网卡 00:1A:2B:3C:4D:5E IMEI 490154203237518 VIN 1HGCM82633A004352 卡号 6222021234567890",
            "/messages/0/content",
        );

        assert!(
            findings
                .iter()
                .any(|hit| { hit.metadata.label == "ip_address" && hit.matched == "10.20.30.40" })
        );
        assert!(findings.iter().any(|hit| {
            hit.metadata.label == "mac_address" && hit.matched == "00:1A:2B:3C:4D:5E"
        }));
        assert!(
            findings
                .iter()
                .any(|hit| { hit.metadata.label == "imei" && hit.matched == "490154203237518" })
        );
        assert!(
            findings
                .iter()
                .any(|hit| { hit.metadata.label == "vin" && hit.matched == "1HGCM82633A004352" })
        );
        assert!(
            findings.iter().any(|hit| {
                hit.metadata.label == "bank_card" && hit.matched == "6222021234567890"
            })
        );
    }
}
