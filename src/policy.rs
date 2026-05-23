use crate::{
    auth::Principal,
    detect::DetectionFinding,
    types::{DecisionAction, Direction},
};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ResolvedFinding {
    pub label: String,
    pub rule_name: String,
    pub action: DecisionAction,
    pub effective_action: DecisionAction,
    pub pointer: String,
    pub severity: crate::types::Severity,
    pub masking: crate::types::MaskingStrategy,
    pub matched_sha256: String,
    pub matched_len: usize,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

#[derive(Clone, Debug)]
pub struct PolicyOutcome {
    pub decision: DecisionAction,
    pub findings: Vec<ResolvedFinding>,
    pub source: String,
    pub reason: Option<String>,
}

#[derive(Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn resolve(
        &self,
        principal: &Principal,
        findings: Vec<DetectionFinding>,
        direction: Direction,
    ) -> PolicyOutcome {
        let mut decision = DecisionAction::Allow;
        let mut resolved = Vec::with_capacity(findings.len());

        for finding in findings {
            let action = if principal.clearance >= finding.metadata.min_clearance
                && principal.allowed_labels.contains(&finding.metadata.label)
            {
                finding.metadata.authorized_action
            } else {
                finding.metadata.unauthorized_action
            };
            decision = decision.combine(action);
            let effective_action = match direction {
                Direction::Request => action,
                Direction::Response => {
                    if action == DecisionAction::Allow {
                        DecisionAction::Allow
                    } else {
                        DecisionAction::Redact
                    }
                }
            };
            resolved.push(ResolvedFinding {
                label: finding.metadata.label,
                rule_name: finding.metadata.rule_name,
                action,
                effective_action,
                pointer: finding.pointer,
                severity: finding.metadata.severity,
                masking: finding.metadata.masking,
                matched_sha256: finding.matched_sha256,
                matched_len: finding.matched.len(),
                start: finding.start,
                end: finding.end,
                matched: finding.matched,
            });
        }

        PolicyOutcome {
            decision,
            findings: resolved,
            source: "builtin".to_string(),
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        auth::Principal,
        detect::{DetectionFinding, RuleMetadata},
        types::{Clearance, DecisionAction, Direction, MaskingStrategy, Severity},
    };

    use super::PolicyEngine;

    #[test]
    fn blocks_unauthorized_high_sensitive_data() {
        let principal = Principal {
            name: "demo".into(),
            tenant_id: "engineering".into(),
            role: "employee".into(),
            clearance: Clearance::Internal,
            allowed_labels: HashSet::from(["email".to_string()]),
        };
        let finding = DetectionFinding {
            start: 0,
            end: 18,
            matched: "13812341234".into(),
            matched_sha256: "hash".into(),
            pointer: "/messages/0/content".into(),
            metadata: RuleMetadata {
                rule_name: "phone".into(),
                label: "phone".into(),
                severity: Severity::High,
                authorized_action: DecisionAction::Allow,
                unauthorized_action: DecisionAction::Block,
                min_clearance: Clearance::Confidential,
                masking: MaskingStrategy::PartialPhone,
            },
        };

        let outcome = PolicyEngine.resolve(&principal, vec![finding], Direction::Request);
        assert_eq!(outcome.decision, DecisionAction::Block);
        assert_eq!(outcome.source, "builtin");
    }
}
