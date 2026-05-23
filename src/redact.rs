use hex::ToHex;
use sha2::{Digest, Sha256};

use crate::{
    policy::ResolvedFinding,
    tokenize::{TokenizationError, Tokenizer},
    types::{DecisionAction, MaskingStrategy},
};

pub fn redact_text(
    input: &str,
    findings: &[ResolvedFinding],
    tokenizer: Option<&Tokenizer>,
) -> Result<String, TokenizationError> {
    let mut selected = findings
        .iter()
        .filter(|finding| finding.effective_action != DecisionAction::Allow)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(input.to_string());
    }

    selected.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(b.effective_action.rank().cmp(&a.effective_action.rank()))
    });

    let mut filtered = Vec::with_capacity(selected.len());
    let mut occupied_until = 0usize;
    for finding in selected {
        if finding.start < occupied_until {
            continue;
        }
        occupied_until = finding.end;
        filtered.push(finding);
    }

    let mut output = input.to_string();
    for finding in filtered.into_iter().rev() {
        let replacement = apply_mask(&finding.matched, finding.masking, &finding.label, tokenizer)?;
        output.replace_range(finding.start..finding.end, &replacement);
    }
    Ok(output)
}

pub fn apply_mask(
    input: &str,
    strategy: MaskingStrategy,
    label: &str,
    tokenizer: Option<&Tokenizer>,
) -> Result<String, TokenizationError> {
    match strategy {
        MaskingStrategy::Placeholder => Ok(format!("[{}]", label.to_uppercase())),
        MaskingStrategy::PartialEmail => Ok(partial_email(input)),
        MaskingStrategy::PartialPhone => Ok(partial_phone(input)),
        MaskingStrategy::KeepLast4 => Ok(keep_last4(input)),
        MaskingStrategy::Hash => Ok(format!(
            "[{}:{}]",
            label.to_uppercase(),
            sha256_short(input)
        )),
        MaskingStrategy::Tokenize => {
            let tokenizer = tokenizer.ok_or(TokenizationError::RequiredButDisabled)?;
            tokenizer.tokenize(label, input)
        }
        MaskingStrategy::Full => Ok("[REDACTED]".to_string()),
    }
}

fn partial_email(input: &str) -> String {
    let Some((local, domain)) = input.split_once('@') else {
        return "[EMAIL]".to_string();
    };
    let prefix = local.chars().next().unwrap_or('*');
    format!("{prefix}***@{domain}")
}

fn partial_phone(input: &str) -> String {
    if input.len() < 7 {
        return "[PHONE]".to_string();
    }
    let prefix = &input[..3.min(input.len())];
    let suffix = &input[input.len().saturating_sub(4)..];
    format!("{prefix}****{suffix}")
}

fn keep_last4(input: &str) -> String {
    if input.len() <= 4 {
        return "[ID]".to_string();
    }
    let suffix = &input[input.len() - 4..];
    format!("************{suffix}")
}

fn sha256_short(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes()).encode_hex::<String>();
    digest[..12].to_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        policy::ResolvedFinding,
        tokenize::Tokenizer,
        types::{DecisionAction, MaskingStrategy, Severity},
    };

    use super::redact_text;

    #[test]
    fn redacts_email_and_phone() {
        let source = "email admin@example.com phone 13812341234";
        let findings = vec![
            ResolvedFinding {
                label: "email".into(),
                rule_name: "email".into(),
                action: DecisionAction::Redact,
                effective_action: DecisionAction::Redact,
                pointer: "/messages/0/content".into(),
                severity: Severity::Medium,
                masking: MaskingStrategy::PartialEmail,
                matched_sha256: "x".into(),
                matched_len: 17,
                start: 6,
                end: 23,
                matched: "admin@example.com".into(),
            },
            ResolvedFinding {
                label: "phone".into(),
                rule_name: "phone".into(),
                action: DecisionAction::Redact,
                effective_action: DecisionAction::Redact,
                pointer: "/messages/0/content".into(),
                severity: Severity::High,
                masking: MaskingStrategy::PartialPhone,
                matched_sha256: "y".into(),
                matched_len: 11,
                start: 30,
                end: 41,
                matched: "13812341234".into(),
            },
        ];

        let output = redact_text(source, &findings, None).unwrap();
        assert!(output.contains("a***@example.com"));
        assert!(output.contains("138****1234"));
    }

    #[test]
    fn tokenizes_sensitive_value_when_enabled() {
        let tokenizer = Tokenizer::from_key_material(&[3u8; 32], "CGT1", "TEST_KEY").unwrap();
        let source = "email admin@example.com";
        let findings = vec![ResolvedFinding {
            label: "email".into(),
            rule_name: "email".into(),
            action: DecisionAction::Redact,
            effective_action: DecisionAction::Redact,
            pointer: "/messages/0/content".into(),
            severity: Severity::Medium,
            masking: MaskingStrategy::Tokenize,
            matched_sha256: "x".into(),
            matched_len: 17,
            start: 6,
            end: 23,
            matched: "admin@example.com".into(),
        }];

        let output = redact_text(source, &findings, Some(&tokenizer)).unwrap();
        assert!(output.starts_with("email [EMAIL_TOKEN:CGT1."));
        let token = output.strip_prefix("email ").unwrap();
        let decoded = tokenizer.detokenize(token).unwrap();
        assert_eq!(decoded.value, "admin@example.com");
    }
}
