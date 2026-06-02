//! Self-contained "scrub this body" API, reusing the exact detection +
//! redaction primitives (`Detector`, `PolicyEngine`, `redact_text`) so the
//! browser extension's in-page redaction has zero drift from the gateway.
//!
//! The pure [`redact_json`] is native-unit-tested; [`wasm`] adds the
//! `#[wasm_bindgen]` glue (compiled only with `--features wasm`).

use serde_json::Value;

use crate::{
    auth::Principal,
    config::DetectionConfig,
    detect::Detector,
    policy::PolicyEngine,
    redact::redact_text,
    types::{Clearance, Direction},
};

/// The local principal used for client-side redaction: lowest clearance and no
/// allowed labels, so every detected finding takes its rule's
/// `unauthorized_action` (the privacy-maximizing default), matching the desktop
/// proxy's `local_principal`.
fn local_principal() -> Principal {
    Principal {
        name: "extension".to_string(),
        tenant_id: "local".to_string(),
        role: "local".to_string(),
        clearance: Clearance::Public,
        allowed_labels: Default::default(),
    }
}

fn redact_string(
    detector: &Detector,
    policy: &PolicyEngine,
    principal: &Principal,
    s: &mut String,
) {
    let findings = detector.scan_text(s, "/");
    if findings.is_empty() {
        return;
    }
    let outcome = policy.resolve(principal, findings, Direction::Request);
    if let Ok(redacted) = redact_text(s, &outcome.findings, None) {
        *s = redacted;
    }
}

fn redact_value(
    detector: &Detector,
    policy: &PolicyEngine,
    principal: &Principal,
    value: &mut Value,
) {
    match value {
        Value::String(s) => redact_string(detector, policy, principal, s),
        Value::Array(items) => {
            for item in items {
                redact_value(detector, policy, principal, item);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                redact_value(detector, policy, principal, v);
            }
        }
        _ => {}
    }
}

/// Scrub `body` against the rules in `detection_config_json` (a JSON-serialized
/// [`DetectionConfig`]). If `body` is JSON, every string node is scrubbed; else
/// it is treated as plain text. On any config/detector error the body is
/// returned unchanged (the caller — e.g. the extension — should fail closed if
/// it required redaction).
pub fn redact_json(detection_config_json: &str, body: &str) -> String {
    let config: DetectionConfig = match serde_json::from_str(detection_config_json) {
        Ok(c) => c,
        Err(_) => return body.to_string(),
    };
    let detector = match Detector::new(&config) {
        Ok(d) => d,
        Err(_) => return body.to_string(),
    };
    let policy = PolicyEngine;
    let principal = local_principal();

    if let Ok(mut value) = serde_json::from_str::<Value>(body) {
        redact_value(&detector, &policy, &principal, &mut value);
        serde_json::to_string(&value).unwrap_or_else(|_| body.to_string())
    } else {
        let findings = detector.scan_text(body, "/");
        let outcome = policy.resolve(&principal, findings, Direction::Request);
        redact_text(body, &outcome.findings, None).unwrap_or_else(|_| body.to_string())
    }
}

/// `#[wasm_bindgen]` glue for the browser extension. Compiled only with
/// `--features wasm` so the native gateway build never pulls wasm-bindgen.
#[cfg(feature = "wasm")]
pub mod wasm {
    use wasm_bindgen::prelude::*;

    /// Scrub `body` against `detection_config_json`. See [`super::redact_json`].
    #[wasm_bindgen]
    pub fn redact_json(detection_config_json: &str, body: &str) -> String {
        super::redact_json(detection_config_json, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"{
        "rules": [
            {
                "name": "email",
                "label": "email",
                "pattern": "([a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,})",
                "authorized_action": "allow",
                "unauthorized_action": "redact",
                "min_clearance": "internal",
                "masking": "placeholder"
            }
        ]
    }"#;

    #[test]
    fn redacts_email_in_json_string_node() {
        let out = redact_json(
            CFG,
            r#"{"messages":[{"content":"mail me at leak@corp.example"}]}"#,
        );
        assert!(
            !out.contains("leak@corp.example"),
            "email must be scrubbed: {out}"
        );
        // structure preserved (still valid JSON with the messages key)
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("messages").is_some());
    }

    #[test]
    fn redacts_plain_text_body() {
        let out = redact_json(CFG, "contact leak@corp.example now");
        assert!(!out.contains("leak@corp.example"));
    }

    #[test]
    fn leaves_clean_body_untouched() {
        let body = r#"{"messages":[{"content":"hello world"}]}"#;
        assert_eq!(redact_json(CFG, body), body);
    }

    #[test]
    fn bad_config_returns_body_unchanged() {
        let body = r#"{"x":"leak@corp.example"}"#;
        assert_eq!(redact_json("not json", body), body);
    }
}
