//! Parse LLM model + token usage from intercepted JSON bodies, feeding the
//! token/cost metering counters. Best-effort: malformed or non-JSON bodies
//! yield `None` and never error.

use serde_json::Value;

/// Token usage parsed from a (non-streamed) response body.
pub struct Usage {
    pub model: Option<String>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// The model id from a request body (`{"model": "..."}`), if present.
pub fn model_from_request(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("model")?.as_str().map(str::to_string)
}

/// Token usage from a response body's `usage` object. Handles OpenAI
/// (`prompt_tokens`/`completion_tokens`) and Anthropic
/// (`input_tokens`/`output_tokens`). Returns `None` if no usage is present.
///
/// Note: streamed (SSE) responses are passed through unbuffered in D1, so their
/// trailing usage event is not metered here (tracked with D1.5 SSE handling).
pub fn usage_from_response(body: &[u8]) -> Option<Usage> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    let model = v.get("model").and_then(Value::as_str).map(str::to_string);
    let prompt = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if prompt == 0 && completion == 0 {
        return None;
    }
    Some(Usage {
        model,
        prompt_tokens: prompt,
        completion_tokens: completion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_model() {
        let body = br#"{"model":"gpt-4.1-mini","messages":[]}"#;
        assert_eq!(model_from_request(body).as_deref(), Some("gpt-4.1-mini"));
    }

    #[test]
    fn request_without_model_is_none() {
        assert!(model_from_request(br#"{"messages":[]}"#).is_none());
        assert!(model_from_request(b"not json").is_none());
    }

    #[test]
    fn parses_openai_usage() {
        let body = br#"{"model":"gpt-4","usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}"#;
        let u = usage_from_response(body).expect("usage");
        assert_eq!(u.model.as_deref(), Some("gpt-4"));
        assert_eq!(u.prompt_tokens, 12);
        assert_eq!(u.completion_tokens, 34);
    }

    #[test]
    fn parses_anthropic_usage() {
        let body = br#"{"model":"claude-opus-4","usage":{"input_tokens":100,"output_tokens":250}}"#;
        let u = usage_from_response(body).expect("usage");
        assert_eq!(u.prompt_tokens, 100);
        assert_eq!(u.completion_tokens, 250);
    }

    #[test]
    fn no_usage_is_none() {
        assert!(usage_from_response(br#"{"model":"x"}"#).is_none());
        assert!(
            usage_from_response(br#"{"usage":{"prompt_tokens":0,"completion_tokens":0}}"#)
                .is_none()
        );
        assert!(usage_from_response(b"not json").is_none());
    }
}
