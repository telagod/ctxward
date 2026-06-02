//! Hot-updatable, signed provider rule-set (Clash-style subscription).
//!
//! A signed rule-set updates the intercept/passthrough lists without a release.
//! The payload is ed25519-signed by a key the operator configures; verification
//! is **mandatory** and any failure (fetch, parse, signature, schema) is
//! **fail-closed** — the current (baked-in or last-good) classifier is kept, so
//! a hijacked feed can never add a victim host to the intercept set.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::config::{HostPattern, ProxyAction};

/// The rule-set payload (the exact object that is signed).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Ruleset {
    pub version: u64,
    #[serde(default)]
    pub intercept: Vec<HostPattern>,
    #[serde(default)]
    pub passthrough: Vec<HostPattern>,
    #[serde(default)]
    pub default_action: ProxyAction,
    /// Hosts whose request body is signed upstream (e.g. AWS SigV4). They are
    /// intercepted for detection/audit but never body-modified, since redaction
    /// would invalidate the signature.
    #[serde(default)]
    pub signs_body: Vec<HostPattern>,
}

/// Signed envelope: the rule-set as a canonical JSON string plus a detached
/// ed25519 signature over that string's UTF-8 bytes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedRuleset {
    pub ruleset: String,
    /// Hex-encoded ed25519 signature over `ruleset`.
    pub signature: String,
}

/// Hard cap on a rule-set payload (defense against a hostile feed; real
/// rule-sets are a few KB). The fetcher also caps the download stream.
pub const MAX_RULESET_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    #[error("ruleset payload exceeds {MAX_RULESET_BYTES} bytes")]
    TooLarge,
    #[error("invalid signed-ruleset envelope: {0}")]
    Envelope(serde_json::Error),
    #[error("invalid ruleset payload: {0}")]
    Payload(serde_json::Error),
    #[error("invalid ed25519 public key")]
    PublicKey,
    #[error("invalid signature encoding")]
    SignatureEncoding,
    #[error("signature verification failed")]
    SignatureInvalid,
}

/// Parse and verify a signed rule-set against `pubkey_hex` (a 32-byte ed25519
/// verifying key in hex). Returns the rule-set only when the signature checks
/// out — callers treat any error as fail-closed.
pub fn parse_and_verify(bytes: &[u8], pubkey_hex: &str) -> Result<Ruleset, RulesetError> {
    if bytes.len() > MAX_RULESET_BYTES {
        return Err(RulesetError::TooLarge);
    }
    let envelope: SignedRuleset = serde_json::from_slice(bytes).map_err(RulesetError::Envelope)?;

    let key_bytes = hex::decode(pubkey_hex.trim()).map_err(|_| RulesetError::PublicKey)?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RulesetError::PublicKey)?;
    let verifying = VerifyingKey::from_bytes(&key_arr).map_err(|_| RulesetError::PublicKey)?;

    let sig_bytes =
        hex::decode(envelope.signature.trim()).map_err(|_| RulesetError::SignatureEncoding)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RulesetError::SignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying
        .verify_strict(envelope.ruleset.as_bytes(), &signature)
        .map_err(|_| RulesetError::SignatureInvalid)?;

    serde_json::from_str(&envelope.ruleset).map_err(RulesetError::Payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_envelope(signing: &SigningKey, ruleset_json: &str) -> Vec<u8> {
        let sig = signing.sign(ruleset_json.as_bytes());
        let env = SignedRuleset {
            ruleset: ruleset_json.to_string(),
            signature: hex::encode(sig.to_bytes()),
        };
        serde_json::to_vec(&env).unwrap()
    }

    fn fixed_signing_key() -> SigningKey {
        // deterministic key for tests (not a real secret)
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn verifies_valid_signed_ruleset() {
        let signing = fixed_signing_key();
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        let ruleset_json = r#"{"version":3,"intercept":[{"kind":"exact","value":"api.openai.com"}],"default_action":"passthrough"}"#;
        let bytes = sign_envelope(&signing, ruleset_json);

        let rs = parse_and_verify(&bytes, &pubkey_hex).expect("valid signature");
        assert_eq!(rs.version, 3);
        assert_eq!(rs.intercept.len(), 1);
        assert_eq!(rs.default_action, ProxyAction::Passthrough);
    }

    #[test]
    fn rejects_tampered_payload() {
        let signing = fixed_signing_key();
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        let ruleset_json =
            r#"{"version":1,"intercept":[{"kind":"exact","value":"api.openai.com"}]}"#;
        let bytes = sign_envelope(&signing, ruleset_json);

        // tamper: flip the signed string after signing
        let mut env: SignedRuleset = serde_json::from_slice(&bytes).unwrap();
        env.ruleset = env.ruleset.replace("api.openai.com", "evil.example.com");
        let tampered = serde_json::to_vec(&env).unwrap();

        let err = parse_and_verify(&tampered, &pubkey_hex).unwrap_err();
        assert!(matches!(err, RulesetError::SignatureInvalid));
    }

    #[test]
    fn rejects_wrong_key() {
        let signing = fixed_signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let other_pub = hex::encode(other.verifying_key().to_bytes());
        let ruleset_json = r#"{"version":1}"#;
        let bytes = sign_envelope(&signing, ruleset_json);

        let err = parse_and_verify(&bytes, &other_pub).unwrap_err();
        assert!(matches!(err, RulesetError::SignatureInvalid));
    }

    #[test]
    fn rejects_malformed_envelope() {
        let signing = fixed_signing_key();
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        let err = parse_and_verify(b"not json", &pubkey_hex).unwrap_err();
        assert!(matches!(err, RulesetError::Envelope(_)));
    }

    #[test]
    fn rejects_oversized_payload() {
        let signing = fixed_signing_key();
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        let oversized = vec![b'x'; MAX_RULESET_BYTES + 1];
        let err = parse_and_verify(&oversized, &pubkey_hex).unwrap_err();
        assert!(matches!(err, RulesetError::TooLarge));
    }

    #[test]
    fn rejects_bad_pubkey() {
        let signing = fixed_signing_key();
        let ruleset_json = r#"{"version":1}"#;
        let bytes = sign_envelope(&signing, ruleset_json);
        let err = parse_and_verify(&bytes, "not-hex").unwrap_err();
        assert!(matches!(err, RulesetError::PublicKey));
    }
}
