use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::config::TokenizationConfig;

#[derive(Debug, Error)]
pub enum TokenizationError {
    #[error("tokenization is required by masking rules but not configured")]
    RequiredButDisabled,
    #[error("tokenization key env {0} is not set")]
    MissingKeyEnv(String),
    #[error("tokenization key must be 32 bytes after decoding, got {0}")]
    InvalidKeyLength(usize),
    #[error("failed to decode tokenization key")]
    InvalidKeyEncoding,
    #[error("invalid token prefix {0}")]
    InvalidPrefix(String),
    #[error("failed to encrypt tokenized payload")]
    Encrypt,
    #[error("invalid token format")]
    InvalidTokenFormat,
    #[error("failed to decrypt tokenized payload")]
    Decrypt,
    #[error("failed to serialize tokenized payload: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to parse tokenized payload: {0}")]
    Parse(serde_json::Error),
}

#[derive(Clone)]
pub struct Tokenizer {
    cipher: Aes256GcmSiv,
    token_prefix: String,
    key_env: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetokenizedValue {
    pub label: String,
    pub value: String,
}

impl Tokenizer {
    pub fn from_config(
        config: Option<&TokenizationConfig>,
    ) -> Result<Option<Self>, TokenizationError> {
        let Some(config) = config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }
        let raw_key = std::env::var(&config.key_env)
            .map_err(|_| TokenizationError::MissingKeyEnv(config.key_env.clone()))?;
        let key = decode_key(&raw_key)?;
        Ok(Some(Self::from_key_material(
            &key,
            config.token_prefix.clone(),
            config.key_env.clone(),
        )?))
    }

    pub fn from_key_material(
        key: &[u8; 32],
        token_prefix: impl Into<String>,
        key_env: impl Into<String>,
    ) -> Result<Self, TokenizationError> {
        let token_prefix = token_prefix.into();
        validate_prefix(&token_prefix)?;
        let cipher = Aes256GcmSiv::new_from_slice(key)
            .map_err(|_| TokenizationError::InvalidKeyLength(key.len()))?;
        Ok(Self {
            cipher,
            token_prefix,
            key_env: key_env.into(),
        })
    }

    pub fn token_prefix(&self) -> &str {
        &self.token_prefix
    }

    pub fn key_env(&self) -> &str {
        &self.key_env
    }

    pub fn tokenize(&self, label: &str, value: &str) -> Result<String, TokenizationError> {
        let payload = serde_json::to_vec(&TokenPayload { label, value })
            .map_err(TokenizationError::Serialize)?;
        let nonce_uuid = Uuid::new_v4();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_uuid.as_bytes()[..12]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, payload.as_ref())
            .map_err(|_| TokenizationError::Encrypt)?;
        Ok(format!(
            "[{}_TOKEN:{}.{},{}]",
            label.to_uppercase(),
            self.token_prefix,
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(ciphertext)
        ))
    }

    pub fn detokenize(&self, token: &str) -> Result<DetokenizedValue, TokenizationError> {
        let raw = normalize_token(token)?;
        let (prefix, encoded_nonce, encoded_ciphertext) = raw
            .split_once('.')
            .and_then(|(prefix, remainder)| {
                remainder
                    .split_once(',')
                    .map(|(nonce, ciphertext)| (prefix, nonce, ciphertext))
            })
            .ok_or(TokenizationError::InvalidTokenFormat)?;
        if prefix != self.token_prefix {
            return Err(TokenizationError::InvalidTokenFormat);
        }
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(encoded_nonce)
            .map_err(|_| TokenizationError::InvalidTokenFormat)?;
        if nonce_bytes.len() != 12 {
            return Err(TokenizationError::InvalidTokenFormat);
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(encoded_ciphertext)
            .map_err(|_| TokenizationError::InvalidTokenFormat)?;
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| TokenizationError::Decrypt)?;
        serde_json::from_slice(&plaintext).map_err(TokenizationError::Parse)
    }
}

#[derive(Serialize)]
struct TokenPayload<'a> {
    label: &'a str,
    value: &'a str,
}

fn validate_prefix(prefix: &str) -> Result<(), TokenizationError> {
    if prefix.is_empty()
        || prefix.contains('.')
        || prefix.contains(',')
        || prefix.contains('[')
        || prefix.contains(']')
        || prefix.contains(':')
    {
        return Err(TokenizationError::InvalidPrefix(prefix.to_string()));
    }
    Ok(())
}

fn decode_key(raw: &str) -> Result<[u8; 32], TokenizationError> {
    let raw = raw.trim();
    let bytes = if raw.len() == 64 && raw.chars().all(|ch| ch.is_ascii_hexdigit()) {
        hex::decode(raw).map_err(|_| TokenizationError::InvalidKeyEncoding)?
    } else {
        URL_SAFE_NO_PAD
            .decode(raw)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
            .map_err(|_| TokenizationError::InvalidKeyEncoding)?
    };
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| TokenizationError::InvalidKeyLength(bytes.len()))?;
    Ok(key)
}

fn normalize_token(token: &str) -> Result<&str, TokenizationError> {
    let trimmed = token.trim();
    if let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let (_, raw) = inner
            .split_once(":")
            .ok_or(TokenizationError::InvalidTokenFormat)?;
        Ok(raw)
    } else {
        Ok(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::{DetokenizedValue, Tokenizer};

    #[test]
    fn token_roundtrip_is_reversible() {
        let key = [7u8; 32];
        let tokenizer = Tokenizer::from_key_material(&key, "CGT1", "TEST_KEY").unwrap();

        let token = tokenizer.tokenize("email", "admin@example.com").unwrap();
        assert!(token.starts_with("[EMAIL_TOKEN:CGT1."));

        let decoded = tokenizer.detokenize(&token).unwrap();
        assert_eq!(
            decoded,
            DetokenizedValue {
                label: "email".to_string(),
                value: "admin@example.com".to_string(),
            }
        );
    }

    #[test]
    fn rejects_invalid_token() {
        let key = [9u8; 32];
        let tokenizer = Tokenizer::from_key_material(&key, "CGT1", "TEST_KEY").unwrap();
        assert!(tokenizer.detokenize("[EMAIL_TOKEN:broken]").is_err());
    }
}
