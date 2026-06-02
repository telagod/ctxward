use std::collections::{HashMap, HashSet};

use hex::ToHex;
use http::{HeaderMap, HeaderName, header::AUTHORIZATION};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    config::{AuthConfig, PrincipalConfig},
    types::Clearance,
};

#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub name: String,
    pub tenant_id: String,
    pub role: String,
    pub clearance: Clearance,
    pub allowed_labels: HashSet<String>,
}

impl From<&PrincipalConfig> for Principal {
    fn from(value: &PrincipalConfig) -> Self {
        Self {
            name: value.name.clone(),
            tenant_id: value.tenant_id.clone(),
            role: value.role.clone(),
            clearance: value.clearance,
            allowed_labels: value.allowed_labels.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid auth header name")]
    InvalidHeaderName,
    #[error("missing credentials")]
    MissingCredentials,
    #[error("invalid credentials")]
    InvalidCredentials,
}

#[derive(Clone)]
pub struct Authenticator {
    header_name: HeaderName,
    principal_by_hash: HashMap<String, Principal>,
}

impl Authenticator {
    pub fn new(config: &AuthConfig) -> Result<Self, AuthError> {
        let header_name = HeaderName::try_from(config.header_name.to_lowercase())
            .map_err(|_| AuthError::InvalidHeaderName)?;
        let principal_by_hash = config
            .principals
            .iter()
            .map(|principal| {
                (
                    principal.secret_sha256.to_lowercase(),
                    Principal::from(principal),
                )
            })
            .collect();

        Ok(Self {
            header_name,
            principal_by_hash,
        })
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, AuthError> {
        let value = headers
            .get(&self.header_name)
            .ok_or(AuthError::MissingCredentials)?;
        let value = value.to_str().map_err(|_| AuthError::InvalidCredentials)?;
        let secret = if self.header_name == AUTHORIZATION {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
                .unwrap_or(value)
        } else {
            value
        };
        let digest = Sha256::digest(secret.as_bytes()).encode_hex::<String>();
        self.principal_by_hash
            .get(&digest)
            .cloned()
            .ok_or(AuthError::InvalidCredentials)
    }
}
