//! Local root certificate authority for the transparent MITM proxy.
//!
//! On first run a self-signed root CA is generated. Its private key is written
//! with `0600` permissions and is **never** logged, exported, or copied into the
//! audit stream. Per-SNI leaf certs are signed on the fly by hudsucker's
//! [`RcgenAuthority`] and cached in memory.

use std::{
    fs,
    path::{Path, PathBuf},
};

use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose},
    rustls::crypto::aws_lc_rs,
};
use thiserror::Error;

use crate::config::ProxyConfig;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("failed to read CA material at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write CA material at {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to generate or parse CA certificate: {0}")]
    Rcgen(#[from] hudsucker::rcgen::Error),
}

/// The common name used for the generated root CA.
const CA_COMMON_NAME: &str = "ctxward Root CA";

/// Resolve the CA private-key path: explicit config → env override → `{ca_dir}/ctxward-ca.key`.
fn resolve_ca_key_path(cfg: &ProxyConfig) -> PathBuf {
    if let Some(path) = &cfg.ca_key_path {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var(&cfg.ca_key_path_env) {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    Path::new(&cfg.ca_dir).join("ctxward-ca.key")
}

/// Resolve the CA certificate path: explicit config → `{ca_dir}/ctxward-ca.pem`.
fn resolve_ca_cert_path(cfg: &ProxyConfig) -> PathBuf {
    if let Some(path) = &cfg.ca_cert_path {
        return PathBuf::from(path);
    }
    Path::new(&cfg.ca_dir).join("ctxward-ca.pem")
}

/// Generate a fresh self-signed root CA, returning `(key_pem, cert_pem)`.
fn generate_root_ca() -> Result<(String, String), CaError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ctxward");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key)?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// Write a file with owner-only permissions (`0600` on Unix).
fn write_protected(path: &Path, contents: &str) -> Result<(), CaError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CaError::Write {
            path: parent.display().to_string(),
            source,
        })?;
    }
    fs::write(path, contents).map_err(|source| CaError::Write {
        path: path.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|source| CaError::Write {
                path: path.display().to_string(),
                source,
            })?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(|source| CaError::Write {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

/// Load the persistent root CA, generating it on first run.
///
/// Returns a hudsucker [`RcgenAuthority`] that signs per-SNI leaf certs and
/// caches them up to `cfg.cert_cache_size`.
pub fn load_or_create_ca(cfg: &ProxyConfig) -> Result<RcgenAuthority, CaError> {
    let key_path = resolve_ca_key_path(cfg);
    let cert_path = resolve_ca_cert_path(cfg);

    let (key_pem, cert_pem) = if key_path.exists() && cert_path.exists() {
        let key_pem = fs::read_to_string(&key_path).map_err(|source| CaError::Read {
            path: key_path.display().to_string(),
            source,
        })?;
        let cert_pem = fs::read_to_string(&cert_path).map_err(|source| CaError::Read {
            path: cert_path.display().to_string(),
            source,
        })?;
        (key_pem, cert_pem)
    } else {
        let (key_pem, cert_pem) = generate_root_ca()?;
        write_protected(&key_path, &key_pem)?;
        // The certificate is public; normal permissions are fine.
        fs::write(&cert_path, &cert_pem).map_err(|source| CaError::Write {
            path: cert_path.display().to_string(),
            source,
        })?;
        tracing::info!(
            cert = %cert_path.display(),
            "generated new ctxward root CA (install this cert in your trust store)"
        );
        (key_pem, cert_pem)
    };

    let key_pair = KeyPair::from_pem(&key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;
    Ok(RcgenAuthority::new(
        issuer,
        cfg.cert_cache_size,
        aws_lc_rs::default_provider(),
    ))
}

/// Export the root CA certificate in PEM form, for the desktop shell / helper to
/// install into OS and NSS trust stores. Returns `None` if the CA has not been
/// generated yet.
pub fn export_ca_cert_pem(cfg: &ProxyConfig) -> Result<Option<String>, CaError> {
    let cert_path = resolve_ca_cert_path(cfg);
    if !cert_path.exists() {
        return Ok(None);
    }
    let pem = fs::read_to_string(&cert_path).map_err(|source| CaError::Read {
        path: cert_path.display().to_string(),
        source,
    })?;
    Ok(Some(pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_cfg_in(dir: &Path) -> ProxyConfig {
        ProxyConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            ca_dir: dir.display().to_string(),
            ca_key_path: None,
            ca_cert_path: None,
            ca_key_path_env: "CONTEXT_GURD_PROXY_CA_KEY_PATH_TEST_UNSET".to_string(),
            leaf_ttl_days: 7,
            cert_cache_size: 16,
            intercept: vec![],
            passthrough: vec![],
            default_action: crate::config::ProxyAction::Passthrough,
            per_app_rules: vec![],
            pin_fallback: crate::config::PinFallbackConfig::default(),
            ruleset_url: None,
            ruleset_poll_secs: 300,
        }
    }

    #[test]
    fn generates_then_reuses_ca() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = proxy_cfg_in(dir.path());

        // first call generates
        let _authority = load_or_create_ca(&cfg).expect("generate CA");
        let key_path = resolve_ca_key_path(&cfg);
        let cert_path = resolve_ca_cert_path(&cfg);
        assert!(key_path.exists(), "key written");
        assert!(cert_path.exists(), "cert written");

        let key_before = fs::read_to_string(&key_path).unwrap();

        // second call reuses the same material (does not regenerate)
        let _authority2 = load_or_create_ca(&cfg).expect("reload CA");
        let key_after = fs::read_to_string(&key_path).unwrap();
        assert_eq!(key_before, key_after, "CA key must be stable across loads");

        // export returns the cert PEM
        let exported = export_ca_cert_pem(&cfg).unwrap().expect("cert exists");
        assert!(exported.contains("BEGIN CERTIFICATE"));
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cfg = proxy_cfg_in(dir.path());
        load_or_create_ca(&cfg).expect("generate CA");
        let mode = fs::metadata(resolve_ca_key_path(&cfg))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CA private key must be chmod 600");
    }
}
