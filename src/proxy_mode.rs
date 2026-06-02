//! Entry-point dispatcher: run either the reverse-proxy (compat) data plane or
//! the transparent MITM forward proxy, based on `config.mode`.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::StreamExt;
use hudsucker::{Proxy, rustls::crypto::aws_lc_rs};
use parking_lot::RwLock;

use crate::{
    app::{AppError, AppState},
    config::Mode,
    mitm::{
        Classifier, CtxwardHandler, PinCache, SharedClassifier, ca, local_principal,
        ruleset::{MAX_RULESET_BYTES, parse_and_verify},
    },
};

/// Dispatch on the configured mode.
pub async fn serve(state: Arc<AppState>) -> Result<(), AppError> {
    let mode = state.current().config.mode;
    match mode {
        Mode::Reverse => crate::app::serve_reverse(state).await,
        Mode::Proxy => serve_proxy(state).await,
    }
}

/// Run the transparent MITM forward proxy until the process ends.
async fn serve_proxy(state: Arc<AppState>) -> Result<(), AppError> {
    run_proxy(state, std::future::pending::<()>()).await
}

/// Build and run the transparent MITM forward proxy, shutting down gracefully
/// when `shutdown` resolves. Exposed for integration tests.
pub async fn run_proxy(
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), AppError> {
    let runtime = state.current();
    let proxy_cfg = runtime
        .config
        .proxy
        .clone()
        .ok_or(AppError::ProxyConfigMissing)?;

    // Ensure a process-default rustls crypto provider exists. hudsucker is given
    // an explicit provider below, but other rustls users (reqwest) may rely on
    // the default; install aws-lc-rs once (idempotent — ignore if already set).
    let _ = aws_lc_rs::default_provider().install_default();

    let addr: SocketAddr = proxy_cfg
        .listen_addr
        .parse()
        .map_err(|_| AppError::ProxyListenAddr(proxy_cfg.listen_addr.clone()))?;

    let authority = ca::load_or_create_ca(&proxy_cfg)?;
    let classifier: SharedClassifier =
        Arc::new(RwLock::new(Arc::new(Classifier::from_config(&proxy_cfg))));
    let pins = Arc::new(PinCache::new(&proxy_cfg));

    // Hot-updatable rule-set (Clash-style subscription). Only enabled when BOTH
    // a url and an ed25519 public key are configured — unverified feeds are
    // rejected, since a hijacked feed could otherwise add a victim host to the
    // intercept set.
    match (&proxy_cfg.ruleset_url, &proxy_cfg.ruleset_pubkey) {
        (Some(url), Some(pubkey)) => {
            spawn_ruleset_updater(
                classifier.clone(),
                runtime.client.clone(),
                url.clone(),
                pubkey.clone(),
                Duration::from_secs(proxy_cfg.ruleset_poll_secs.max(1)),
            );
        }
        (Some(_), None) => {
            tracing::warn!(
                "ruleset_url is set but ruleset_pubkey is missing; ignoring the feed (unsigned rule-sets are rejected)"
            );
        }
        _ => {}
    }

    let handler = CtxwardHandler::new(
        runtime.clone(),
        state.metrics.clone(),
        local_principal(),
        classifier,
        pins,
    );

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .map_err(AppError::Proxy)?;

    tracing::info!(listen = %addr, "context-gurd MITM proxy listening (proxy mode)");
    proxy.start().await.map_err(AppError::Proxy)
}

/// Poll a signed remote rule-set and hot-swap the classifier on a verified,
/// newer version. Every failure (fetch, signature, parse) is fail-closed: the
/// current classifier is kept untouched.
fn spawn_ruleset_updater(
    classifier: SharedClassifier,
    client: reqwest::Client,
    url: String,
    pubkey: String,
    poll: Duration,
) {
    tokio::spawn(async move {
        let mut current_version: u64 = 0;
        loop {
            match fetch_ruleset(&client, &url).await {
                Ok(bytes) => match parse_and_verify(&bytes, &pubkey) {
                    Ok(rs) if rs.version > current_version => {
                        let n_intercept = rs.intercept.len();
                        *classifier.write() = Arc::new(Classifier::from_ruleset(&rs));
                        current_version = rs.version;
                        tracing::info!(
                            version = rs.version,
                            intercept = n_intercept,
                            "applied verified rule-set update"
                        );
                    }
                    Ok(rs) => {
                        tracing::debug!(
                            version = rs.version,
                            "rule-set not newer; keeping current"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(%err, "rule-set rejected (fail-closed; keeping current)");
                    }
                },
                Err(err) => {
                    tracing::warn!(%err, "rule-set fetch failed (fail-closed; keeping current)");
                }
            }
            tokio::time::sleep(poll).await;
        }
    });
}

/// Fetch a rule-set, bounding memory: reject an over-limit Content-Length up
/// front, then stream with a hard cap (defends against a hostile feed lying
/// about its length and trying to OOM the proxy).
async fn fetch_ruleset(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_RULESET_BYTES {
            return Err(format!(
                "content-length {len} exceeds {MAX_RULESET_BYTES}-byte limit"
            ));
        }
    }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if buf.len() + chunk.len() > MAX_RULESET_BYTES {
            return Err("ruleset stream exceeds size limit".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
