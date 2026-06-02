//! Entry-point dispatcher: run either the reverse-proxy (compat) data plane or
//! the transparent MITM forward proxy, based on `config.mode`.

use std::{future::Future, net::SocketAddr, sync::Arc};

use hudsucker::{Proxy, rustls::crypto::aws_lc_rs};

use crate::{
    app::{AppError, AppState},
    config::Mode,
    mitm::{Classifier, CtxwardHandler, PinCache, ca, local_principal},
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
    let classifier = Arc::new(Classifier::from_config(&proxy_cfg));
    let pins = Arc::new(PinCache::new(&proxy_cfg));
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
