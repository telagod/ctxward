//! End-to-end test for the transparent forward-proxy (MITM) mode.
//!
//! Drives a real hudsucker proxy built by `proxy_mode::run_proxy` over plain
//! HTTP (no CONNECT/TLS, so no cert trust is needed), with a local echo upstream
//! that records what it received. Proves the MITM handler reuses the existing
//! detection/redaction pipeline at runtime:
//!   * a request containing an email is redacted before reaching the upstream;
//!   * a response containing an email is redacted before reaching the client;
//!   * a request containing a CN phone (unauthorized_action=block) is blocked.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, body::Bytes, extract::State, response::IntoResponse, routing::post};
use context_gurd::{
    app::build_state,
    config::{AppConfig, Mode, ProxyConfig},
};

/// Upstream echo stub: stores the body it received, replies with a body that
/// itself contains an email (to exercise response-side redaction).
async fn echo(State(captured): State<Arc<Mutex<Vec<u8>>>>, body: Bytes) -> impl IntoResponse {
    *captured.lock().unwrap() = body.to_vec();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"reply":"please contact agent@corp.example for help"}"#,
    )
}

async fn start_echo_stub() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/chat", post(echo))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, captured)
}

/// Grab a currently-free localhost port (best effort; small TOCTOU window).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_until_listening(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy never started listening on {addr}");
}

/// Build a proxy-mode [`AppState`]. The returned [`tempfile::TempDir`] guard must
/// be held by the caller for the lifetime of the proxy (it owns the CA + config).
fn build_proxy_state(proxy_port: u16) -> (Arc<context_gurd::app::AppState>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path().to_path_buf();

    let mut config: AppConfig =
        serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
    config.mode = Mode::Proxy;
    let proxy_cfg: ProxyConfig = serde_yaml::from_str(&format!(
        "listen_addr: \"127.0.0.1:{proxy_port}\"\nca_dir: \"{}\"",
        temp_path.join("certs").display()
    ))
    .unwrap();
    config.proxy = Some(proxy_cfg);
    config.audit.jsonl_path = temp_path.join("audit.jsonl").display().to_string();
    config.review.jsonl_path = temp_path.join("review.jsonl").display().to_string();

    let config_path = temp_path.join("config.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
    (build_state(config_path).unwrap(), temp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_redacts_request_and_response_and_blocks_phone() {
    let (stub_addr, captured) = start_echo_stub().await;
    let proxy_port = free_port();
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    let (state, _temp_guard) = build_proxy_state(proxy_port);
    let audit = state.audit_store.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let proxy_task = tokio::spawn(async move {
        context_gurd::proxy_mode::run_proxy(state, async move {
            let _ = rx.await;
        })
        .await
    });
    wait_until_listening(proxy_addr).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    // --- 1. request with an email: redacted before upstream; response email redacted ---
    let resp = client
        .post(format!("http://{stub_addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"email me at zhangsan@corp.example"}]}"#)
        .send()
        .await
        .expect("request through proxy");
    assert_eq!(resp.status(), 200, "email request should be forwarded");
    let resp_body = resp.text().await.unwrap();

    let upstream_saw = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        !upstream_saw.is_empty(),
        "upstream should have received a forwarded body"
    );
    assert!(
        !upstream_saw.contains("zhangsan@corp.example"),
        "raw email must be redacted before reaching upstream, got: {upstream_saw}"
    );
    assert!(
        !resp_body.contains("agent@corp.example"),
        "raw email in the response must be redacted before the client, got: {resp_body}"
    );

    // --- 2. request with a CN phone (unauthorized_action=block) is blocked ---
    let blocked = client
        .post(format!("http://{stub_addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"call me at 13800138000"}]}"#)
        .send()
        .await
        .expect("blocked request still gets a proxy response");
    assert_eq!(
        blocked.status(),
        403,
        "phone (block policy) must be short-circuited with 403"
    );

    // --- 3. audit + metrics parity: the MITM path must have emitted audit records ---
    let records = audit.snapshot();
    assert!(
        records.iter().any(|r| r.direction == "request"
            && r.decision == "redact"
            && r.matched_labels.iter().any(|l| l == "email")),
        "MITM path must emit a request audit record showing the email redaction"
    );
    assert!(
        records
            .iter()
            .any(|r| r.direction == "request" && r.decision == "block"),
        "MITM path must emit an audit record for the blocked phone request"
    );

    let _ = tx.send(());
    let _ = proxy_task.await;
}
