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
        r#"{"model":"gpt-test","reply":"please contact agent@corp.example for help","usage":{"prompt_tokens":11,"completion_tokens":7}}"#,
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

/// Build a proxy-mode [`AppState`]. `proxy_extra` is appended under `proxy:` in
/// the config YAML (e.g. intercept/signs_body lists). The returned
/// [`tempfile::TempDir`] guard must outlive the proxy (it owns the CA + config).
fn build_proxy_state(
    proxy_port: u16,
    proxy_extra: &str,
) -> (Arc<context_gurd::app::AppState>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path().to_path_buf();

    let mut config: AppConfig =
        serde_yaml::from_str(include_str!("../config/example.yaml")).unwrap();
    config.mode = Mode::Proxy;
    let proxy_yaml = format!(
        "listen_addr: \"127.0.0.1:{proxy_port}\"\nca_dir: \"{}\"\n{proxy_extra}",
        temp_path.join("certs").display()
    );
    let proxy_cfg: ProxyConfig = serde_yaml::from_str(&proxy_yaml).unwrap();
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

    let (state, _temp_guard) = build_proxy_state(proxy_port, "");
    let audit = state.audit_store.clone();
    let metrics = state.metrics.clone();
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
        .body(r#"{"model":"gpt-test","messages":[{"role":"user","content":"email me at zhangsan@corp.example"}]}"#)
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

    // --- 4. token/cost metering: request model + response usage counted ---
    let snap = metrics.snapshot();
    assert!(
        snap["counters"]["llm_requests_total"]["gpt-test"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "llm_requests_total should count the gpt-test request: {snap}"
    );
    assert_eq!(
        snap["counters"]["llm_tokens_total"]["gpt-test"]["prompt"]
            .as_u64()
            .unwrap_or(0),
        11,
        "prompt tokens metered from the response usage object"
    );
    assert_eq!(
        snap["counters"]["llm_tokens_total"]["gpt-test"]["completion"]
            .as_u64()
            .unwrap_or(0),
        7,
        "completion tokens metered from the response usage object"
    );

    let _ = tx.send(());
    let _ = proxy_task.await;
}

/// signs_body hosts (e.g. AWS SigV4) are intercepted for detection/audit, but
/// the request body must reach the upstream *unmodified* so the signature stays
/// valid. Here the stub host is in both intercept and signs_body: the email is
/// detected (audited) but the upstream sees the original, un-redacted body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_signs_body_preserves_original_request_body() {
    let (stub_addr, captured) = start_echo_stub().await;
    let stub_host = stub_addr.ip().to_string(); // "127.0.0.1"
    let proxy_port = free_port();
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    let proxy_extra = format!(
        "intercept:\n  - kind: exact\n    value: \"{stub_host}\"\nsigns_body:\n  - kind: exact\n    value: \"{stub_host}\"\ndefault_action: passthrough\n"
    );
    let (state, _temp_guard) = build_proxy_state(proxy_port, &proxy_extra);
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

    let resp = client
        .post(format!("http://{stub_addr}/v1/chat"))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"email me at signed@corp.example"}]}"#)
        .send()
        .await
        .expect("request through proxy");
    assert_eq!(resp.status(), 200);
    let _ = resp.text().await;

    // signature-preserving: upstream receives the ORIGINAL email, un-redacted.
    let upstream_saw = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        upstream_saw.contains("signed@corp.example"),
        "signs_body host must receive the original body unmodified, got: {upstream_saw}"
    );
    // ...but detection still happened and was audited.
    let records = audit.snapshot();
    assert!(
        records
            .iter()
            .any(|r| r.direction == "request" && r.matched_labels.iter().any(|l| l == "email")),
        "signs_body host must still detect + audit the email (just not modify the body)"
    );

    let _ = tx.send(());
    let _ = proxy_task.await;
}
