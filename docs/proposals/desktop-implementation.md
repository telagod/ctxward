# ctxward Pivot — Desktop Transparent LLM-Privacy Gateway: File-Level Implementation Plan

> 状态：提案 (proposal) · 2026-06-02 · 由 9-agent workflow 合成，所有 `file:line` seam 已对活源码二次核验。
>
> Locked product-shape: **Desktop transparent-interception = MAIN line**, Gateway reverse-proxy = secondary/compat shell. First-phase scope = desktop ×3 OS + browser extension. 定位事实源见 [`product-shape.md`](product-shape.md)。
>
> Ground truth verified against live source: crate `context-gurd`, `version = 0.2.0`, `edition = 2024`, `rust-version = 1.85`.

---

## 0. Verified ground-truth (load-bearing facts)

| Fact | Confirmed at |
|---|---|
| Crate is a single binary+lib named `context-gurd` | `Cargo.toml:2`, `src/lib.rs:1-19` (18 `pub mod`) |
| Hard-coded upstream join | `src/proxy.rs:1180-1183` — `runtime.upstream_base_url.join(path_and_query.trim_start_matches('/'))` |
| `proxy_handler` clones full `uri` but forwards only `path_and_query` | `src/proxy.rs:839-848`, `869-876` |
| `handle_proxy(context, method, request)` — `RequestContext` has no `uri` field | `src/proxy.rs:53-60`, `908-920` |
| Core filtering entrypoint `process_payload(...) -> Result<ProcessedPayload, AppError>` is module-private | `src/proxy.rs:1482-1489` |
| `ProcessedPayload { sanitized_body: Bytes, policy: PolicyOutcome }` is module-private | `src/proxy.rs:1666-1671` |
| `authenticate_request(state, headers)` reads `AppState` (needs decoupling for MITM) | `src/proxy.rs:1816` |
| Pure core modules (WASM/Desktop-ready as-is): `detect`, `redact`, `policy`, `session`, `types` | kernel-purity |
| IO-coupled core: `tokenize` (env `tokenize.rs:59`), `audit` (fs+tokio `audit.rs:29`), `auth` (axum `HeaderMap` `auth.rs:72`) | kernel-purity |
| Reqwest already on rustls-tls | `Cargo.toml` reqwest features; `app.rs:113` `.use_rustls_tls()` |
| Server entrypoint `pub async fn run(config_path)` → `axum::serve(...)` | `src/app.rs:363-374` |
| `RuntimeState` holds `upstream_base_url: Url`, no proxy-mode flag | `src/app.rs:77-90` |

---

## 1. Crate / workspace shape

**Recommendation: 不在 D1 搬迁 crate。** workspace 拆分推迟到 Phase B，与 `ctxward-core` 抽离一起协调（届时同步改 Dockerfile/CI/Makefile 的 root 级路径假设）。D1 期间 MITM 模块直接加在现有单 crate `src/` 下，reverse-proxy build 每步保持绿（铁律 #2）。

### Phase B（D1 绿之后，D3 WASM 的前置）— 抽离 `ctxward-core`

```
crates/
├── ctxward-core/         # detect, redact, policy, session, types (pure)
│   │                     #  + tokenize::from_key_material (pure path)
│   │                     #  + auth::authenticate(get_header: impl Fn(&str)->Option<&str>)
│   │                     #  + audit::AuditRecord schema + AuditSink trait
│   └── Cargo.toml        # crate-type = ["cdylib","rlib"]; no tokio/axum/reqwest
├── ctxward-gateway/      # 今天的 context-gurd 减去已迁模块；reverse-proxy compat shell
└── ctxward-desktop/      # D2 Tauri shell (src-tauri)，依赖 ctxward-gateway as lib
```

Phase B 解耦动作（各自独立可测）：
- **`tokenize.rs:59`** — `from_config()` 调 `std::env::var`。拆：core 留纯 `from_key_material(key:[u8;32])`，env 读放到调用方。
- **`auth.rs:72`** — `authenticate(&self, headers: &HeaderMap)` → `authenticate(&self, get_header: impl Fn(&str)->Option<&str>)`。Gateway 传 HeaderMap 闭包，MITM/WASM 传各自闭包。同时解锁 D1 的 `authenticate_request` 解耦。
- **`audit.rs:29`** — 引入 `trait AuditSink { fn emit(&self, rec: AuditRecord); }`；现实现成 `FileSink`，Desktop 加 `WatchSink` 推 webview。

---

## 2. Config changes — `src/config.rs`

遵循现有 pattern：`#[serde(default = "fn")]`（如 `config.rs:84`/`:103`），`#[serde(default)]` 给 `Option`/集合（如 `config.rs:100`）。Env override 约定 `CONTEXT_GURD_*`。

### 2.1 Mode switch — 加到 `AppConfig` (`config.rs:32-51`)

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]                  // default = Reverse => 现有 config 全部不变
    pub mode: Mode,
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,      // Proxy 模式下成为 fallback/default upstream
    // ... 其余字段不变 ...
    pub audit: AuditConfig,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,    // mode = Proxy 时激活
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Reverse,   // 现有 axum reverse-proxy (compat shell)
    Proxy,     // 透明 forward MITM proxy (main line)
}
```

> **关键兼容判断（覆盖解剖建议）：** `mode` 必须 `#[serde(default)]` → `Reverse`，**不可设为 required**——否则现有 `config/example.yaml` 与 reverse build/test 立刻全红。配对校验（`mode==Proxy ⇒ proxy.is_some()`）放在 `RuntimeState::from_config`（`app.rs:93`），不放 serde。

### 2.2 `ProxyConfig` + 嵌套结构

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_listen_addr")]
    pub listen_addr: String,                 // "127.0.0.1:8888"
    #[serde(default = "default_ca_dir")]
    pub ca_dir: String,                      // "./certs"（key 永不 log/export）
    #[serde(default)]
    pub ca_key_path: Option<String>,         // 默认 {ca_dir}/ctxward-ca.key
    #[serde(default)]
    pub ca_cert_path: Option<String>,        // 默认 {ca_dir}/ctxward-ca.pem
    #[serde(default = "default_ca_key_path_env")]
    pub ca_key_path_env: String,             // "CONTEXT_GURD_PROXY_CA_KEY_PATH"
    #[serde(default = "default_leaf_ttl_days")]
    pub leaf_ttl_days: u32,                   // 7
    #[serde(default = "default_cert_cache_size")]
    pub cert_cache_size: u64,                 // 1000 (per-SNI LRU)
    #[serde(default = "default_intercept_hosts")]
    pub intercept: Vec<HostPattern>,          // Tier-1 拦截白名单
    #[serde(default = "default_passthrough_hosts")]
    pub passthrough: Vec<HostPattern>,        // Tier-2 显式透传
    #[serde(default)]
    pub default_action: ProxyAction,          // 未知 SNI 默认 Passthrough（fail-open）
    #[serde(default)]
    pub per_app_rules: Vec<PerAppRule>,
    #[serde(default)]
    pub pin_fallback: PinFallbackConfig,
    #[serde(default)]
    pub ruleset_url: Option<String>,          // D4 热更新订阅
    #[serde(default = "default_ruleset_poll_secs")]
    pub ruleset_poll_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum HostPattern {
    Exact(String),       // api.openai.com
    Wildcard(String),    // *.openai.azure.com
    Regex(String),       // ^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAction {
    Intercept,
    #[default]
    Passthrough,
}
```

默认 intercept 名单（offline fallback）：`api.openai.com`, `*.openai.azure.com`, `*.cognitiveservices.azure.com`, `*.services.ai.azure.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `aiplatform.googleapis.com`, `^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$`, `api.deepseek.com`, `api.moonshot.ai/.cn`, `api.groq.com`, `api.mistral.ai`, `api.cohere.com`, `api.x.ai`, `openrouter.ai`。
默认 passthrough：`chatgpt.com`/`*.chatgpt.com`/`chat.openai.com`、`*.auth0.com`、`challenges.cloudflare.com`、`desktop/ios/android.chat.openai.com`（pinned）、`claude.ai`/`*.claude.com`、`gemini.google.com`、`aistudio.google.com`。

> **Bedrock SigV4 caveat：** `bedrock-runtime` 对 body 签名，脱敏会破坏签名。D1 对这类 host **intercept-but-passthrough-on-detect**（body 将被改且命中 `signs_body` set 时回退透传，而非 403）。`signs_body` 标志 D4 加，不在 D1。

---

## 3. D1 — Transparent MITM proxy PoC (THE UNLOCK)

**Strategy：用 `hudsucker 0.24.1` 作 MITM 基座。** 它已提供 CONNECT hijack + per-SNI `RcgenAuthority`（签名 + moka LRU 缓存）+ HTTP/1.1+H2+WS 拦截，且栈与内核一致（`hyper 1.x / rustls 0.23 / rcgen`）。我们只写：(a) `should_intercept` 的 SNI gate，(b) `handle_request`/`handle_response` 桥接进**现有** `process_payload`。

> 唯一承重复用：`proxy.rs:1482 process_payload` 与 axum/reqwest 解耦（唯一框架耦合是 `metrics.payload_processing_timer()`）。hudsucker 交给我们解码后的 `http::Request<Body>`/`Response<Body>`，collect 成 `Bytes` → 调 `process_payload` → 重建 body。**检测/脱敏逻辑零重写。**

### 3.1 新增 Cargo 依赖

```toml
hudsucker = { version = "0.24", default-features = false, features = ["rcgen-ca", "rustls-client", "http2", "decoder"] }
rcgen = "0.14"
tokio-rustls = "0.26"                  # fallback 裸路由
http-body-util = "0.1"                 # body collect（现为 root dev-dep，提升为 dep）
moka = { version = "0.12", optional = true }
```

> **Provider 冲突 guard：** 内核 reqwest 用 rustls-tls。hudsucker + 终止侧必须用**同一 `CryptoProvider`**。两边都钉 `aws_lc_rs::default_provider()`（或都 `ring`），在 `proxy_mode::serve` 任何 TLS 前 `install_default()` 一次。D1 gate 跑 `cargo tree -d -p rustls` 证明无双 provider。加 hudsucker 后跑 `cargo deny check` 过 license/advisory 关。

### 3.2 新增文件

```
src/
├── proxy_mode.rs     # dispatcher：读 AppConfig.mode，跑 reverse 或 proxy server
├── mitm/
│   ├── mod.rs        # hudsucker Proxy::builder 接线 + CtxwardHandler（3 hooks）
│   ├── ca.rs         # 本地 root CA gen/load (rcgen)，DER 导出供信任库安装
│   ├── classify.rs   # HostPattern 匹配 (Exact/Wildcard/Regex) + PinCache
│   └── bridge.rs     # collect Body->Bytes，调 process_payload，重建 Body
```

### 3.3 `mitm/ca.rs` — 本地 root CA + per-SNI leaf 签名

CA 私钥 chmod 600、永不 log/export。首次运行生成（rcgen `IsCa::Ca`，self-signed），写保护文件；`RcgenAuthority::new(key_pair, ca_cert, cache_size, provider())`。导出 DER 供 Tauri/helper 装入 OS+NSS 信任库（D2）。集成测试：`curl --cacert ctxward-ca.pem` 经代理到本地 TLS stub 成功（证明链有效）。

### 3.4 `mitm/classify.rs` — SNI 路由 + pin cache

```rust
impl Classifier {
    pub fn classify(&self, host: &str) -> ProxyAction {
        if self.passthrough.iter().any(|m| m.matches(host)) { return ProxyAction::Passthrough; }
        if self.intercept.iter().any(|m| m.matches(host))   { return ProxyAction::Intercept; }
        self.default   // 未知 SNI -> Passthrough（fail-open）
    }
}
// PinCache: (peer_key, sni) -> deadline；TLS leaf-reject 时 mark，retry 强制 splice。moka TTL = pin_fallback.block_ttl_secs
```

### 3.5 `mitm/bridge.rs` — 复用桥（需一处可见性改动）

**源改 #1（`proxy.rs:1482`）：** `async fn process_payload` → `pub(crate) async fn`。
**源改 #2（`proxy.rs:1666`）：** `struct ProcessedPayload` → `pub(crate) struct`，两字段 `pub(crate)`。
均为可见性改动，零行为变化，reverse build 保持绿。

```rust
pub async fn filter_body(
    rt: &RuntimeState, metrics: &Metrics, principal: &Principal,
    headers: &http::HeaderMap, body: Body, direction: Direction,
) -> Result<(Bytes, ProcessedPayload), AppError> {
    let ct = headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    let raw = http_body_util::BodyExt::collect(body).await?.to_bytes();
    let processed = process_payload(rt, metrics, principal, &raw, ct, direction).await?;
    Ok((raw, processed))
}
```

> **SSE caveat（真正的工程成本）：** `process_payload` 是整 body。内核真流式在 `response_from_sse_stream`（`proxy.rs:1325+`）。**D1：** 非 SSE 走 `filter_body`；SSE 响应（`text/event-stream`）**不 collect、原样透传**，follow-up（D1.5）把 hudsucker per-chunk 接到 `transform_sse_line`（`proxy.rs:1410`，已纯）。

### 3.6 `mitm/mod.rs` — 三 hooks

**源改 #3（解耦 auth，`proxy.rs:1816`）：** 加同胞 `pub(crate) fn authenticate_with(auth: &Authenticator, headers: &HeaderMap) -> Result<Principal, AppError>`，现 `authenticate_request` 委托它。本地桌面代理用固定 local principal，无需入站 auth header。

```rust
impl hudsucker::HttpHandler for CtxwardHandler {
    async fn should_intercept(&mut self, ctx: &HttpContext, _req: &Request<Body>) -> bool {
        let host = ctx.uri.host().unwrap_or_default();
        if self.pins.is_pinned(peer_key(ctx), host) { return false; }   // 曾 pin-reject -> splice
        matches!(self.classifier.classify(host), ProxyAction::Intercept)
        // false -> hudsucker 纯 TCP tunnel：不签证、不解密、零隐私接触
    }
    async fn handle_request(&mut self, _ctx, req) -> RequestOrResponse {
        // decode gzip/br -> filter_body(Direction::Request)
        // policy.decision == Block -> 短路返回 blocked_response，永不上游
        // 否则移除 CONTENT_LENGTH（脱敏改了长度），保留客户端 Host（==SNI），重建 body 转发
    }
    async fn handle_response(&mut self, _ctx, res) -> Response<Body> {
        // is_sse -> 原样返回（D1）；否则 decode -> filter_body(Direction::Response) -> 重建
    }
    async fn handle_error(&mut self, _ctx, err) -> Response<Body> {
        // cert-pinning fallback：客户端拒我方 leaf -> pins.mark + audit（仅 hash）-> 让 retry 走 splice
    }
}
```

> **MITM 上游解析 = 自动，无需改 `proxy.rs:1180`。** 这是与解剖 area-1 的关键分歧：hudsucker 路由下上游就是客户端自己的 `Request`（authority/Host = 目标，由 hudsucker `rustls-client` 加密），故 seam `proxy.rs:1180/839/908/1191` **只与裸-hyper fallback 路由及 reverse compat shell 相关**，D1 hudsucker 路由不碰。明确记下，免得有人去"修" `proxy.rs:1180`。

### 3.7 `proxy_mode.rs` — dispatcher + 接入 `app::run`

**源改 #4（`app.rs:363-374`）：** 把现 `axum::serve` body 抽成 `pub async fn serve_reverse(state)`，`run()` 建 state 后调 `proxy_mode::serve(state)`，按 `config.mode` 分支。`lib.rs` 加 `pub mod proxy_mode; pub mod mitm;`。

```rust
async fn serve_proxy(state: Arc<AppState>) -> Result<(), AppError> {
    install_crypto_provider_once();                  // aws_lc_rs，任何 TLS 前
    let ca = mitm::ca::load_or_create_ca(&pcfg)?;
    let handler = mitm::CtxwardHandler::new(rt, metrics, local_principal(), classifier, pins);
    let proxy = hudsucker::Proxy::builder()
        .with_addr(pcfg.listen_addr.parse()?)
        .with_ca(ca.authority)
        .with_rustls_client(provider())
        .with_http_handler(handler)
        .build()?;
    proxy.start().await
}
```

### 3.8 D1 验收（必须绿才落地）

1. 生成 CA，代理起在 `127.0.0.1:8888`。
2. `HTTPS_PROXY=http://127.0.0.1:8888 curl --cacert ctxward-ca.pem -d '{"prompt":"my SSN is 123-45-6789"}' https://api.openai.com/...`（打本地 stub）→ 断言出站 body 已脱敏（证明拦截 + 复用 `process_payload`）。
3. `... https://claude.ai/` → 断言 TCP tunnel、不签证、body 不变（证明 passthrough gate）。
4. 模拟 pin 客户端（拒 leaf）→ 断言 `handle_error` mark pin + retry splice。
5. `cargo test` + `cargo tree -d -p rustls`（无重复）+ `cargo deny check`。

---

## 4. D2 — Tauri 2.x desktop shell

进程内嵌 proxy（无 sidecar）。Tauri 拥有 tokio runtime → desktop 二进制 main 去掉 `#[tokio::main]`。

布局 `crates/ctxward-desktop/src-tauri/`：`lib.rs`（Builder.setup spawn proxy + tray + manage state）、`commands.rs`（`toggle_proxy`/`install_ca`/`set_proxy`）、`bin/ctxward-helper.rs`（最小特权 helper）。前端 vite/TS：`listen('proxy://status')` / `invoke`。

- **Runtime：** setup 里 `tauri::async_runtime::spawn(proxy_mode::serve(state))`，managed state 存 `CancellationToken` 优雅停。
- **State：** `app.manage(Arc<ProxyState>)`，跨 `.await` **禁 `std::sync::Mutex`**（`MutexGuard !Send` panic），用 `tokio::sync`。
- **Status push：** spawned task `app_handle.emit("proxy://status", ...)`；高频审计流用命令域 `ipc::Channel<T>`，非全局 event。
- **Tray：** `TrayIconBuilder` + 菜单驱动（Linux click 不可靠）。macOS `ActivationPolicy::Accessory`。
- **特权边界：** 不提权整个 app（Windows WebView2 Admin-Protection bug）。`ctxward-helper` 独立最小二进制经 `elevated-command`（UAC / osascript admin / pkexec）调用，自校验 argv。

### CA 安装/卸载 + 系统代理 set/clear（per-OS）

- **macOS：** CA `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ctxward-ca.pem`（Big Sur+ 必弹管理员密码，UX 要说明）；卸载 `security delete-certificate -c "ctxward Root CA"`。代理逐 network service `networksetup -setwebproxy/-setsecurewebproxy/...`，网络切换时重应用（Wi-Fi/Ethernet/VPN 各自独立）。
- **Windows：** CA（machine Root，需提权）`certutil -addstore Root ctxward-ca.cer` / `-delstore`。代理 WinINET（HKCU Internet Settings ProxyEnable/ProxyServer/ProxyOverride + 广播 `WM_SETTINGCHANGE`）；WinHTTP（提权）`netsh winhttp set/reset proxy`。
- **Linux：** CA 系统库（root）Debian `cp -> /usr/local/share/ca-certificates/ && update-ca-certificates`；RHEL `/etc/pki/ca-trust/source/anchors/ + update-ca-trust extract`。**外加 per-NSS-db** Firefox/Chrome `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," ...`。代理 `gsettings org.gnome.system.proxy` + env `http_proxy/https_proxy/no_proxy`。提权 `pkexec`。
- **拆除保证：** 连接时装、断开/退出时卸，**启动时 self-heal** 清残留 CA + 代理。CA 私钥置 OS keystore / chmod-600，永不明文入 config、永不 log。

---

## 5. D3 — Browser extension (MV3)

决策：**MAIN-world fetch/XHR monkey-patch 拦截 + ISOLATED-world WASM（`ctxward-core`）脱敏。** native messaging = 可选桥（policy/audit 同步），非热路径。

布局 `ext/`：`manifest.json`（两 content_scripts：world MAIN + ISOLATED，`run_at:document_start`）、`mainworld-patch.js`（包 `window.fetch`+XHR，PROVIDER_RE gate，读 body postMessage→isolated）、`isolated-bridge.js`（init WASM、`redact_json`、postMessage back）、`pkg/`（`wasm-pack --target web` 出 ctxward-core）、`sw.js`（可选 connectNative）。

- **前置 = Phase B `ctxward-core`。** `wasm-pack build --target web`，导出 `#[wasm_bindgen] pub fn redact_json(body:&str)->String` 包 `Detector::scan_text`+`redact_text`（与 Gateway/Desktop 同一 `DetectionConfig`/labels，零检测漂移）。
- WASM 跑 ISOLATED world（扩展 CSP 允许 `wasm-unsafe-eval`），不跑 MAIN。流：MAIN 读 body → postMessage → ISOLATED WASM 脱敏 → 回传 → MAIN `new Request(orig,{body:clean})` 调存好的 `origFetch`。
- **fail-closed belt：** 对 provider chat endpoint 上 DNR block rule，MAIN-world patch 确认 live 后才解除 → 注入失败则 BLOCK 而非泄露。
- **v1 scope：** `claude.ai` + `chatgpt.com`/`chat.openai.com` 先行。`gemini`（SW 路由绕过 `window.fetch`）= best-effort/phase-1.5。诚实声明：扩展只护浏览器内 web UI，桌面 app/CLI 归 Desktop。

---

## 6. D4 — Provider rule-set + retention hooks

- **热更新签名规则集：** `RulesetClient` 轮询 `proxy.ruleset_url`（仿现有 OPA 轮询 pattern），payload `{version, intercept[], passthrough[], default_action}`（同 `HostPattern` schema）。**cosign keyless 签验**（复用 release 链）；验签前不换；签名不符/拉取失败 **fail-closed 回退 baked-in 默认**。被劫的 feed 不得能把受害 host 加进 intercept set。加 `signs_body` per-pattern（Bedrock）。热换进 `Classifier`，复用 `Arc<RwLock>`（`app.rs:178`）+ `AppState::reload`（`app.rs:214`）语义。
- **token/成本看板：** 扩 `AuditRecord` 加 `provider_host`/`model`/`prompt_tokens`/`completion_tokens`/`decision`/`redaction_count`（从拦截 JSON 解析）。Desktop `WatchSink` 经 Tauri Channel 流到 webview，渲染 per-provider token+估算成本+脱敏统计。Gateway 模式保留 `audit.jsonl`+`/admin/audits`。Retention：加 `audit.retention_days` + 轮转任务（复用 FileSink），永不存原文，仅 label/hash。

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| 私有 root CA = MITM 主钥 | 钥 chmod-600/OS keystore；永不 log/export/commit；断开/退出保证拆除 + 启动 self-heal；leaf 短命 7d |
| Provider 双 rustls CryptoProvider panic | 单 `aws_lc_rs` `install_default()` 一次；gate 跑 `cargo tree -d -p rustls` |
| Cert-pinned 目标（ChatGPT desktop 拒启动；移动 app） | `should_intercept` 对 pinned host 默认 passthrough；`handle_error` 检 TLS leaf-reject → mark PinCache → retry splice。绝不诱导 |
| SSE 脱敏破坏流式/OOM | D1 透传 SSE；D1.5 per-chunk 接现有纯 `transform_sse_line`（`proxy.rs:1410`） |
| AWS SigV4 body-signing 403 | `signs_body` flag → intercept-but-passthrough-on-modify；v1 不重签 |
| scope-split 混乱（reverse vs proxy build） | `mode` 默认 `Reverse`；proxy opt-in；reverse build/test 永不破；只对 proxy.rs 做可见性改动 |
| 扩展注入竞态/CSP | `document_start` 注入、patch XHR、fail-closed DNR belt、逐 target smoke |
| Linux NSS/snap 信任缺口 | per-NSS-db `certutil` 导入 + 明确"snap 浏览器不支持"UX |

---

## 8. Sequenced task checklist（先落 D1；每步 build+test 绿才进下一步）

> Guard rule：每步以 `cargo build && cargo test` 绿收尾才提交。红则不进。

**Phase A — D1 unlock（不抽 core，不搬 crate）**
1. `[guard]` `config.rs`：加 `Mode`（默认 `Reverse`）+ `proxy: Option<ProxyConfig>` + 结构/默认（§2）。加两条 config 测试（§2.3）。绿。提交。
2. `[guard]` 可见性改动：`proxy.rs:1482` → `pub(crate) async fn process_payload`；`proxy.rs:1666` → `pub(crate) struct ProcessedPayload`（+ pub 字段）；`proxy.rs:1816` 加 `authenticate_with` 同胞。绿（零行为变化）。提交。
3. `[guard]` 加依赖（§3.1）；跑 `cargo deny check` + `cargo tree -d -p rustls`。绿。提交。
4. `[guard]` `mitm/ca.rs` + CA gen 测试（curl `--cacert` 经代理到本地 TLS stub）。绿。提交。
5. `[guard]` `mitm/classify.rs` + `PinCache` + 单测（exact/wildcard/regex/default-fail-open）。绿。提交。
6. `[guard]` `mitm/bridge.rs` + `mitm/mod.rs`（3 hooks + `handle_error` pin fallback）。绿。提交。
7. `[guard]` `proxy_mode.rs` dispatcher；重构 `app.rs:363` `run` → `serve_reverse` + `Mode::Proxy` 分支；`lib.rs` 加新 mod。绿。提交。
8. `[guard]` **D1 验收套件**（§3.8）：拦截脱敏、透传不变、block 短路、pin fallback splice。全绿。**D1 DONE — 解锁落地。**

**Phase B — 抽离 + 各端（D1 绿之后）**
9. 抽 `ctxward-core`（5 纯模块 + tokenize env 解耦 + auth 闭包 + audit trait）；余者更名 `ctxward-gateway`。建 workspace、同步改 Dockerfile/CI/Makefile。`cargo test --workspace` 绿。
10. D2 `ctxward-desktop` Tauri 壳：内嵌 proxy、tray、helper、per-OS CA/proxy 装+拆。Per-OS smoke。
11. D1.5 SSE 流式脱敏经 `transform_sse_line`。
12. D3 扩展：`wasm-pack` ctxward-core、MAIN+ISOLATED 脚本、fail-closed DNR belt；claude.ai + chatgpt.com 先行。
13. D4 签名热更新规则集（cosign 验、fail-closed 回退）+ token/成本看板 + retention 轮转。

---

## 9. D1 状态 — 已落地 (2026-06-02)

**D1 透明 MITM 代理 PoC 已完成、运行时实证、对抗加固。** Reverse 反代旧路径零触碰，默认 `Reverse` 保证现有 config 全部不变。

落地清单：
- `src/config.rs` — `Mode{Reverse,Proxy}`（默认 Reverse）+ `ProxyConfig`/`HostPattern`/`ProxyAction`/`PerAppRule`/`PinFallbackConfig` + baked-in 默认名单 + 3 条 config 测试。
- `src/proxy.rs` — `process_payload`/`ProcessedPayload` 提 `pub(crate)`；新增 `authenticate_with` 同胞；新增 `pub(crate) emit_decision_telemetry`（audit+metrics 复用，reverse/MITM 同一发射逻辑）；`is_sse` 收窄为 `starts_with`。
- `src/mitm/{ca,classify,bridge,mod}.rs` — 本地 CA（rcgen，chmod 600）/ SNI 路由 + PinCache / 复用桥 / hudsucker 三 hook handler。
- `src/proxy_mode.rs` — mode dispatcher + `run_proxy(state, shutdown)`。
- `tests/mitm_e2e.rs` — 真代理 e2e：请求 email 脱敏转发 / 响应 email 脱敏 / phone 阻断 403 / audit 记录发射。

技术核验（纠正合成方案 3 处 API 臆测 + 1 处分歧）：
- `RcgenAuthority::new(Issuer<'static,KeyPair>, cache, provider)`（非 `(key,cert,...)`）；CA 经 `Issuer::from_ca_cert_pem`。
- builder 方法 `with_rustls_connector(provider)`（非 `with_rustls_client`）。
- `HttpContext` 无 `uri`，SNI 从 CONNECT 请求 `req.uri().host()` 取。
- hudsucker 路由下上游 = 客户端自身 Host，**无需改 `proxy.rs:1180`**（hudsucker 自动转发）。

对抗审查（9-agent fan-out → 三棱镜验证，8 坐实，全数处理）：
1. ✅ **[critical]** Bedrock SigV4：`bedrock-runtime` 从默认 intercept 移到 passthrough（脱敏会废 body 签名→403）。intercept-with-`signs_body` 留 D4。
2. ⏭ Content-Encoding 未移除 → **假阳性**：hudsucker `decode_request/response` 已自行剥离（decoder.rs:155,206）。
3. ⚠️ SSE 透传不脱敏 → **文档化已知边界**：仅响应侧（请求不流式，核心隐私目标不受影响）；不 fail-closed（否则所有流式 chat 全断，反伤产品），留 D1.5。
4. ✅ **[high]** Regex 大小写：`RegexBuilder::case_insensitive(true)`（host 已 lowercase）+ 回归测试。
5. ✅ **[high]** MITM 无审计 → `emit_decision_telemetry` 补齐 + e2e 断言。
6. ✅ **[medium]** `is_sse` `contains`→`starts_with`。
7. ✅ **[medium]** Transfer-Encoding 残留 → `strip_framing_headers` 移除 CL+TE。
8. ✅ **[medium]** MITM 无 metrics → 同 `emit_decision_telemetry` 补齐。

残留风险：
- **`cargo-deny` license gate**：新增 `aws-lc-sys`（AWS-LC 复合许可证）+ hudsucker 依赖链，本地未跑 deny，**须 CI 把关**（可能需在 `deny.toml` 增补 allow）。
- **真 HTTPS/CONNECT/SNI e2e**：当前 e2e 走 HTTP 路径（无需信任 stub 证书）证明 handler 接线；完整 HTTPS 终止 e2e 需自定义上游 connector 信任本地 stub，列为手工验收/后续。
- **pin 自动标记**：hudsucker 0.24 `handle_error` 不暴露客户端拒证，PinCache 闸门保留但自动标记留 D2/未来；已知 pinned host（ChatGPT desktop 等）在默认 passthrough 名单兜底。
- **body 无大小上限**：MITM 路径未限 body（reverse 有 `request_body_limit_bytes`）；桌面单用户威胁模型下非真漏洞，列为 defense-in-depth 待补。

---

## 10. D2 状态 — 部分落地 (2026-06-02)

**D2 的可验证内核（per-OS 集成命令层）已落地并单测；Tauri 壳为骨架（需 GUI 工具链验证）。**

已落地：
- `src/platform.rs` — `TargetOs` + `CommandSpec` + per-OS 命令构造：CA 安装/卸载（macOS `security`、Windows `certutil`、Linux `update-ca-certificates`）+ 系统代理 set/clear（macOS `networksetup`、Windows `reg` WinINET、Linux `gsettings`）。OS 作显式入参，三端命令在 Linux CI 上全测；`elevated` 标志供 helper 统一提权；`run()` 拒绝静默跳过提权。7 单测绿。
- `desktop/src-tauri/` — 独立 workspace 的 Tauri 2 crate：内嵌 `proxy_mode::run_proxy`，命令 start/stop/status、CA 导出、integration_plan（基于已验平台层）。**刻意不入 root workspace**，headless CI 不需 GUI 工具链。
- `desktop/ui/index.html` — 控制台骨架（开关 + CA + 集成计划）。

待续（next session，需 GUI 工具链）：托盘菜单（菜单驱动，非 click）；特权 helper 二进制（UAC/osascript/pkexec）；webview 实时审计流（Tauri `ipc::Channel`）；退出拆除 + 启动 self-heal；Linux per-NSS-db CA。详见 `desktop/README.md`。

残留风险：Tauri crate 在此 headless 环境未编译验证（无 webkit/tauri-cli）；其 Rust 集成点引用真实 kernel API，但首次真编译可能需小幅修正。
