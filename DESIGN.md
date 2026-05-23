# DESIGN

## 目标

构建一层放在业务系统与大模型 API 之间的轻量隐私门禁：

1. 请求必须先过身份认证与策略判断。
2. 敏感数据优先本地检测，不依赖外部重型组件。
3. 决策结果支持 `allow / redact / review / block`。
4. 所有日志只保留脱敏后的证据与命中元数据。
5. 默认高可观测，便于被平台化托管。

## 非目标

- 暂不处理图片 OCR、扫描版 PDF 与加密附件；当前先覆盖文本型附件、可抽文本的 PDF，以及可结构级回写的 OOXML。
- 暂不内置多级审批编排、通知、多人会签与完整管理 UI；当前只提供轻量 ticket、approve/reject 与 replay 放行。
- 暂不把 OPA / Presidio 作为硬依赖，避免把核心路径做重。

## 架构

```text
caller ──Bearer API key──▶ context-gurd
                               │
                               ├─ auth: principal / tenant / role / clearance
                               ├─ detector: regex + entropy + optional Presidio
                               ├─ attachment extractor: multipart + pdf text + ooxml node rewrite
                               ├─ session store: x-session-id correlation
                               ├─ policy: builtin + optional OPA
                               ├─ audit: redacted jsonl only
                               ├─ metrics: prometheus
                               ▼
                           upstream llm api
                               │
                               └─ response filter: json + sse
```

## 关键设计决策

### 1. Axum + Reqwest，而不是 Envoy/WASM

- **原因**：当前目标是快速做出产品级 MVP，Rust 端直接掌控检测与脱敏逻辑最顺手。
- **收益**：轻量、单二进制、易扩展。
- **代价**：若后续要做超大规模 mesh，可再外置成 sidecar 或迁移到 Envoy ext-auth。

### 2. 内建策略 + OPA 双层决策

- **原因**：快速路径仍由本地 Rust 决策兜底，复杂 PBAC / 合规规则交给 OPA 热更新。
- **收益**：既保留轻量高性能，又能外接策略中心。
- **代价**：会多一次本地网络 hop；若 OPA 不可用，需要 fail-open/fail-close 策略。

### 3. 审计只存 hash / label / decision，不存原文

- **原因**：网关本身不能变成新的泄露点。
- **收益**：最小化日志敏感面。
- **代价**：纯靠审计无法复原原始文本；如要可逆 tokenization，后续可接 KMS/Vault。

### 4. 响应过滤默认开启

- **原因**：仅拦上传不够，模型可能回吐历史 prompt。
- **收益**：双向 DLP。
- **代价**：JSON 响应会被额外解析，SSE 会做事件级扫描，增加少量 CPU 开销。

### 5. Presidio 作为可选 analyzer sidecar，而不是硬依赖

- **原因**：NER 能力重要，但 Python/NLP 运行时不应拖重 Rust 主进程。
- **收益**：主网关保持轻量；需要更高召回时，再外接 analyzer。
- **代价**：会增加一次 sidecar RTT，需要 fail-open/fail-close 策略与超时控制。

### 6. Regex 第一个 capture group 作为有效命中片段

- **原因**：Unicode `\b` 在中文等 CJK 邻接文本里容易漏检，例如 `手机号13800138000`。
- **收益**：规则可用“外围边界 + 内层 capture group”方式精确截取敏感值，既降低漏检，又不把边界字符写进审计与脱敏输入。
- **代价**：规则作者需要显式约定：若写了 capture group，第一个 group 必须包住真实敏感片段。

### 7. 可逆 tokenization 由 Rust 主进程内建，而不是先依赖外部 anonymizer

- **原因**：产品目标是轻量、高性能、少依赖。若每次脱敏都额外 RPC 到 Python anonymizer，会把热路径变重。
- **收益**：regex / entropy / Presidio findings 可共用一套本地 tokenization，延迟更稳，也便于统一审计与管理面 detokenize。
- **代价**：密钥管理责任落在网关侧，后续需要接 KMS / Vault 做轮换、吊销、分租户隔离。

### 8. review 决策落地为内建审批队列，而不是只返回错误码

- **原因**：单纯返回 `409 review_required` 不是产品能力，业务方无法闭环处理审批。
- **收益**：网关自身维护轻量审批 ticket 队列，管理员可查询与批准/拒绝，业务端可带 `x-review-ticket-id` 重放。
- **代价**：当前 override 仍是单实例短 TTL 状态，只能依赖本地 JSONL event log 在重启后恢复，不适合多实例共享，后续需外接 Redis / DB。

### 9. review 队列先用 JSONL event log 持久化，而不是立即引入数据库

- **原因**：产品当前强调轻量、单二进制、零额外依赖。review 状态本质是少量追加事件，天然适合 event log。
- **收益**：跨重启保活、排障简单、便于审计与导出，部署侧不需要先准备 Postgres/Redis。
- **代价**：多实例共享、并发写入协调、复杂查询能力有限，后续仍需要外部状态存储。

### 10. OOXML 附件按 XML text node 级 pointer 检测与回写

- **原因**：`docx/xlsx/pptx` 若只抽平面文本，会丢失节点边界，无法把命中的 span 安全写回 ZIP 内原 XML。
- **收益**：可把 `word/`、`xl/`、`ppt/` 下 XML 文本节点映射成稳定 pointer，再复用现有 detector / policy / redact 链，对命中节点做最小范围改写并重新封包转发。
- **代价**：当前 pointer 与 rewrite 粒度停留在 text node，尚未处理富文本 run 合并、公式/图表嵌字、加密 OOXML 等更复杂结构。

### 11. 响应侧策略升级必须改变真实输出，而不只写审计

- **原因**：若响应已经过内建脱敏，但随后被 OPA / 更高层策略升级为 `review` / `block`，仅在审计里记“更严决策”而继续把原响应返回，会造成真实泄露。
- **收益**：buffered JSON / text 响应在被升级后会直接切换到 redacted body；SSE 则按 event 即时替换为 redacted sentinel，保证“决策结果”和“实际输出”一致。
- **代价**：当 OPA 在响应侧基于更高层语义升级决策时，网关可能只能退化为通用 redacted sentinel，而无法构造更细粒度的保真改写。

### 12. 指标要记录“谁做的决定”，不只记录“结果是什么”

- **原因**：仅有 `allow/redact/review/block` 总量，不足以区分是 builtin、OPA、review override、还是 fallback 在生效，排障时会失真。
- **收益**：`gateway_policy_decisions_total{direction,decision,source}` 能直接看 request/response 最终决策来源；`gateway_review_events_total`、`gateway_review_queue_*`、`gateway_dependency_*`、`gateway_processing_fallback_total` 则补齐审批队列、依赖健康、降级路径这三块产品级可观测性。
- **代价**：指标维度变多，Prometheus 序列数会上升；因此当前只保留低基数标签（direction/decision/source/dependency/event/kind），避免把 path、principal 等高基数字段打进 counter。

### 13. 管理面先做内嵌静态控制台，而不是先上独立前端工程

- **原因**：产品当前强调轻量、单二进制、零额外前端构建链。若立即拆出 React/Vite 等独立工程，会增加部署体积、构建复杂度与版本漂移面。
- **收益**：`GET /admin` 直接由 Rust 二进制返回内嵌 HTML/CSS/JS，天然与 `/admin/status`、`/admin/reviews`、`/admin/audits`、`/admin/reload`、`/admin/detokenize` 同步演进，适合单实例和内网控制面场景。
- **代价**：前端工程化能力弱于独立 SPA；若后续管理台要扩展成多人协作、复杂图表、权限分层，再考虑外置独立前端。

### 14. benchmark 统一由 scenario harness 驱动，而不是为每条链路复制 shell 脚本

- **原因**：产品已经同时覆盖 builtin / tokenization / review / OPA / Presidio / PDF rewrite，多条热路径若各自维护一套 shell smoke，阈值、产物格式、端口与验证逻辑会很快漂移。
- **收益**：统一用 `scripts/bench_harness.py` 生成 config、起 stub sidecar、执行并发压测、抓 `/admin/status` + `/admin/config-summary` + `/metrics`，再汇总成标准 `report.json` / `summary.json`，便于横向比较与后续接 CI。
- **代价**：bench harness 自身变成关键测试资产，需要随能力扩展一起维护。

### 15. Presidio sidecar 返回的 offset 按 character index 解释，再映射回 UTF-8 byte offset

- **原因**：Presidio analyzer 的 `start/end` 是字符位置；Rust 字符串切片要求 byte offset。若直接把字符位置当 byte offset，用中文/CJK 前缀时会把敏感值切歪，导致 request rewrite 边界错位。
- **收益**：先构建字符边界表，再映射成 byte index，可稳定覆盖 `"邮箱 admin@example.com"` 这类多字节前缀场景，避免检测命中正确但实际 rewrite 错位。
- **代价**：每次 Presidio analyze 结果落地前多一次边界映射，但开销极低。

## 配置面

- `server`：监听地址、body limit
- `upstream`：上游地址、超时、附加认证头、透传头白名单
- `auth`：调用方 API key 摘要、角色、密级、允许上传的标签
- `detection.rules`：实体规则、正则、授权/未授权动作、掩码方式
- `detection.presidio`：analyzer URL、语言、实体映射、超时
- `tokenization`：是否启用、密钥环境变量名、token 前缀
- `attachments`：是否启用、单附件大小上限、抽取文本长度上限、允许抽取的 media type 白名单
- `review`：队列容量、preview 长度、审批 override TTL
- `review.jsonl_path`：review event log 路径
- `policy_backend.opa`：外部策略 URL、timeout、fail_open
- `session`：TTL、最大会话数、关联阈值、命中后的升级动作
- `response_filtering`：JSON / SSE 是否过滤
- `audit`：JSONL 路径、stdout 是否镜像

## 可观测性补充

- `readyz` 与 `/metrics` 都会更新：
  - `gateway_active_sessions`
  - `gateway_review_queue_pending`
  - `gateway_review_queue_capacity`
  - `gateway_dependency_configured{dependency}`
  - `gateway_dependency_ready{dependency}`
  - `gateway_dependency_status_code{dependency}`
- request / response 真实收口时统一记录：
  - `gateway_requests_total{direction,decision}`
  - `gateway_policy_decisions_total{direction,decision,source}`
- 若在进入上述收口前就硬失败，则额外记录：
  - `gateway_proxy_errors_total{stage,kind}`
  - 当前重点覆盖 `stage=request_pre_upstream`
  - `kind` 低基数归类为 `attachment / presidio / opa / tokenization / detector / runtime_io / upstream_url ...`
- review 生命周期记录：
  - `created`
  - `approved`
  - `rejected`
  - `override_approved`
  - `override_rejected`
- 以下降级源会计入 `gateway_processing_fallback_total{kind}`：
  - `attachment_review_fallback`
  - `json_processing_error_fallback`
  - `presidio_error_fallback`
  - `processing_error_fallback`
  - `opa_error_fallback`
  - `builtin_fail_open`
- `GET /admin/status` 不直接返回 Prometheus 文本，而是追加一份 `observability.metrics_summary`：
  - 仅聚合低基数关键 gauges / counters / histogram 摘要
  - 适合管理 UI 直接消费
  - 避免把高基数全量指标、PromQL 逻辑或完整 exposition format 强塞进管理面
- 若启用 `benchmarks.summary_json_path`，`GET /admin/status` 还会附带 `observability.benchmarks`：
  - 回显 benchmark matrix 的摘要、场景排行、baseline drift
  - 若 `gate_report_json_path` 存在且可解析，还会带上 benchmark gate 的 `pass/fail + fresh/stale + failure rows`
  - 不主动触发压测
  - summary 缺失时返回 `loaded=false + error`，不影响网关主链路
  - baseline 缺失时返回 `baseline.loaded=false + error`，不影响主链路
- `GET /admin/config-summary` 返回**当前生效配置的安全摘要**：
  - principal / allowed_labels
  - regex / high-entropy / Presidio entity 策略面
  - tokenization / session / attachments / review / audit / OPA / benchmark summary path 配置面
  - 只暴露 env 名、URL、开关、阈值、掩码类型，不暴露 secret 明文
  - 同时区分 `configured` 与 `env_present/runtime_loaded`，便于识别“配置了但当前没真正生效”的漂移
- `GET /admin` 当前内嵌控制台直接消费：
  - `GET /admin/status`
  - `GET /admin/config-summary`
  - `GET /admin/reviews`
  - `POST /admin/reviews/resolve`
  - `GET /admin/audits`
  - `POST /admin/reload`
  - `POST /admin/detokenize`
  - `POST /admin/benchmarks/promote`
  - 会把 `observability.metrics_summary.counters.proxy_errors_total` 额外渲染成：
    - hero 卡片 `Proxy hard-fails`
    - 状态表 `Pre-upstream failure radar`
  - 用于观察附件抽取 / Presidio analyze 等 request preprocessing 硬失败，而不是只看一条 `502 upstream_error`
  - 审计段会额外内嵌 `Latest hard-fails` 面板：
    - 后端直接复用 `GET /admin/audits?source=both&policy_source=request_pre_upstream_error&limit=N`
    - 点击单条事件可回填 `request_id / error_stage / error_kind / decision=block / direction=request` 到审计筛选
  - 审计筛选额外支持：
    - `policy_source`
    - `request_id`
    - `error_stage`
    - `error_kind`
  - 对 hard-fail skeleton audit 可直接筛：
    - `policy_source=request_pre_upstream_error`
    - `error_stage=request_pre_upstream`
    - `error_kind=attachment|presidio`
  - 同时会把 `observability.benchmarks` 渲染成“性能基线矩阵”与 regression 判官
  这样控制面与数据面共用同一 Bearer admin 鉴权，无额外 session / cookie 状态。

- 对 request preprocessing 在进入正常 request/response 收口前就硬失败的场景：
  - 仍返回 `502 upstream_error`
  - 不记 request policy decision / 不记 fallback metric
  - 但会补一条 **skeleton audit**：
    - `policy_source=request_pre_upstream_error`
    - `decision=block`
    - `status_code=502`
    - `matched_labels=[]`
    - `matched_rules=[]`
    - `findings=[]`
    - `decision_reason` 仅保留 `stage/kind + 已脱敏错误串`
  - 这样既保留追责链，也不把原始 request body 或敏感命中内容写入审计

## 验证策略

- 单测负责：
  - 策略决策
  - review / detokenize / admin API
  - 附件 rewrite（OOXML / simple PDF）
- `make smoke-admin` 负责：
  - 控制面 API 的活体验收
  - review -> approve -> replay -> upstream tokenization -> detokenize 的端到端链
  - `status` / `config-summary` / `metrics` 三面一致性
- `make smoke-session-correlation` 负责：
  - live 验证 `x-session-id` 会把同一会话里跨请求累积的 `email + phone` 升级成 `review`
  - 顺手证明第二次原始请求不会提前进 upstream，只有 approve + replay 后才会走 `review_override_approved`
- `make smoke-builtin-block` 负责：
  - live 验证纯内建 regex 的高敏规则（如 `phone_cn` / `china_national_id`）会直接返回 `403 blocked`
  - 顺手证明 upstream 请求计数保持 `0`，且 request block 审计与 detection / decision metrics 都只落脱敏元数据
- `make smoke-builtin-regex` 负责：
  - live 验证扩展内建 regex matrix（`ip_address` / `mac_address` / `imei` / `vin` / `bank_card`）的默认 `redact / block` 收口
  - 顺手证明低敏规则会重写后再进 upstream，高敏规则会直接阻断，且 audit / metrics 只保留脱敏证据
- `make smoke-bench-drift` 负责：
  - 不依赖真实压测结果，直接伪造 `summary.json` 与更旧的 `baseline.json`
  - live 验证 `GET /admin/status` 对 `regressions / improvements / unchanged / missing_in_baseline` 的 compare 逻辑
  - 顺手取 `/admin` 壳页，证明 benchmark watchlist / drift summary 控制面随服务一起发货
  - 再经 `POST /admin/benchmarks/promote` 验证 baseline 固化后回到全量 `unchanged`
- `make smoke-bench-gate` 负责：
  - 不起服务，直接伪造 pass/fail 两组 benchmark summary/baseline
  - 验证 `scripts/bench_regression_gate.py` 的退出码、分类与 `gate-report.json`
- `make smoke-pdf` 负责：
  - simple text PDF live rewrite 取证
  - 起本地 stub upstream + gateway，验证 forwarded PDF 已脱敏、审计 pointer 落在 `/attachments/file/page/1`，且运行态 `/readyz` / metrics 保持一致
- `make smoke-ooxml` 负责：
  - `docx / xlsx / pptx` live rewrite 取证
  - 证明 OOXML ZIP 内 XML text node 在命中 `redact` 后已重写再转发
  - 顺手验证 audit log 节点级 pointer（`word/`、`xl/`、`ppt/`）随请求落账
- `make smoke-presidio` 负责：
  - 起本地 Presidio analyzer stub + upstream JSON + gateway
  - live 验证 request / response 两侧都能仅依赖 Presidio findings 触发脱敏，不混入 regex 命中
  - 顺手验证中文前缀场景下的 character offset -> UTF-8 byte offset 转换、`/readyz` 与管理面依赖状态、Prometheus dependency/detection counter，以及 audit log 不落原始明文
- `make smoke-presidio-fail` 负责：
  - 不起 Presidio sidecar，只保留 gateway + upstream
  - live 验证 sidecar 不可达时两类真实语义：
  - response path 退化为通用 redacted body，并落 `processing_error_fallback`
  - request path 在需要 Presidio 扫描时直接 `502 upstream_error`，不把未审数据放上游
  - 顺手验证 `/readyz=false`、dependency gauge 变红、`gateway_proxy_errors_total{stage="request_pre_upstream",kind="presidio"} == 1`、上游计数不增加，以及 audit 不落原始明文
- `make smoke-attachment-presidio-fail` 负责：
  - 不起 Presidio sidecar，只保留 gateway + upstream，并开启 attachment scanning
  - live 验证 `multipart/form-data` 文本附件在 request 处理阶段一旦需要 Presidio analyze，会直接冒泡成 `502 upstream_error`
  - 顺手证明这条链不是 `attachment_review_fallback`：
    - 上游请求计数保持 `0`
    - `gateway_processing_fallback_total` 不新增 `attachment_review_fallback`
    - `gateway_proxy_errors_total{stage="request_pre_upstream",kind="attachment"} == 1`
    - request processing 在 audit / review 落账前就中断，因此 `audit.log` 与 `review.log` 保持空白
- `make smoke-sse-fail` 负责：
  - 不起 Presidio sidecar，只保留 gateway + upstream SSE
  - live 验证流式 JSON event 在 sidecar 不可达时会退化为 stream sentinel `data: {"error":"response redacted by gateway"}`，而不是整条连接直接 502
  - 顺手验证 `json_processing_error_fallback` 指标、`/readyz=false`、dependency gauge 与响应审计的 `policy_source`
- `make smoke-response-json` 负责：
  - 起本地 stub upstream JSON + OPA + gateway
  - live 验证 buffered JSON 响应一旦被 OPA 升级为非 `allow`，客户端真实收到的是通用 redacted body，而不是原始模型文本
  - 顺手验证 `x-privacy-gateway-action=redact`、`content-length` 已按 redacted body 重建，以及 audit / OPA 输入中 `policy_source=opa`、`decision_reason=response requires approval`
- `make smoke-sse` 负责：
  - 起本地 stub upstream SSE + OPA + gateway
  - live 验证响应侧一旦被 OPA 升级为非 `allow`，客户端真实收到的是 redacted SSE sentinel，而不是原始 event 内容
  - 顺手验证 `x-privacy-gateway-action=stream`、无 `content-length` 的流式响应头，以及 audit / OPA 输入中 `policy_source=opa`、`decision_reason=stream policy denied`
- `make bench-smoke` 负责：
  - 保留最轻的单场回归（当前为 `json-redact`）
  - 继续作为“轻量、高性能”目标的最快 smoke 证据
- `make bench-matrix` 负责：
  - 分场景压测 `json-redact / json-tokenize / json-review-replay / json-opa / json-presidio / pdf-redact`
  - 每场默认跑 `3` 轮，把单轮 artifacts 落到 `runs/run-*`
  - 再按 `median` 聚合 `throughput / avg / p95 / payload / upstream`，输出聚合后的 `report.json` / `aggregation.json`
  - 汇总生成 `.tmp-smoke/bench-matrix/summary.json` 与 `report.txt`，作为功能路径与性能基线矩阵
  - 若 baseline 尚不存在，会自动初始化 `.tmp-smoke/bench-matrix/baseline.json`
- `make bench-gate` 负责：
  - 读取 `summary.json` / `baseline.json`
  - 按与控制面一致的 compare 阈值给出 `regression / improvement / unchanged / new`
  - 对 hot path latency compare 叠加 absolute noise floor，避免亚毫秒抖动在百分比上被放大后误杀
  - 若 scenario 自带 `aggregation.sample_runs`，再做 sample-range overlap guard：只有 current / baseline 波动带完全错开时，raw delta 才升级成 release-blocking regression；否则保留 `unchanged` 并标注 `noise-suppressed`
  - 输出 `gate-report.json`
  - 若 summary/baseline 的 aggregation 代际不一致，先返回 `aggregation mismatch`，避免把 `single-run` baseline 与 `median-of-N` summary 直接混比
  - 默认 `regressions > 0` 直接 fail，作为 CI / release gate 的最小实现
- `make bench-ci` 负责：
  - 串行执行 `bench-matrix -> bench-gate`
  - 作为 CI 中的专用 bench job 入口，尽量隔离其它重型 smoke / build 并发对吞吐与延迟采样的污染
- `make bench-promote` 负责：
  - 把当前 `summary.json` 固化为 `baseline.json`
  - 作为 aggregation 策略切换后的 baseline 迁移闸门
  - `make smoke-bench-drift` 会把这份 `gate-report.json` 再接回 `/admin/status` 与 admin console，验证 fresh/stale 语义与 gate failure 展示链

## 安全考量

- Bearer secret 在配置中只保存 SHA-256 摘要。
- 不透传内部鉴权头到上游。
- Hop-by-hop 头统一剥离。
- 错误响应不回显原始敏感内容。
- 会话缓存只保留标签集合与指纹，不落明文。
- OPA 输入只传命中元数据与 principal，不传原始敏感明文。
- Presidio sidecar 当前会收到待分析文本，因此应部署在受控内网，并视作同一信任域组件。
- 对接 Presidio analyzer 时，必须把 sidecar 返回的 character offset 映射回 Rust UTF-8 byte offset；否则在中文等多字节前缀场景下会出现命中正确但 rewrite 错位的泄露风险。
- 附件抽取当前只在网关内存中处理，不应把原始附件内容写入审计与错误响应。
- OOXML 重写覆盖 XML text / CDATA 节点；PDF 当前新增了“简单文本型 content stream”回写能力，但若遇到复杂字体编码、扫描件、图片型文本或 `lopdf` 无法安全替换的内容，仍会回退为 `review`。
- 响应侧一旦被升级为非 `allow`，网关优先保证不泄露内容；在缺乏精细 rewrite 上下文时，会退化为通用 redacted body / SSE sentinel。
- 对 regex 规则，若使用 capture group 做边界兼容，只有第一个 capture group 会进入审计与脱敏链路。
- tokenization key 只从环境变量加载，不进入配置文件与审计日志。
- `POST /admin/detokenize` 只允许 `role=admin`，避免 token 被普通调用方逆推出原文。
- `POST /admin/reviews/resolve` 只允许 `role=admin`，并要求 replay 请求携带 `x-review-ticket-id`，且与原始 request bytes hash 匹配。
- review event log 采用追加写；若部署在不可靠磁盘或多 writer 环境，需升级为外部持久层。

## 后续路线

1. 接入 Presidio / 本地 NER sidecar。
2. 对接 Presidio anonymizer / KMS 托管 tokenization key。
3. 补图片 OCR、扫描版 PDF 与更多附件格式。
4. 增加审计查询 API 与前端管理台。
5. 引入策略版本管理、审批工作流与多租户隔离 UI。
6. 把 benchmark matrix 接到更长期的 CI / release baseline。
