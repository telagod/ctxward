<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Smoke / Live 验证

> 这些目标都不是"跑一次就完"——它们是**网关产品的活体验尸**：起本地 stub upstream + gateway，验证真实路径上的指标、审计、数据、降级语义。任何一条挂了，等于产品某个公开承诺不再成立。

## 全量入口

```bash
make test
make clippy
make smoke-admin
make smoke-session-correlation
make smoke-builtin-block
make smoke-builtin-regex
make smoke-pdf
make smoke-ooxml
make smoke-presidio
make smoke-presidio-fail
make smoke-attachment-presidio-fail
make smoke-response-json
make smoke-sse
make smoke-sse-fail
make smoke-bench-drift
make smoke-bench-gate
make bench-smoke
make bench-matrix
make bench-gate
make smoke-all
```

## 逐项

- `make smoke-admin`
  - 起本地 stub upstream + gateway
  - 校验 `GET /admin/status` / `GET /admin/config-summary` / `GET /admin/reviews` / `GET /admin/audits` / `POST /admin/reviews/resolve` / `POST /admin/detokenize`
  - 证明：
    - request 命中 `review_required`
    - admin 批准后 replay 成功
    - 上游真实收到的是 tokenized 内容
    - detokenize 能回出原文
    - metrics / status / config-summary 三面一致
- `make smoke-session-correlation`
  - 用 `x-session-id` 先上传邮箱，再上传手机号，验证**多轮跨标签累积**会把第二次请求升级成 `409 review_required`
  - 随后由管理员 approve，并用 `x-review-ticket-id` replay 第二次请求
  - 同时校验：
    - 第二次首发请求未进 upstream，approve 后 replay 才成为第 2 次上游请求
    - review ticket / audit record 都带 `session_id=sess-corr-1` 与 `session_escalated=true`
    - `gateway_active_sessions`、`gateway_review_events_total`、`review_override_approved` 与 request decision source 全部落账
- `make smoke-builtin-block`
  - 发两条纯内建 regex 命中的高敏请求：手机号、身份证号
  - 证明未授权调用方会直接收到 `403 blocked`，且这两条请求**都不会进入 upstream**
  - 同时校验 request 审计只记录脱敏后的 labels / hashes、`review.log` 保持空白、`gateway_policy_decisions_total{decision="block",source="builtin"}` 与 detection counters 正常落账
- `make smoke-pdf`
  - 做 simple text PDF live rewrite 取证
  - 证明上游真实收到的 PDF 已从 `admin@example.com` 改成 `a***@example.com`
  - 同时校验 request 审计命中 `/attachments/file/page/1`、`/readyz=true` 与 request/response decision metrics
- `make smoke-ooxml`
  - 做 `docx / xlsx / pptx` live rewrite 取证
  - 起本地 stub upstream + gateway，逐个上传 OOXML 附件
  - 证明上游真实收到的 XML 节点文本已从 `admin@example.com` 改成 `a***@example.com`
  - 同时校验 audit log 已记录：
    - `word/document.xml#text/0`
    - `xl/sharedStrings.xml#text/0`
    - `ppt/slides/slide1.xml#text/0`
- `make smoke-presidio`
  - 起本地 Presidio analyzer stub + upstream JSON + gateway
  - 发真实 `stream=false` 请求，证明 request / response 都仅靠 Presidio sidecar 驱动命中与脱敏
  - 顺手验证：
    - 上游真实收到的是 `邮箱 a***@example.com`
    - 客户端真实收到的是 `联系人 a***@example.com`
    - 中文前缀场景下 character offset -> UTF-8 byte offset 没有错位
    - `/readyz`、`/admin/status`、`/admin/config-summary`、`/metrics` 都回显 `presidio configured/reachable/status_code`
    - `gateway_detections_total{direction,label}` 与 `gateway_policy_decisions_total{direction,decision,source}` 已落账
    - audit log 中不含原始 `admin@example.com`
- `make smoke-presidio-fail`
  - 不起 Presidio sidecar，只起 upstream JSON + gateway
  - 先发一个仅含 `/model` 的请求，证明 request path 可过、但 response path 因 Presidio 不可达退化为：
    - `{"error":"response redacted by gateway"}`
    - `x-privacy-gateway-action: redact`
    - `gateway_processing_fallback_total{kind="processing_error_fallback"} == 1`
  - 再发一个真正需要扫描的请求，证明 request path 会在转发前直接返回：
    - `502 upstream_error`
    - 上游请求计数不增加
  - 同时校验：
    - `/readyz` 为 `ready=false`
    - `gateway_dependency_ready{dependency="presidio"} == 0`
    - `gateway_proxy_errors_total{stage="request_pre_upstream",kind="presidio"} == 1`
    - 第二条 hard-fail 会额外落一条 `policy_source=request_pre_upstream_error` 的 skeleton audit
    - 全部 audit 都不落原始 `admin@example.com`
- `make smoke-attachment-presidio-fail`
  - 不起 Presidio sidecar，只起 upstream + 开启 attachment scanning 的 gateway
  - 发真实 `multipart/form-data` 文本附件，证明附件抽取一旦需要 Presidio 扫描而 sidecar 不可达，会在 request 处理阶段直接返回：
    - `502 upstream_error`
    - 错误串含 `attachment text analysis failed`
    - 错误串含 `presidio request failed`
    - 上游请求计数保持 `0`
  - 同时校验：
    - `/readyz` 为 `ready=false`
    - `gateway_dependency_ready{dependency="presidio"} == 0`
    - 不会误记 `attachment_review_fallback`
    - 因 request processing 在 audit 前就中断，`audit.log` / `review.log` 都保持空白
- `make smoke-response-json`
  - 起本地 stub upstream JSON + OPA + gateway
  - 发送真实 `stream=false` 的 `/v1/chat/completions` 请求
  - 证明客户端收到的是完整 redacted body：
    - `{"error":"response redacted by gateway"}`
    - 且不再出现原始 `普通响应内容`
  - 同时校验：
    - 响应头保留 `content-type: application/json`
    - `x-privacy-gateway-action: redact`
    - `content-length` 已按 redacted body 重建为 `40`
    - audit log 中响应记录为 `decision=redact`、`policy_source=opa`、`decision_reason=response requires approval`
    - OPA sidecar 实际收到了 `direction=response` 且 `current_decision=allow` 的决策输入
- `make smoke-sse`
  - 起本地 stub upstream SSE + OPA + gateway
  - 发送真实 `stream=true` 的 `/v1/chat/completions` 请求
  - 证明客户端收到的是：
    - `data: {"error":"response redacted by gateway"}`
    - `data: [DONE]`
    - 且不再出现原始 `普通响应内容`
  - 同时校验：
    - 响应头保留 `content-type: text/event-stream`
    - `x-privacy-gateway-action: stream`
    - stream body 不再携带 `content-length`
    - audit log 中响应记录为 `decision=redact`、`policy_source=opa`、`decision_reason=stream policy denied`
    - OPA sidecar 实际收到了 `direction=response` 的决策输入
- `make smoke-sse-fail`
  - 不起 Presidio sidecar，只起 upstream SSE + gateway
  - 发一个 request path 可过的 `stream=true` 请求，证明 response SSE event 因 sidecar 失联会退化为：
    - `data: {"error":"response redacted by gateway"}`
    - `data: [DONE]`
    - 同时保持 `x-privacy-gateway-action: stream`
  - 同时校验：
    - `/readyz` 为 `ready=false`
    - `gateway_dependency_ready{dependency="presidio"} == 0`
    - `gateway_processing_fallback_total{kind="json_processing_error_fallback"} == 1`
    - audit 的响应收口为 `policy_source=json_processing_error_fallback`
- `make smoke-bench-drift`
  - 不跑真实压测，直接构造 benchmark `summary.json` + older `baseline.json`
  - 起本地 gateway，活体验证 `GET /admin/status` 会正确给出：
    - `regressions / improvements / unchanged / missing_in_baseline`
    - `gate.loaded / gate.status / gate.fresh / gate.rows / gate.failures`
  - 同时校验 `GET /admin/config-summary` / `/admin`：
    - `benchmarks.gate_report_json_path` 已回显
    - admin console 已挂载 `Gate verdict / Gate report / gate failure captured`
  - 随后调用 `POST /admin/benchmarks/promote`
  - 证明 promote 后 baseline compare 回到全量 `unchanged`
  - 且旧 gate report 会被识别为 `stale`
- `make smoke-bench-gate`
  - 不起网关，直接伪造 pass/fail 两组 `summary.json + baseline.json`
  - 证明 `scripts/bench_regression_gate.py`：
    - 对 `regression` 会返回非零退出码
    - 对 `new` 默认只记账，不默认 fail
    - 会把 gate 结果写入 `gate-report.json`
- `make bench-smoke`
  - 保留最快的单场回归：`json-redact`
  - 起本地 stub upstream + gateway
  - 并发压一组固定 JSON request
  - 验证：
    - request/response 都发生 redact
    - `gateway_payload_processing_duration_seconds`
    - `gateway_upstream_duration_seconds`
    - p95 延迟与吞吐达到 smoke 阈值
- `make bench-matrix`
  - 跑分场景性能矩阵，统一产物落到 `.tmp-smoke/bench-matrix/`
  - 默认每个场景连跑 `3` 次，按 `median` 聚合成最终 `summary.json`
  - 当前覆盖：
    - `json-redact`
    - `json-tokenize`
    - `json-review-replay`
    - `json-opa`
    - `json-presidio`
    - `pdf-redact`
  - 总表输出：
    - `.tmp-smoke/bench-matrix/summary.json`
    - `.tmp-smoke/bench-matrix/report.txt`
  - 可用 `RUNS=1 make bench-matrix` 退回单次采样
- `make bench-gate`
  - 读取 `.tmp-smoke/bench-matrix/summary.json` 与 `baseline.json`
  - 按与控制面一致的 compare 阈值判断 regression / improvement / unchanged / new
  - 对 avg / p95 latency 额外叠加 absolute noise floor，避免 4~5ms 热路径里亚毫秒抖动被误判成 regression
  - 若 `aggregation.sample_runs` 存在，还会做 sample-range overlap 判定：只有当百分比阈值触发，且 current / baseline 的波动区间已经彻底错开，才升级成真正的 regression / improvement；否则记作 `unchanged` 并在文本输出标出 `noise-suppressed=...`
  - 若 `summary` 与 `baseline` 的 aggregation 代际不一致（如 `median-of-3` 对 `single-run`），gate 会先报 `aggregation mismatch`，要求先 promote baseline，再把结果当 release-blocking regression
  - 默认 `regressions > 0` 即 fail，退出码非零
  - 默认不因 `new` fail；若要把未入基线场景也视作阻断，可加 `--fail-on-new`
- `make bench-ci`
  - 串行执行 `bench-matrix -> bench-gate`
  - 适合在 CI 里作为专用 bench job，避免与其他重任务并发污染采样
- `make bench-promote`
  - 把当前 `.tmp-smoke/bench-matrix/summary.json` 直接固化为 `baseline.json`
  - 适合在 benchmark aggregation 策略切换后，先把 baseline 代际刷正，再继续跑 gate

详见 `scripts/smoke-*.sh` 与 `scripts/bench_*.py`。
