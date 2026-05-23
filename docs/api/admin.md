<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Admin API

管理接口当前使用与业务请求相同的 Bearer principal 鉴权，但要求 `role=admin`。

## Endpoints

- `GET /admin/status`
  - 查看当前配置路径、上游、功能开关、审计缓冲区长度、会话数量
  - `features.attachment_scanning` 表示请求侧附件抽取是否启用
  - `observability.benchmarks` 会附带 benchmark matrix 摘要与 baseline drift（若 `benchmarks.enabled=true` 且 summary 可读）；若 `gate_report_json_path` 可读，还会附带 gate report verdict、fresh/stale 状态与 failure 摘要
- `GET /admin/config-summary`
  - 查看**当前生效**的策略面摘要：principal、regex/high-entropy 规则、Presidio/OPA、tokenization、session、attachments、review/audit 路径、benchmark summary path 等
  - 仅回显安全摘要，不暴露 bearer secret 或 tokenization key 明文
- `GET /admin`
  - 内嵌只读/轻交互管理台
  - 通过浏览器输入 admin Bearer token 后，可直接查看 status / metrics / config-summary / reviews / audits，并执行 reload 与 detokenize
- `GET /admin/audits`
  - 查询最近审计记录
  - 支持：`limit`、`source=memory|file|both`、`principal`、`decision`、`label`、`direction`、`session_id`、`policy_source`、`request_id`、`error_stage`、`error_kind`
- `POST /admin/reload`
  - 热重载配置
- `POST /admin/benchmarks/promote`
  - 把当前 `summary_json_path` 拷贝到 `baseline_summary_json_path`
  - 仅 `role=admin`
- `POST /admin/detokenize`
  - 仅 `role=admin`
  - body: `{"token":"[EMAIL_TOKEN:CGT1....]"}`
  - 返回 token 对应的 `label` 与原始 `value`
- `GET /admin/reviews`
  - 查询待审批或已审批 ticket
  - 支持：`status=pending|approved|rejected|all`
- `POST /admin/reviews/resolve`
  - body: `{"id":"<ticket_id>","approve":true,"note":"approved by secops"}`
  - 生成短 TTL override，供业务端带 `x-review-ticket-id` 重放同一请求

## Review event log

`review.jsonl` / 自定义 `review.jsonl_path` 会保存 review create/resolve event，用于：

- 重启后恢复 ticket 状态
- 在 TTL 未过期时恢复 approved/rejected override
- 轻量单实例部署
- 追加式审计追踪

## /readyz

`/readyz` 现在会主动探测已配置的 OPA / Presidio sidecar，可区分：

- `configured`
- `reachable`
- `status_code`
- `timeout_ms`

## /metrics（关键指标）

- `gateway_requests_total{direction,decision}`
- `gateway_policy_decisions_total{direction,decision,source}`
- `gateway_proxy_errors_total{stage,kind}`
- `gateway_detections_total{direction,label}`
- `gateway_review_events_total{event}` — `created / approved / rejected / override_approved / override_rejected`
- `gateway_review_queue_pending`
- `gateway_review_queue_capacity`
- `gateway_dependency_configured{dependency}`
- `gateway_dependency_ready{dependency}`
- `gateway_dependency_status_code{dependency}`
- `gateway_processing_fallback_total{kind}`
  - `attachment_review_fallback / json_processing_error_fallback / presidio_error_fallback / processing_error_fallback / opa_error_fallback / builtin_fail_open`

`gateway_proxy_errors_total{stage,kind}` 专门覆盖**未进入 request/response audit 收口前**就硬失败的路径，例如：

- `stage="request_pre_upstream", kind="attachment"`：附件抽取 / 附件侧 Presidio analyze 失败
- `stage="request_pre_upstream", kind="presidio"`：普通 request text/json 侧 Presidio analyze 失败

## Admin Console (`GET /admin`)

- 顶部状态与 dependency 信号
- 生效策略面（principal / rules / integrations）
- review queue 审批页
- `Latest hard-fails` 面板，可直接拉最近的 `request_pre_upstream_error` skeleton audit 并一键套用到审计筛选
- audit filters + recent records
- reload / detokenize 工具位
- 直接消费 `GET /admin/status` 与 `GET /admin/config-summary`

`GET /admin/status` 还会附带 `observability.metrics_summary`：低基数关键 gauges / counters / histogram 摘要，适合管理 UI 直接展示，避免把高基数全量指标强塞进管理面。

## OpenAPI

完整契约 (planned for M2): `docs/api/openapi.yaml`。
