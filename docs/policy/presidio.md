<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Presidio Integration

启用方式：

1. 在 `detection.presidio.enabled` 设为 `true`
2. 准备一个兼容 Presidio analyzer 的 HTTP 服务，例如：
   - `POST /analyze`
   - body:

   ```json
   {
     "text": "John lives in Seattle",
     "language": "en",
     "entities": ["PERSON", "LOCATION"]
   }
   ```

3. sidecar 返回数组：

   ```json
   [
     {"start": 0, "end": 4, "score": 0.91, "entity_type": "PERSON"}
   ]
   ```

网关会把这些外部实体映射成内部 `findings`，再与本地 regex / entropy 结果合并决策。

若要做产品级活体验尸，可直接执行：

```bash
make smoke-presidio
make smoke-presidio-fail
make smoke-attachment-presidio-fail
make smoke-sse-fail
```

它会起本地 Presidio analyzer stub + upstream + gateway，验证：

- request / response 都由 Presidio 驱动命中并脱敏
- 中文前缀场景下的 character offset -> UTF-8 byte offset 转换没有错位
- `/readyz`、`/admin/status`、`/admin/config-summary`、`/metrics` 四面都能看到 Presidio 依赖状态与检测计数
- audit log 不落原始邮箱明文

## 失联与降级语义

若要验证 sidecar 失联时的安全降级语义，可执行：

```bash
make smoke-presidio-fail
make smoke-attachment-presidio-fail
```

它会验证两类失败面：

- **response path fail-safe**：请求本身可通过，但响应侧因 Presidio 不可达而退化为通用 redacted body
- **request path hard-fail**：请求正文需要 Presidio 扫描时，网关会在转发前直接返回 `502 upstream_error`

并同时取证 `/readyz=false`、dependency gauge、`processing_error_fallback` 计数与审计不落明文。

若要专门验证**附件 multipart** 在 sidecar 失联时的真实行为：

```bash
make smoke-attachment-presidio-fail
```

它会证明：

- 文本附件一旦进入 attachment scanning 且需要 Presidio analyze，会直接报 `502 upstream_error`
- 上游不会收到任何 multipart body
- 因 request processing 在 request/response 正常收口前就中断：
  - 不会新增 `attachment_review_fallback`
  - 不会新增 request policy decision 计数
  - 会新增 `gateway_proxy_errors_total{stage="request_pre_upstream",kind="attachment"} == 1`
  - 会落一条 **skeleton audit**：
    - `policy_source=request_pre_upstream_error`
    - `decision=block`
    - `status_code=502`
    - `matched_labels/findings=[]`
    - 不含原始 `admin@example.com`

若要验证 **SSE 响应链** 在 sidecar 失联时的退化语义：

```bash
make smoke-sse-fail
```

它会证明：

- request path 仍可过
- SSE `data:` event 在 Presidio 不可达时会退化成**流式 error sentinel** `data: {"error":"response redacted by gateway"}`，而不是整条连接直接变成 502
- `/readyz=false`、dependency gauge 与 `json_processing_error_fallback` 计数会同步变红
