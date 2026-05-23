<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# OPA Integration

启用方式：

1. 把 `config/example.yaml` 中的 `policy_backend.opa.enabled` 改成 `true`
2. 启动 OPA，并加载 `opa/privacy.rego`
3. 网关会把以下上下文 POST 给 OPA：
   - `principal`
   - `direction`
   - `path`
   - `session_escalated`
   - `current_decision`
   - `findings`

OPA 返回格式：

```json
{
  "result": {
    "action": "review",
    "reason": "custom policy reason"
  }
}
```

网关会把 OPA 结果与内建策略做"从严合并"，并把来源写进审计日志。
