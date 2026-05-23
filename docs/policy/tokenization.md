<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Reversible Tokenization

当某条规则的 `masking` 设置为 `tokenize` 时，网关会把敏感值替换成类似：

```text
[EMAIL_TOKEN:CGT1.<nonce>,<ciphertext>]
```

特点：

- token 由 Rust 主进程本地生成，不依赖外部 anonymizer sidecar
- 明文不会进入上游，只保留密文占位
- 管理员可通过 `POST /admin/detokenize` 回查
- tokenization key 从环境变量读取，不落配置文件

配置示例：

```yaml
tokenization:
  enabled: true
  key_env: CONTEXT_GURD_TOKENIZATION_KEY
  token_prefix: CGT1

detection:
  rules:
    - name: email
      label: email
      pattern: '(?i)(?:^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})(?:$|[^A-Z0-9._%+-])'
      severity: medium
      authorized_action: allow
      unauthorized_action: redact
      min_clearance: internal
      masking: tokenize
```

注意：只要任一规则/高熵规则/Presidio entity 使用 `masking: tokenize`，启动时就必须同时启用 `tokenization` 并提供有效 32-byte key，否则网关拒绝启动。

> **Key rotation roadmap**: v0.x 仍依赖 env-var 注入；v1.0 计划接 KMS / Vault Transit，详见 [`PRODUCTIZATION.md`](../../PRODUCTIZATION.md) §5 与 §9 M3。
