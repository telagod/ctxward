<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Known Limits

- 图片 OCR、扫描版 PDF、加密文档尚未接入。
- 当前 NER 为规则/高熵优先，外部分析器（如 Presidio）仍是下一阶段。
- 当前 Presidio 只接了 analyzer sidecar，尚未接外部 anonymizer；可逆 tokenization 已由 Rust 主进程内建。
- 当前可逆 tokenization 为 Rust 内建实现，尚未接 KMS / Vault 托管密钥与轮换（v1.0 路标）。
- SSE 响应过滤为**事件粒度**处理，不跨事件拼接超长上下文。SSE 当前按**事件粒度即时执行**内建策略与 OPA 升级；若单个 event 被升级为非 `allow`，会直接替换为 redacted sentinel，但仍不跨 event 拼接长上下文。
- review replay 当前按 **principal + path + raw request body hash** 严格匹配，不做 JSON canonicalization。
- OOXML 当前仅覆盖 `word/`、`xl/`、`ppt/` 下 XML text / CDATA 节点回写；PDF 仅对**简单文本型 content stream** 支持结构级回写，复杂字体编码/扫描件/图片型 PDF 仍会回退为 `review`。
- 当前外部策略后端只接了 OPA，尚未接审批工作流与策略版本管理 UI。
- review 队列单实例（JSONL backend）；多实例共享要等 v1.x 切到 Redis/Postgres backend。

完整路线图与缓解计划见 [`PRODUCTIZATION.md`](../../PRODUCTIZATION.md)。
