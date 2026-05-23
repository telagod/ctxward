<!-- Extracted from the original README.md to keep the project README pitch-sized. -->

# Attachment Extraction

请求若使用 `multipart/form-data` 上传文件，可启用附件抽取：

```yaml
attachments:
  enabled: true
  max_bytes: 5242880
  max_text_chars: 32768
  allowed_media_types:
    - text/*
    - application/json
    - application/xml
    - text/xml
    - text/csv
    - application/pdf
    - application/vnd.openxmlformats-officedocument.wordprocessingml.document
    - application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
    - application/vnd.openxmlformats-officedocument.presentationml.presentation
```

行为说明：

- `text/*` / `json/xml/csv`：命中 `redact` 时直接改写附件正文后转发上游
- `docx/xlsx/pptx`：会展开 ZIP 内 `word/`、`xl/`、`ppt/` 下 XML text nodes，按节点级 pointer 检测并在命中 `redact` 时重写 XML 后重新封包转发
- `pdf`：当前优先尝试对**简单文本型 PDF content stream** 做结构级回写；若 PDF 文本可被 `lopdf` 定位并替换，则命中 `redact` 后会重写 PDF 再转发。若遇到复杂编码、不可逆 glyph 映射、扫描版/图片型 PDF 等无法安全改写的情况，仍会回退为 `review`
- 若上传客户端把附件 MIME 统统打成 `application/octet-stream`，网关会按文件扩展名回退识别 `pdf/docx/xlsx/pptx`，避免真实办公客户端绕过附件扫描
- 超过 `attachments.max_bytes` 的单个附件会被阻断当前请求
- `make smoke-ooxml` 可对 `docx/xlsx/pptx` 做 live rewrite 取证，并验证 audit log 的节点级 pointer

## Regex 规则边界

若规则需要兼容中文等 CJK 文本紧邻敏感值的场景，不要依赖 Unicode `\b`。`context-gurd` 会把**第一个 capture group** 视为真实敏感片段，因此可以把外围边界写进非捕获组，只对捕获组做审计与脱敏：

```yaml
pattern: '(?:^|[^0-9])(1[3-9]\d{9})(?:$|[^0-9])'
```

这样 `我的手机号是13800138000` 也会命中，而不会把前后文本一起写入匹配结果。
