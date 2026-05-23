# Productization Readiness · context-gurd

> 状态快照：2026-05-23 · 评估对象 v0.1.0
>
> 目的：把"能跑、能压、能验"的工程库，收口为可被业务方信任、可被运维稳定接入、可被合规答辩的产品。

---

## 0. TL;DR

工程内核已成熟（10.8k 行 Rust，覆盖反向代理 / 检测 / 脱敏 / 可逆 tokenize / 审批队列 / OOXML 重写 / SSE 流式 / OPA / Presidio / benchmark gate / 内嵌 admin console），CI 含 verify+bench 两段，smoke 矩阵齐全。

**距离"产品"还差三件事**：

1. **治理面真空**：无 `LICENSE` / `CHANGELOG` / `CONTRIBUTING` / `SECURITY` / `CODE_OF_CONDUCT` / 无 git 历史。开源/商业都过不了第一关。
2. **交付面只有 `cargo build`**：无 release 通道、无多架构镜像、无签名/SBOM、无 Helm / systemd unit。
3. **定位面没收**：README 是手册不是 pitch，没有"为谁解决什么"的一段话；没有 SLO、容量基线、运维手册、威胁模型。

下面按 8 维拆开，每维给：**现状 → 缺口 → 闭口动作 → 验收**。

---

## 1. 品牌与定位 (Positioning)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| 产品名 | `context-gurd`（疑似 typo: guard/gurd） | 商标可注册性、SEO、口碑形象未评估 | 二选一：(a) 保留 `context-gurd` 作为 OSS 代号 + 商业名另起；(b) 改名 `context-guard` 或 `Pravāha` / `Pravacy` 等 | 名字落到 README header / Cargo metadata / docker image / domain |
| 一句话定位 | "轻量 Rust LLM 会话清洗网关" | 缺"为谁、解决什么、对比谁" | 写一句 ≤ 25 字的 elevator pitch + 一段 ≤ 80 字的 problem statement | 任意工程师 30 秒内能复述 |
| 受众分层 | 没分 | OSS 用户 / 商业用户 / 合规审计 / SRE 不同入口 | README 顶部加 "For Developers / For Security / For Ops" 三段引导 | 三种角色都能在 60s 内找到下一步 |
| 竞品对位 | 没列 | 与 Cloudflare AI Gateway / Portkey / LiteLLM proxy / Lakera Guard / Protect AI Layer / Robust Intelligence 的差异点 | 一张对比表 + 三条非对称优势 | 销售/PR 可直接引用 |

---

## 2. 法务与治理 (Legal & Governance)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| LICENSE 文件 | **缺** | `Cargo.toml` 写 MIT 但仓库无 LICENSE | 加 `LICENSE`（MIT 全文）；若想保留商业空间，考虑 Apache-2.0 + Commons Clause / BSL-1.1 双轨 | `licensee` / GitHub 自动识别为 MIT |
| 第三方依赖合规 | 未审计 | `aes-gcm-siv / lopdf / quick-xml / pdf-extract / zip` 协议未盘 | `cargo deny check licenses bans advisories sources` 入 CI | CI 红线，发布前清零 |
| SBOM | 无 | 无产物 SBOM | `cargo cyclonedx` 或 `syft` 在 release job 产出 `sbom.cdx.json` 与 `sbom.spdx.json` | 每次 GitHub Release 附 SBOM |
| 漏洞披露 | 无 | 无 `SECURITY.md`、无 PSIRT 通道 | 写 `SECURITY.md`：报告邮箱（PGP key 可选）、SLA、CVE 流程 | GitHub `Security` 标签亮起 |
| 贡献指南 | 无 | 无 `CONTRIBUTING.md` / DCO / CLA | `CONTRIBUTING.md` + DCO `Signed-off-by` 校验 + PR/Issue 模板 | 外部贡献可顺畅提 PR |
| 行为准则 | 无 | 无 `CODE_OF_CONDUCT.md` | 复用 Contributor Covenant v2.1 | 文件就位 |
| 隐私声明 | 无 | 默认 audit log 不落明文，但没文档承诺 | `PRIVACY.md` 明确：哪些字段被记录、哪些被 hash、保留期、删除流程 | 客户问"你存我什么"时一句话答得出 |

---

## 3. 版本与发布通道 (Release)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| 版本号 | `0.1.0` 锁住没动 | 无 SemVer 承诺、无 deprecation 策略 | 文档化 SemVer：`MAJOR=不兼容 / MINOR=新功能 / PATCH=修复`；明确 `/admin/*` 与 `/v1/*` 双面的兼容承诺 | `docs/versioning.md` 上线 |
| CHANGELOG | 无 | 无 | Keep-a-Changelog 格式 + `git-cliff` 自动化 | 每 release tag 必带 CHANGELOG diff |
| Git 历史 | **空** | 项目目录非 git 仓库 | `git init` + 首提交 + 推到 GitHub/GitLab | 远端仓库可见 |
| 发布产物 | 仅本地 cargo build | 无 binary release | `cargo-dist` 产出 linux-x86_64 / linux-aarch64 / darwin-arm64 三平台二进制 + 校验和 + 安装脚本 | `curl install.sh` 一行可装 |
| 容器镜像 | `docker-compose` 用 local build | 无注册表镜像、无多架构、无签名 | GHCR + `docker buildx --platform linux/amd64,linux/arm64` + `cosign sign` + provenance attestation | `docker pull ghcr.io/<org>/context-gurd:0.2.0` 可用 |
| Helm / K8s | 无 | 客户拿到镜像也不会装 | 写 `deploy/helm/context-gurd/` chart：configmap、secret（OPENAI_API_KEY / TOKENIZATION_KEY）、HPA、PDB、ServiceMonitor、ingress | `helm install` 一行起服务 |
| systemd / nomad | 无 | 非 K8s 客户没入口 | `deploy/systemd/context-gurd.service` 范例 | 单机 VM 一份 unit 文件起服务 |

---

## 4. 文档与入门 (Docs & DX)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| README | 32k，混合 pitch/操作/验证/参考 | 一篇文撑不住产品 | 拆三层：(1) README ≤ 200 行专做 pitch+quickstart；(2) `docs/` 目录拆 architecture/operations/policy/api；(3) `examples/` 放真实场景片段 | 新手 5 分钟跑起来 |
| 站点 | 无 | 无 docs site | `mdBook` 或 `Docusaurus` + GitHub Pages，CI 自动发布 | `https://<org>.github.io/context-gurd` 上线 |
| API 参考 | 散在 README | 无 OpenAPI | 给 `/v1/*` 与 `/admin/*` 出 `openapi.yaml`；admin 部分用 `utoipa` 自动生成 | swagger UI 可点 |
| 配置参考 | `config/example.yaml` | 字段无逐项说明 | 为 `Config` struct 补 `#[doc]`，用 `schemars` 出 JSON Schema，IDE 即可补全 | VSCode YAML 插件能 hover 出说明 |
| 运行手册 | 无 | 故障/重启/扩容/降级流程没写 | `docs/runbook.md`：Presidio 失联 / OPA 失联 / review 队列堆积 / tokenization key 轮换 / 升级回滚 | SRE 拿到无歧义 |
| 威胁模型 | DESIGN.md 有"安全考量" | 不是 STRIDE 形式 | `docs/threat-model.md`：STRIDE × 数据流 × 边界，列已缓解/未缓解 | 安全审计可直接引用 |

---

## 5. 容器与部署 (Deploy)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| Dockerfile | 单阶段 builder + bookworm-slim | 镜像偏大、无 healthcheck、无 NOFILE 调优 | 改 `distroless` 或 `chainguard/static`；加 `HEALTHCHECK CMD curl -f localhost:8080/healthz`；非 root；只读 rootfs；明确 ENTRYPOINT/CMD | `docker scout`/Trivy 高危为零 |
| 镜像签名 | 无 | 供应链空白 | `cosign sign --keyless` + `cosign attest --predicate sbom.cdx.json` | 客户能 `cosign verify` |
| Helm chart | 无 | 见 §3 | 同 §3 | 同 §3 |
| 配置注入 | volume mount yaml | 缺 env 覆盖、缺 secret/CSI 集成 | 支持 `CONTEXT_GURD_<KEY>=value` 覆盖 yaml；docs 给 ESO / Vault Agent 范例 | 客户可纯 env 部署 |
| Tokenization key 管理 | env 注入裸 hex | 无轮换、无 KMS | v0.x：文档化轮换流程；v1.x：接 KMS / Vault Transit / GCP KMS | 客户可零停机轮换 |
| 高可用 | 单实例 + 本地 JSONL | review 队列单点 | 文档化"单实例边车 vs 多实例共享 backend" 决策树；Roadmap 明确 v1.1 上 Postgres/Redis backend | 客户能选定形态 |

---

## 6. 可观测与 SRE (Observability & SRE)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| 指标 | Prometheus 一手齐 | 无 Grafana dashboard JSON | `deploy/grafana/context-gurd.json`：QPS / 决策分布 / 拒绝率 / fallback / 依赖就绪 / latency p50/p95/p99 | 一键导入即可看 |
| 告警规则 | 无 | 无 PrometheusRule | `deploy/prometheus/rules.yaml`：`gateway_dependency_ready==0` / `processing_fallback` 高于阈值 / `proxy_errors_total` 突增 / review queue near capacity | PR review 可见 |
| 追踪 | 无 OpenTelemetry | 黑盒难定位 | 接 `tracing-opentelemetry`，导出 OTLP；request_id 贯通 audit / metrics / trace | Jaeger 上看得到一条完整链路 |
| 日志 | tracing JSON | 无字段 schema 文档 | `docs/logging.md` 列出每条字段含义、PII 承诺；日志等级建议 | 客户接 ELK 不踩坑 |
| SLO | 无 | 无承诺 | 文档化候选 SLO：可用性 99.9% / 决策延迟 p95 < 5ms（json-redact 链路）/ false-block 率 < 0.1% | 内部 SRE 有靶子 |
| 容量基线 | bench-matrix 已有 | 没翻成"X 核 Y 内存能扛 Z RPS" | `docs/capacity.md`：单实例容量曲线 + 横向扩展拐点 | 售前/SE 报方案有依据 |

---

## 7. 安全门禁 (Security Gates)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| 静态分析 | clippy `-D warnings` | 无 `cargo audit` / `cargo deny` | 入 CI 第三 job：advisories / licenses / yanked | CI 红线 |
| Fuzz | 无 | 检测/重写路径未 fuzz | `cargo-fuzz` targets：JSON pointer 重写、OOXML XML 改写、PDF content stream rewrite、SSE event parser | 至少 4 个 fuzz target 跑过 1h |
| 单测覆盖率 | 未公开 | 无 codecov | `cargo llvm-cov --workspace --lcov` + Codecov；阈值先设 60% | PR 可见覆盖率 delta |
| Secret 扫描 | 无 | 仓库可能漏 token | `gitleaks` / `trufflehog` 入 pre-commit + CI | clean 状态 |
| 容器扫描 | 无 | 镜像漏洞不知 | `trivy image` 入 release job，高危阻断 | 报告附 Release |
| 数据/密钥 | env + sha256 | 无密钥管理章节 | `docs/secrets.md`：`secret_sha256` 算法、`tokenization_key` 长度/熵/轮换、`OPENAI_API_KEY` 注入路径 | 安全审计无问号 |
| 渗透测试 | 无 | 无外部红队报告 | 安排一次第三方 pentest，先盯 admin 鉴权 / detokenize / multipart 解析 / SSE 边界 | 报告归档 + 修复 closeout |
| 合规框架对位 | 无 | 客户问 SOC2 / ISO27001 / GDPR / 中国 PIPL 怎么对 | `docs/compliance.md` 给一张控件 ↔ 实现的映射表 | 销售/合规可填问卷 |

---

## 8. 商业化与上线节奏 (Commercial)

| 项 | 现状 | 缺口 | 闭口动作 | 验收 |
|----|------|------|----------|------|
| 形态决策 | 未定 | OSS / OSS+商业 / 内部产品 | 三选一（见对话） | 一句话写在 README 顶部 |
| 客户旅程 | 无 | 试用 → POC → 上线 → 续费 没设计 | 写 4 篇 docs：5 分钟试用 / 1 周 POC / 上生产 checklist / 升级回滚 | 销售可端出 |
| 价格/分级 | 无 | 若走商业 | OSS 免费 / 商业差异化点：多实例审批后端、KMS 托管、SSO、SLA、合规报告生成 | landing page 落 |
| 演示环境 | 无 | 无 hosted demo | 部署一份只读 demo（admin token 只读）+ 内嵌 admin console 访问 | demo URL 可点 |

---

## 9. 收口里程碑 (Milestones)

按"先治理 → 再发布 → 再扩商业"的顺序，建议三段：

### M1 · v0.2.0 治理与首发（1~2 周可收）

必做（无歧义、低成本、解锁所有后续）：

- [ ] `git init` + 首提交 + 推到远端
- [ ] `LICENSE`（MIT）/ `SECURITY.md` / `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` / `CHANGELOG.md`
- [ ] PR / Issue 模板 + DCO
- [ ] `cargo deny` + `cargo audit` 入 CI（独立 security job）
- [ ] `gitleaks` 入 CI
- [ ] README 顶部三段：positioning / quickstart / docs index；其余下沉到 `docs/`
- [ ] 首个 GitHub Release：`cargo-dist` 三平台二进制 + 校验和 + SBOM
- [ ] 多架构 GHCR 镜像 + `cosign` 签名 + provenance
- [ ] Dockerfile 收紧（distroless / healthcheck / 只读根）

### M2 · v0.3.0 部署与运维（2~3 周）

让客户能装、能看、能扩：

- [ ] Helm chart（含 ServiceMonitor / PrometheusRule / HPA / PDB）
- [ ] systemd unit 范例
- [ ] Grafana dashboard JSON + 告警规则
- [ ] OpenTelemetry 追踪接入
- [ ] `docs/runbook.md` / `docs/capacity.md` / `docs/threat-model.md` / `docs/secrets.md`
- [ ] OpenAPI 自动生成（utoipa）+ JSON Schema for config

### M3 · v1.0.0 GA（4~6 周）

锁定兼容承诺、做到合规答辩：

- [ ] SemVer + deprecation policy 文档化并锁定
- [ ] review backend 抽象层 + Postgres/Redis 实现（解决多实例单点）
- [ ] tokenization key 接 KMS / Vault Transit
- [ ] 第三方 pentest 报告 closeout
- [ ] `docs/compliance.md` SOC2 / ISO27001 / GDPR / PIPL 映射
- [ ] hosted demo + 一份生产参考架构
- [ ] v1.0 兼容承诺：`/v1/*` 与 `/admin/*` 进入 stable，破坏性改动只在 v2.x

---

## 10. 现成可立即收的"低垂之果"

不需要决策、不破坏现状、立刻能写：

1. `LICENSE` MIT
2. `SECURITY.md` + 报告邮箱占位
3. `CHANGELOG.md` 起头
4. `CONTRIBUTING.md` + DCO 行
5. `CODE_OF_CONDUCT.md`（Contributor Covenant v2.1）
6. `.github/ISSUE_TEMPLATE/` + `PULL_REQUEST_TEMPLATE.md`
7. `cargo-deny.toml` + CI security job
8. README 顶部加 positioning + badges 占位

吾建议这八条等魔尊点头里程碑后，一气写完作为 M1 起手。
