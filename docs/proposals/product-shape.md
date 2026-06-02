# 产品形态定义 · Ctxward

> 状态：提案 (proposal) · 2026-06-02
>
> 目的：把 Ctxward 从「单一显式反代库」重定义为「一个 LLM 隐私数据平面 + 两副交付人格」，并锁定第一阶段范围。本文是该转向的**单一事实源**；与 `PRODUCTIZATION.md`（只覆盖反代库产品化）互补，不冲突。

---

## 0. 决策快照（已拍板）

| 决策 | 取值 | 含义 |
|------|------|------|
| **主线人格** | **Desktop 透明接管端** | Clash 式桌面 client 是增长引擎与资源主投向；Gateway 反代退为次要/兼容形态 |
| **首阶段端** | **桌面三端 + 浏览器扩展** | Win/Mac/Linux 为主力；浏览器扩展为最低摩擦快赢；移动端后期 |

---

## 1. 一句话定位

> **Ctxward 是你机器上的 LLM 流量隐私防火墙——出门前的每一个 prompt，先检测、脱敏、再放行。**

对标心智：**Clash for LLM privacy**（借架构，不蹭品牌；对外措辞用 "data-plane firewall for LLM traffic"）。

Clash 的本质是三件事，Ctxward 逐一映射：

| Clash | Ctxward Desktop |
|-------|-----------------|
| 透明接管（不改 app） | 系统代理 / TUN 接管，应用无需改 base_url |
| 规则分流（按域名/进程） | 按 LLM provider SNI 白名单分流，命中才脱敏 |
| 可视化控制台（看每条连接） | 看每条 LLM 请求的 PII 命中与脱敏决策 |

---

## 2. 真命人群

| 人群 | 痛点 | Clash 式价值 |
|------|------|------|
| **开发者本地** | Cursor / Copilot / Cline / Claude Code / SDK 脚本 / Raycast 多客户端，闭源 app 硬编码 endpoint 改不动 | **极高** |
| **隐私意识个人** | 网页版 ChatGPT/Claude/Gemini、桌面 AI app、各种插件，PII 随手就发出去 | **极高** |
| 企业平台方 | 自家 app 流量合规 | 低——反代已足够（走 Gateway 人格） |

**结论**：Clash 式接管的真命人群是「开发者本地 + 个人桌面」，这正是新主线。

---

## 3. 架构：一核两壳

内核（已成熟的 Rust 检测/脱敏/tokenize/review/audit/policy 引擎，现 `src/proxy.rs` 等）是唯一事实源，上面长两副壳——对标 Clash `core` → `Clash Verge`/`ClashX` 的一核多壳演化。

```text
                 ┌─────────────────────────────────┐
                 │   Ctxward Core (Rust, 现状内核)   │
                 │  detect · redact · tokenize ·     │
                 │  review · policy · audit · OPA    │
                 └───────────────┬─────────────────┘
                                 │ 同一份 policy 语义 / 同一套 label
              ┌──────────────────┴──────────────────┐
              ▼                                       ▼
   ┌──────────────────────┐            ┌──────────────────────────┐
   │  Ctxward Gateway      │            │  Ctxward Desktop (主线)    │
   │  显式反代 · headless   │            │  透明接管 · Tauri 壳       │
   │  k8s/server · 多租户   │            │  本地 MITM · 单用户/单机   │
   │  → 企业变现线          │            │  → 开源增长引擎            │
   └──────────────────────┘            └──────────────────────────┘
```

### 身份模型在两壳上故意不同

- **Gateway**：per-Bearer multi-tenant（现状）。
- **Desktop**：退化为单用户单机，principal 改为「**哪个本机进程/app 发的**」。不硬套租户模型——这是根本简化。

### 内核抽离

`Cargo.toml` 现为单 crate。转向后建议演进为 workspace：

- `ctxward-core` —— 引擎（detect / redact / tokenize / review / policy / audit），无 IO 入口假设。
- `ctxward-gateway` —— 反代入口（现 `app.rs` + `proxy.rs` 的 server 部分）。
- `ctxward-desktop` —— Tauri 壳 + 接管层（system proxy / TUN / CA）。

抽离可渐进，不阻塞首版 Desktop（首版可先在现 crate 内加 `mode` 分支）。

---

## 4. Desktop 接管模型（三档渐进）

| 档 | 机制 | 覆盖 | MITM | 对标 Clash | 排期 |
|----|------|------|------|-----------|------|
| **L1 Endpoint** | app 自动写 `OPENAI_BASE_URL`/env 指向本地 | 认 env 的 CLI/SDK | 否 | — | 复用现状 |
| **L2 System Proxy** | 设系统 HTTP(S) proxy + 装本地根 CA，**仅白名单 SNI 解密** | 多数桌面 app | 是（限白名单） | system proxy 模式 | **v1 主力** |
| **L3 TUN** | 虚拟网卡全量接管 | 硬编码 endpoint 的 app | 是 | TUN 模式 | v2 |

### 规则分流（对标 Clash rule-set 订阅）

- 内置 **LLM provider 域名库**：OpenAI / Anthropic / Azure OpenAI / Gemini / Bedrock / DeepSeek / Moonshot / Groq / Ollama 本地口……
- **可热更新订阅**——域名库随新 provider 上线远程更新，不发版。
- 命中 → MITM + 脱敏管线；**未命中 → direct passthrough，绝不触碰**。这就是「自动探测 LLM 请求」的真身：规则匹配，非魔法嗅探。
- 规则可编辑：per-domain / **per-app** / per-model（例：「Cursor 走脱敏，本地 Ollama 直放」）。

### 控制台（杀手级差异化）

Clash dashboard 给你看「连接」；Ctxward Desktop 给你看别人看不到的：

> 「你刚才发给 GPT-4 的那句话里，`13812341234` 被换成了 `[PHONE_TOKEN:CGT1.xxx]`，模型那头看不到原文。」

实时面板每条 LLM 请求展示：**provider · model · token 数 · 命中的 PII label · 决策(allow/redact/tokenize/review/block) · 哪个 app 发的**。融合 Clash 连接视图 + Ctxward 决策审计。review 队列做成**本地系统弹窗审批**，替代现状的 HTTP ticket。

留存钩子（用户没要但会上瘾）：**全机 LLM token 消耗统计 / 成本看板 / prompt 历史**。

---

## 5. 全端分期（第一阶段范围已锁定）

| 端 | 机制 | 接管「所有 app」 | 成本 | 阶段 |
|----|------|------|------|------|
| **桌面 Win/Mac/Linux** | Tauri + 内核直编 + L2 proxy + CA 助手 | 能 | 中（内核现成） | **v1 主力 ✅** |
| **浏览器扩展** | 页面层 hook `fetch`/XHR 做脱敏，**无需装 CA** | 仅浏览器内（claude.ai/gemini 网页） | 低 | **v1 快赢 ✅** |
| Android | `VpnService` + 内核编进去 | 受限 | 高 | v2 |
| iOS | Network Extension + 描述文件装 CA | 基本不能（系统级 + 审核限制） | 极高 | v2+ / 可放弃 |

**第一阶段 = 桌面三端 + 浏览器扩展。** 移动端不进首阶段。

---

## 6. 致命风险（必须前置缓解）

1. **MITM 信任灾难**：装根 CA = 给一个 app 解密全机 TLS 的权力。缓解唯一活路——只对白名单 SNI 解密 / CA 私钥本地生成永不出机 / 全开源可审计 / 一键彻底卸载。做不到，产品即后门。
2. **cert pinning 撞墙**：ChatGPT desktop、部分 app pin 证书，MITM 直接断连。必须优雅 fallback（passthrough + 提示），不能让用户「装了你之后 app 全废了」。
3. **定位分裂**：infra 与 C 端是两套 GTM / 两套后端（多租户 vs 单机）/ 两套运维假设。已钦定 Desktop 为主，Gateway 为次，资源不摊薄。
4. **Clash 品牌阴影**：Clash 本体因「翻墙」被删库/下架。借架构，不蹭名字。

---

## 7. 商业形态（OSS infra 打法，参照 Tailscale / ngrok）

- **免费开源**：Desktop client、本地脱敏、本地审计、单机。
- **企业版变现**：多实例审批后端（Postgres/Redis，解 `DESIGN.md:337` 单点）、KMS 托管 key、SSO、合规报告生成、**集中策略下发**（一个控制面管全公司的 Desktop client——Clash 没有而企业需要）。

---

## 8. 收口里程碑（Desktop 主线）

### D1 · 透明接管 PoC（解锁一切）

- [ ] 现 crate 加 `mode: reverse | proxy` 配置
- [ ] HTTP CONNECT + 动态 SNI 路由的 forward proxy 入口
- [ ] LLM provider SNI 白名单：命中走脱敏管线，未命中透传
- [ ] 自签根 CA 生成（私钥本地，永不出机）+ 安装/卸载文档

### D2 · Tauri 桌面壳

- [ ] 系统托盘 + 开关 + 系统代理一键设置/还原
- [ ] CA 安装助手（三端各自的信任库操作）
- [ ] 实时流量控制台（provider/model/token/label/决策/来源 app）
- [ ] 本地弹窗审批替代 HTTP ticket
- [ ] cert pinning fallback + 提示

### D3 · 浏览器扩展（并行快赢）

- [ ] content script hook `fetch`/XHR，覆盖 claude.ai / chat.openai.com / gemini
- [ ] 页面层脱敏，复用内核 label 集（经 WASM 或本地 native messaging 调内核）
- [ ] 与桌面端共享策略/审计

### D4 · 域名库订阅 + 留存钩子

- [ ] provider 域名库远程订阅热更新
- [ ] token 消耗 / 成本看板 / prompt 历史
