# Licensing & open-core model

## TL;DR

Ctxward uses an **open-core** model:

- **Core** (this repository) — Apache-2.0. Use it, modify it, embed it, sell
  products around it. Keep the notice, don't claim our trademarks.
- **Enterprise add-ons** (separate, not in this repo) — commercial license.
  Multi-instance control plane, KMS-managed keys, SSO, centralized policy push,
  compliance reporting. These are operationally distinct from the core and will
  never gate features that belong in the open engine.

## Why Apache-2.0

| Need | How Apache-2.0 serves it |
|------|--------------------------|
| **Auditability** | A privacy tool you can't inspect is just a backdoor. Source is open, forkable, and inspectable — including the MITM trust model and the CA lifecycle. |
| **Patent grant** | Explicit patent license (Section 3) protects users and contributors from patent ambush — MIT has none. |
| **Trademark clarity** | Section 6 reserves the "Ctxward" name without a separate trademark policy file. |
| **Adoption** | OSI-approved, enterprise-legal-friendly, no copyleft — the lowest friction for corporate adopters. |
| **Ecosystem fit** | Our dependency graph (Tokio, Axum, rustls, hudsucker) is Apache-2.0 / MIT. No license incompatibility. |

## What this means in practice

| You want to… | Answer |
|--------------|--------|
| Use Ctxward internally | Yes, free, forever. |
| Fork and modify for your own infra | Yes. Keep the NOTICE file. |
| Embed the engine in a product you sell | Yes. Credit Ctxward in your notices. |
| Offer a managed Ctxward service | Yes — but you may not use the "Ctxward" trademark to brand it (Section 6). |
| Contribute back | Welcome. DCO sign-off, Apache-2.0. No CLA required. |

## Core competitive advantages (what makes Ctxward hard to replicate)

These are the load-bearing differentiators the open-core model is designed to
protect through execution speed, not license restriction:

1. **Multi-format detection depth** — recursive scan across JSON, SSE events,
   OOXML node-level rewrite (docx/xlsx/pptx), PDF content-stream rewrite,
   multipart attachments, with pluggable Presidio / OPA / regex / entropy
   detection. Reproducing this breadth at production quality is months of work.

2. **Transparent take-over trust model** — Clash-style system-proxy + local
   root CA that (a) only decrypts whitelisted LLM-provider SNIs, (b) keeps the
   private key local and never exports it, (c) is fully open to audit. Security
   tools earn trust through transparency, not secrecy — and trust compounds.

3. **Reversible tokenization** — AES-GCM-SIV in-process tokenization lets
   admins recover original values without ever exposing them to the model.
   Combined with session correlation (cross-turn label aggregation to defeat
   split-payload exfil), this is a unique combination in the LLM privacy space.

4. **One-core-two-shells coverage** — the same Rust engine powers a desktop
   transparent client (developer/personal growth) AND a headless reverse-proxy
   gateway (enterprise). One policy language, one label set, one audit format.

5. **Enterprise control plane** (commercial, separate repo) — centralized
   policy push across an org's desktop clients, multi-instance review backend,
   KMS key management, SSO, compliance reporting. This is where the business
   model lives — operational complexity that individual users don't need and
   that makes the open core more valuable, not less.

## Prior license

Commits before the Apache-2.0 migration were under the MIT License. The
relicense was performed by the sole copyright holder (all commits by the same
author). The Apache-2.0 license is strictly more protective for users (adds
patent grant, trademark clarity) and is compatible with MIT-licensed downstream
consumers.

## Questions

Open a GitHub Discussion or reach out per [SECURITY.md](SECURITY.md) for
private licensing inquiries.
