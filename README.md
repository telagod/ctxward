# Ctxward

> A privacy gateway for LLM traffic. **Detect → redact → tokenize → review → forward.** Lightweight Rust, transparent reverse proxy, no SDK changes on the caller side.

[![ci](https://github.com/OWNER/ctxward/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/ctxward/actions/workflows/ci.yml)
[![security](https://github.com/OWNER/ctxward/actions/workflows/security.yml/badge.svg)](https://github.com/OWNER/ctxward/actions/workflows/security.yml)
[![release](https://github.com/OWNER/ctxward/actions/workflows/release.yml/badge.svg)](https://github.com/OWNER/ctxward/actions/workflows/release.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![image](https://img.shields.io/badge/image-ghcr.io%2Fctxward-informational)](https://github.com/OWNER/ctxward/pkgs/container/ctxward)

> ⚠️ **Status: pre-1.0.** Stable internal mechanics, deliberately small public surface. The crate name `context-gurd`, the `CONTEXT_GURD_*` env vars, the `gateway_*` Prometheus names, and the `x-privacy-gateway-*` headers will keep working for the entire 0.x line; renames go through a deprecation cycle. See [`CHANGELOG.md`](CHANGELOG.md).

---

## Why

Your application talks to OpenAI / Azure OpenAI / a self-hosted LLM. You don't want raw PII, secrets, or internal identifiers to leave your perimeter — but you also don't want to wrap every SDK call.

Ctxward sits **between your app and the upstream** as a transparent reverse proxy and:

1. Identifies the caller (per-tenant Bearer principals, clearance, allowed labels).
2. Recursively scans request and response payloads (`messages`, JSON, SSE events, multipart attachments including `docx/xlsx/pptx/pdf/csv/xml/text`).
3. Decides per finding: `allow` / `redact` / `tokenize` / `review` / `block` — built-in policy first, OPA second, strictest wins.
4. Logs hashes and labels — **never raw values** — to a JSONL audit stream.
5. Exposes Prometheus metrics, a `/readyz` dependency probe, and a `/admin` console.

Compared to in-app SDK wrappers, Ctxward is **language-agnostic** (your apps stay unchanged), **policy-centralized** (one config + OPA, not N codebases), and **observable as infrastructure** (Prometheus, audit, drift reports).

## Three roles, three entry points

| You are…                     | Start here                                                     |
|------------------------------|----------------------------------------------------------------|
| App developer adopting Ctxward | [Quickstart](#5-minute-quickstart) → [`docs/policy/`](docs/policy/) |
| Platform / SRE running it    | [`docs/operations/`](docs/operations/)                         |
| Security / compliance reviewing it | [`SECURITY.md`](SECURITY.md), [`PRIVACY.md`](PRIVACY.md), [`DESIGN.md`](DESIGN.md) |

---

## 5-minute quickstart

```bash
# 1. Bring up Ctxward + OPA locally
docker compose up --build

# 2. Point your app at it (was: api.openai.com → now: localhost:8080)
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: incident-001' \
  -d '{
    "model":"gpt-4.1-mini",
    "messages":[
      {"role":"user","content":"联系我：zhangsan@corp.example，手机号 13812341234"}
    ],
    "stream":false
  }'
```

The upstream sees a redacted body. Your client sees the upstream response, optionally re-filtered. Your audit log contains hashes, labels, and decision sources — no raw email or phone number.

Two demo principals are seeded:

| Principal      | Role     | Clearance  | Allowed labels |
|----------------|----------|------------|----------------|
| `demo-secret`  | employee | `internal` | `email`        |
| `admin-secret` | admin    | `restricted` | full set     |

Replace these for production. The config stores **only the SHA-256** of each secret — compute yours with `printf 'mysecret' | sha256sum`.

If you want reversible `tokenize` masking (so the upstream sees `[EMAIL_TOKEN:CGT1.<...>]` and admins can `POST /admin/detokenize` it back), provide a 32-byte hex key:

```bash
export CONTEXT_GURD_TOKENIZATION_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Want a non-Compose path? See:

- [`docs/operations/docker.md`](docs/operations/docker.md) — the hardened OCI image (read-only rootfs, healthcheck, distroless-friendly)
- [`deploy/systemd/ctxward.service`](deploy/systemd/ctxward.service) — VM / bare-metal unit file
- [`deploy/helm/`](deploy/helm/) — Kubernetes Helm chart (skeleton, full templates land in M2)

---

## What's inside

- **Reverse proxy core**: Axum + Reqwest, rustls-tls, no system CA dependency. Source code: [`src/proxy.rs`](src/proxy.rs), [`src/app.rs`](src/app.rs).
- **Detection pipeline**: linear-time `regex`, high-entropy token detector, optional Presidio analyzer sidecar, JSON pointer-aware scanning. See [`docs/policy/`](docs/policy/).
- **Decision engine**: `label + clearance + allowed_labels` → `allow / redact / review / block`, with OPA strict-merge.
- **Reversible tokenization**: AES-GCM-SIV in-process; key from env, never disk. See [`docs/policy/tokenization.md`](docs/policy/tokenization.md).
- **Session correlation**: `x-session-id` aggregates labels across turns to defeat split-payload exfil.
- **Review queue with replay**: `409 review_required` + ticket id; admin approves; client replays with `x-review-ticket-id`. JSONL persistence survives restart. See [`docs/operations/review.md`](docs/operations/review.md).
- **Attachment scanning**: `text/*`, JSON/XML/CSV, **OOXML node-level rewrite** (`docx/xlsx/pptx`), simple-text PDF rewrite. See [`docs/policy/attachments.md`](docs/policy/attachments.md).
- **Streaming**: SSE event-level redaction with stream-aware fail-safe (sentinel event, never a mid-stream 502).
- **Observability**: `/healthz`, `/readyz` (probes OPA + Presidio), Prometheus metrics with `policy_source` cardinality, JSONL audit (no raw PII), embedded admin console at `/admin`. See [`docs/api/admin.md`](docs/api/admin.md).
- **Benchmark gate**: scenario matrix (`json-redact / json-tokenize / json-review-replay / json-opa / json-presidio / pdf-redact`), regression detector with absolute noise floor and sample-range overlap suppression. See [`docs/operations/benchmarks.md`](docs/operations/benchmarks.md).

Architecture decisions and threat-model considerations: [`DESIGN.md`](DESIGN.md). Roadmap to GA: [`PRODUCTIZATION.md`](PRODUCTIZATION.md).

---

## Verify it works

```bash
make test                    # cargo tests
make clippy                  # -D warnings
make smoke-admin             # smallest live-fire scenario
make smoke-all               # full smoke + bench-matrix (multi-minute)
```

Detailed scenario list: [`docs/operations/smoke.md`](docs/operations/smoke.md).

---

## Releases & supply chain

- **Binaries**: `linux-x86_64`, `linux-aarch64`, `darwin-arm64`, `darwin-x86_64` — published per tag with SHA-256 sums.
- **Container**: `ghcr.io/OWNER/ctxward:<version>` — multi-arch (`amd64`/`arm64`), read-only rootfs, non-root, `tini` PID 1, healthcheck.
- **Provenance**: build-time SLSA provenance attached, **cosign keyless signed**, **CycloneDX SBOM** attested.

Verify before deploying:

```bash
cosign verify ghcr.io/OWNER/ctxward:<version> \
  --certificate-identity-regexp "https://github.com/OWNER/ctxward/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pre-1.0 versioning policy and the M1/M2/M3 GA roadmap: [`PRODUCTIZATION.md`](PRODUCTIZATION.md).

---

## Contributing

PRs welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) — TL;DR: `git commit -s` (DCO), run the relevant `make smoke-*` target, add a `## [Unreleased]` line to [`CHANGELOG.md`](CHANGELOG.md).

Security issues: **do not open a public issue**, see [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
