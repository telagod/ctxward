# Ctxward Documentation

> Operator-facing reference. Pitch + 5-minute quickstart live in the project [`README.md`](../README.md). Roadmap lives in [`PRODUCTIZATION.md`](../PRODUCTIZATION.md).

## By Role

- **For developers** building against Ctxward → start with [`policy/`](policy/) and [`api/admin.md`](api/admin.md).
- **For operators** running it in production → start with [`operations/`](operations/).
- **For security teams** approving its deployment → start with [`../SECURITY.md`](../SECURITY.md), [`../PRIVACY.md`](../PRIVACY.md), and the upcoming `threat-model.md` (M2).

## Index

### Policy & Detection

- [`policy/opa.md`](policy/opa.md) — OPA external policy backend
- [`policy/presidio.md`](policy/presidio.md) — Presidio analyzer sidecar
- [`policy/tokenization.md`](policy/tokenization.md) — reversible tokenization
- [`policy/attachments.md`](policy/attachments.md) — multipart / OOXML / PDF attachment handling and regex authoring rules

### API

- [`api/admin.md`](api/admin.md) — `/admin/*` control plane, metrics, and admin console
- `api/openapi.yaml` — *planned for M2*

### Operations

- [`operations/docker.md`](operations/docker.md) — Docker / Compose reference
- [`operations/smoke.md`](operations/smoke.md) — `make smoke-*` live-fire matrix
- [`operations/benchmarks.md`](operations/benchmarks.md) — benchmark matrix, gate, baseline drift
- [`operations/review.md`](operations/review.md) — review queue and replay
- [`operations/known-limits.md`](operations/known-limits.md) — current edges and roadmap pointers
- `operations/runbook.md` — *planned for M2* (failure modes, key rotation, upgrade/rollback)
- `operations/capacity.md` — *planned for M2* (sizing curve from bench matrix)

### Architecture

- [`../DESIGN.md`](../DESIGN.md) — design decisions, alternatives, threat considerations
- `architecture/threat-model.md` — *planned for M2* (STRIDE map)

## Versioning

Until **v1.0**, the public surface (HTTP API paths, metric names, YAML keys, audit fields) may change between minor releases — see [`CHANGELOG.md`](../CHANGELOG.md) for the per-release deprecation notices. Post-1.0 we follow strict SemVer; see `versioning.md` (planned for M2).
