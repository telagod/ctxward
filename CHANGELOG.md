# Changelog

All notable changes to **Ctxward** are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project rebrand from `context-gurd` to **Ctxward** (product/brand surface only; crate name, env vars, and metric names retained for backwards compatibility through the 0.x line).
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `PRIVACY.md`, `NOTICE`, this CHANGELOG.
- `.github/ISSUE_TEMPLATE/{bug,feature,security}.yml`, `.github/PULL_REQUEST_TEMPLATE.md`.
- `cargo-deny` configuration and a dedicated `security` CI workflow (`cargo-deny`, `cargo-audit`, `gitleaks`).
- Multi-arch release pipeline scaffold (`cargo-dist` + GHCR multi-arch image + `cosign` signing + SBOM).
- Hardened `Dockerfile` (distroless runtime, healthcheck, read-only root, non-root user).
- `PRODUCTIZATION.md` GA-readiness roadmap (M1/M2/M3).

### Changed
- `README.md` reorganized: top-level positioning + 5-minute quickstart; deep operational reference moved under `docs/`.

### Deprecated
- _none_

### Removed
- _none_

### Fixed
- _none_

### Security
- Added supply-chain hygiene gates (`cargo-deny`, `cargo-audit`, `gitleaks`) — no findings carried forward at first release.

---

## [0.1.0] — 2026-05-22

Pre-release engineering snapshot. Captured here for historical reference; this version was never published to crates.io or to a container registry.

### Highlights
- Reverse-proxy core for OpenAI-compatible upstreams (Axum + Reqwest).
- Built-in detection: regex, high-entropy token, optional Presidio analyzer sidecar.
- Decision engine with `allow / redact / review / block`, per-tenant clearance, and OPA external policy backend.
- Reversible tokenization (AES-GCM-SIV), session correlation, review queue with JSONL persistence.
- Multipart attachment scanning with in-place rewrite for `text/*`, OOXML (`docx/xlsx/pptx`), and simple-text PDFs.
- SSE response filtering with event-level redaction and stream-aware fail-safe.
- Embedded admin console (`/admin`), Prometheus metrics, JSONL audit (no raw PII), `/healthz`, `/readyz`, `/admin/reload`, `/admin/detokenize`.
- Benchmark matrix harness + regression gate with noise-floor and sample-range overlap suppression.

[Unreleased]: https://github.com/OWNER/ctxward/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/ctxward/releases/tag/v0.1.0
