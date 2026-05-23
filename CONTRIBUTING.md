# Contributing to Ctxward

Thanks for considering a contribution. Ctxward sits on the privacy boundary of LLM traffic — small bugs can have outsized consequences, so we keep the bar high. The flip side: every accepted patch ships with real safety value.

## Ground Rules

1. **No untested change touches the proxy / detection / redaction / OOXML / SSE paths.** All five have smoke targets. Run them before opening a PR (see below).
2. **Audit log must never leak raw PII.** If your change touches the request/response audit path, prove it with a fixture.
3. **Public surface is a contract.** `/v1/*`, `/admin/*`, the Prometheus metric names, and the YAML config keys are versioned per SemVer. Breaking changes need a major bump and a deprecation note in the previous minor.
4. **Default-deny posture.** When in doubt, prefer `block` over `allow` and document the rationale.

## Quick Start

```bash
# Fork & clone, then:
make test          # cargo test -q
make clippy        # -D warnings, no exceptions
make smoke-admin   # smallest live-fire target
```

Heavier verification before a non-trivial PR:

```bash
make smoke-all     # all smoke + bench fixtures (~ several minutes)
```

## Pull Request Checklist

- [ ] `make test` passes
- [ ] `make clippy` clean
- [ ] Relevant smoke target passes (link it in the PR body)
- [ ] If you touched audit/redact paths: `audit.log` confirmed not to contain raw secrets in the smoke output
- [ ] CHANGELOG entry under `## [Unreleased]`
- [ ] Docs updated if behavior, metric names, or YAML keys changed
- [ ] All commits are signed-off (`git commit -s`) — see DCO below

## Developer Certificate of Origin (DCO)

We use the [DCO 1.1](https://developercertificate.org/). Every commit must include:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add it automatically via `git commit -s`. PRs without DCO sign-off will be blocked by CI.

We do **not** require a CLA.

## Coding Standards

- Rust: stable toolchain. `cargo fmt` + `cargo clippy --all-targets --all-features -- -D warnings`.
- Public items in the `ctxward` crate need at least a one-line doc comment.
- Avoid `unsafe`. If unavoidable, justify in a comment and isolate.
- Avoid panics in request/response paths. Return typed errors.

## Test Conventions

- Unit tests live next to code (`#[cfg(test)] mod tests`).
- Integration scenarios live under `scripts/smoke-*.sh`. Add a new smoke target for any new policy decision branch.
- Bench scenarios live under `scripts/bench_harness.py`. Adding a new scenario? Also add it to `bench-matrix` and re-baseline.

## Reporting Bugs / Asking Questions

- **Security issues**: see [`SECURITY.md`](SECURITY.md). Do not open a public issue.
- **Bugs / feature requests**: GitHub Issues with the relevant template.
- **Design discussions**: GitHub Discussions (or a draft PR with a `[design]` prefix).

## License

By contributing, you agree your contributions are licensed under the MIT License (see [`LICENSE`](LICENSE)).
