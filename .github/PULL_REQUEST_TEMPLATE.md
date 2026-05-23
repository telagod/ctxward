## Summary

<!-- One paragraph: what changes and why. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (requires major version bump)
- [ ] Documentation only
- [ ] CI / build / supply-chain only

## Affected surface

<!-- Tick all that apply. -->

- [ ] `/v1/*` data path
- [ ] `/admin/*` control plane
- [ ] Detection / redaction / tokenization
- [ ] Review queue
- [ ] Attachments (multipart / OOXML / PDF)
- [ ] SSE / streaming
- [ ] Metrics names / labels (versioned)
- [ ] YAML config keys (versioned)
- [ ] Audit log schema (versioned)

## Verification

<!-- Required: at least one smoke target name + outcome. -->

- [ ] `make test`
- [ ] `make clippy`
- [ ] `make smoke-<name>` — paste pass/fail
- [ ] Audit log inspected for raw-PII leaks (if redaction-adjacent)

## Backwards compatibility

<!-- If you changed a public surface, document the deprecation path. Otherwise write "n/a". -->

## Checklist

- [ ] All commits signed off (`git commit -s`) per [DCO](../CONTRIBUTING.md#developer-certificate-of-origin-dco)
- [ ] CHANGELOG entry added under `## [Unreleased]`
- [ ] Docs updated (README / `docs/` / config schema)
- [ ] No raw secrets, raw PII, or production audit fragments in this PR

## Linked issues

<!-- Closes #..., Refs #... -->
