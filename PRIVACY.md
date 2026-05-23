# Privacy Policy (Operator-Facing)

This document describes what data **Ctxward**, when deployed by you as an operator, processes and persists. It is not a privacy policy for *your* end users — that remains your responsibility.

## Data Flows

```
Client ──(LLM request)──▶ Ctxward ──(redacted/tokenized)──▶ Upstream (OpenAI / Azure / self-hosted)
                              │
                              ├─▶ JSONL audit log (no raw PII)
                              ├─▶ Prometheus metrics (low-cardinality only)
                              ├─▶ Optional: OPA sidecar (decision context only)
                              └─▶ Optional: Presidio analyzer sidecar (text snippets)
```

## What Ctxward **Stores**

| Surface              | Content                                                                                          | Retention                            |
|----------------------|--------------------------------------------------------------------------------------------------|--------------------------------------|
| Audit log (JSONL)    | `principal`, `tenant_id`, `direction`, `path`, `decision`, `policy_source`, `decision_reason`, matched **labels** and **hashes** of values, `session_id`, `request_id`. **Never raw values.** | Operator-controlled. Default: append-only, no auto-rotate. |
| Review queue (JSONL) | `ticket_id`, `principal`, `path`, `request_body_hash`, decision, approver, TTL                  | Operator-controlled.                 |
| In-memory ring buffer| Same fields as audit log                                                                         | Process lifetime.                    |
| Prometheus metrics   | Counters/gauges/histograms with low-cardinality labels (no PII).                                | Scrape-driven; not persisted by Ctxward. |
| Tokenization vault   | Reversible AES-GCM-SIV ciphertext. Plaintext never persisted to disk.                            | Plaintext kept in-process only as long as needed for response rewrite. |

## What Ctxward **Forwards**

To the configured upstream:
- The request body **after** detection / redaction / tokenization
- Whitelisted headers (`forward_headers` in config)
- Auth header rewritten with the operator-supplied upstream credential

To OPA (if enabled):
- `principal`, `direction`, `path`, `session_escalated`, `current_decision`, `findings` (labels + hashes — no raw values)

To Presidio analyzer (if enabled):
- The text snippet under analysis (this **does** contain raw text by necessity — operators should run Presidio on trusted infrastructure)

## What Ctxward **Never Does**

- Never writes raw PII to the audit log.
- Never writes the tokenization key to disk; key comes from `CONTEXT_GURD_TOKENIZATION_KEY` env.
- Never logs upstream credentials.
- Never makes outbound calls beyond the configured upstream and the optional OPA / Presidio sidecars.

## Operator Obligations

- Provision tokenization key and rotate it per your compliance requirements.
- Restrict access to the audit log file and `/admin/*` routes.
- If running Presidio, treat the analyzer's logs as PII-bearing.
- Comply with applicable data protection laws (GDPR, CCPA, PIPL, HIPAA, etc.) — Ctxward provides controls, not exemptions.

## Data Subject Requests

Because Ctxward audits store only hashes and labels, it cannot fulfill subject access / erasure requests on its own. You must correlate via your application-layer identifiers (`principal`, `tenant_id`, `session_id`, `request_id`).

## Changes

Material changes to this policy will appear in [`CHANGELOG.md`](CHANGELOG.md) under a `Privacy` heading and be called out in the release notes.
