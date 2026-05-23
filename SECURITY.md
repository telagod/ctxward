# Security Policy

`Ctxward` is a privacy gateway sitting on the path of LLM traffic — vulnerabilities here can directly expose customer data. We take all reports seriously.

## Supported Versions

| Version | Status              |
|---------|---------------------|
| `0.x`   | Active development. Latest minor only. |
| `1.x`   | Planned GA. Will receive security patches per stated SemVer SLA once released. |

Until `1.0.0`, only the latest tagged release is patched.

## Reporting a Vulnerability

**Do not open a public GitHub issue.**

Email: `security@ctxward.dev` *(placeholder — replace before first public release)*

Optionally encrypt with our PGP key (TBD, will be published at `https://ctxward.dev/.well-known/security.txt`).

Please include:

- Affected version / commit / container digest
- Reproducer (config + curl + expected vs observed)
- Impact assessment (data exposure / DoS / auth bypass / supply chain / etc.)
- Whether you intend to disclose publicly and on what timeline

## Response SLA (target)

| Step                              | Target                  |
|-----------------------------------|-------------------------|
| Acknowledge receipt               | 2 business days         |
| Initial triage + severity         | 5 business days         |
| Fix or mitigation plan committed  | 14 days for High/Critical |
| Coordinated public disclosure     | ≤ 90 days from report   |

## Scope

In scope:

- The Ctxward gateway binary and its OCI image
- Configuration parsing, OPA / Presidio integration paths
- Admin API (`/admin/*`) auth and authorization
- Detokenization endpoint
- Multipart / OOXML / PDF rewrite paths
- Audit log content (must not leak raw PII)

Out of scope:

- Third-party services Ctxward integrates with (OPA, Presidio, OpenAI, etc.) — report upstream
- Misconfigurations in user-supplied policy
- Self-inflicted DoS via unrealistic config (e.g. infinite regex)

## Safe Harbor

Good-faith research that:

- Avoids privacy violations, data destruction, and service degradation
- Targets only your own deployments or test fixtures
- Gives us reasonable time to fix before public disclosure

…will not be pursued legally. We will publicly credit reporters in release notes unless you ask otherwise.

## Hall of Fame

*(Coming soon.)*
