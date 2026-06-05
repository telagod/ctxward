# Committed benchmark baseline

`baseline.json` is the reference the **relative** performance gate diffs against.

## Why this exists

The PR/`main` `bench` job (`.github/workflows/ci.yml`) self-seeds its baseline
from the same run — it copies `summary.json` to `baseline.json` when none
exists (`scripts/bench_harness.py`, the matrix step). That makes its relative
gate compare a run against itself: zero discrimination, pure smoke test. Its
absolute gates are also relaxed to warnings on shared runners (see
`PERF_RELAXED` in `bench_harness.py`). So on hosted CI the `bench` job is
**informational only**.

`bench-nightly.yml` fixes that by pre-placing this committed `baseline.json`
into the matrix root before the run, so the gate diffs against a **real,
fixed reference** and can flag regressions.

## What the nightly gate can and cannot catch

- **Authority:** the relative regression gate (`scripts/bench_regression_gate.py`),
  current run vs this committed baseline, guarded by a volatility band built
  from the per-run `sample_runs`.
- **Catches:** large, decisive regressions — throughput drop / avg-latency rise
  where the run's sample range no longer overlaps the baseline's. In practice
  that means roughly **1.4–2×+ on avg latency and throughput**.
- **Does NOT reliably catch:** p95 regressions (a single shared-runner spike
  widens the baseline band — e.g. a `run-01` p95 of ~48 ms vs ~15 ms median —
  so even a 3× p95 move can be suppressed), nor sub-band drift. Absolute
  latency ceilings are warnings here, not failures (shared-hardware noise).
- **Current-snapshot caveat:** this baseline was captured with cold-start
  `run-01` outliers on **3 of 6** scenarios (json-tokenize p95 run-01 ≈ 392 ms,
  json-review-replay ≈ 112 ms, json-redact ≈ 48 ms vs ~15 ms medians). Those
  inflate the baseline band so wide the gate is **near-blind on those three**
  until re-promoted. The 3 stable scenarios (json-opa, json-presidio,
  pdf-redact) already gate well. **Follow-up:** add a harness warm-up that
  discards `run-01` before measuring, then re-promote — that restores teeth on
  all six without faking data (you cannot hand-edit a sample out: dropping a run
  breaks the median-of-3 aggregation-compat check, replacing one fabricates
  data).
- **Precision gating** (tight absolute thresholds) needs a **dedicated /
  self-hosted runner**. That is the standing follow-up; on shared hardware the
  band-guarded relative gate is the best honest signal.

On a gate failure the nightly opens/updates a `perf-regression` issue. It is
**not** a required check and blocks nothing — it is monitoring.

## Provenance of the current baseline

- Source: bench artifact `bench-matrix-26964600410` (CI run on PR #9, a clean
  GitHub-hosted `ubuntu-latest`).
- Aggregation: **median-of-3** (`runs: 3`), matching what `bench-matrix.sh`
  produces in CI — the gate refuses to compare mismatched aggregations.
- It is a shared-runner snapshot, so absolute values carry runner variance.
  That is acceptable: the gate compares *relative* deltas with a band guard.

## Re-promoting the baseline

When the numbers shift legitimately (intended perf change, or the baseline has
drifted stale), refresh it from a green nightly artifact:

```bash
# 1. Download the summary from a trusted nightly run. `-n` drops the artifact's
#    contents directly into -D; `find` keeps it correct even if your gh version
#    nests under a per-artifact subdirectory.
gh run download <run-id> -n bench-nightly-<run-id> -D /tmp/bench-nightly

# 2. Replace the baseline with that run's summary
cp "$(find /tmp/bench-nightly -name summary.json | head -1)" bench/baseline.json

# 3. Review the diff, then commit (DCO sign-off)
git add bench/baseline.json
git commit -s -m "chore(bench): re-promote committed baseline"
```

Prefer promoting from a run whose `sample_runs` are tight (no outlier spikes),
otherwise a noisy run poisons the band and dulls the gate further.
