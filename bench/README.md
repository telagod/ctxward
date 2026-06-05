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
- **Cold-start handled:** the harness now discards a warm-up run before
  measuring (`bench-matrix --warmup`, default 1), so the page-cache cold-start
  spike no longer lands in `sample_runs`. After re-promotion the p95 bands are
  tight — json-redact p95 band 15.4–15.9 ms (≈ 1.03×), down from a 14.8–47.9 ms
  (3.2×) cold-start spread — giving the gate real teeth.
- **Does NOT reliably catch:** sub-band drift, and one per-scenario quirk:
  json-tokenize *throughput* still swings widely (a run can drop to ~75 rps vs
  ~640) from occasional shared-runner CPU contention, so its throughput band
  stays wide and dull (its latency band is tight). Absolute latency ceilings are
  warnings here, not failures (shared-hardware noise). To tame json-tokenize
  throughput further, bump `RUNS` (5+) on a re-promote — optional.
- **Precision gating** (tight absolute thresholds) needs a **dedicated /
  self-hosted runner**. That is the standing follow-up; on shared hardware the
  band-guarded relative gate is the best honest signal.

On a gate failure the nightly opens/updates a `perf-regression` issue. It is
**not** a required check and blocks nothing — it is monitoring.

## Provenance of the current baseline

- Source: bench artifact `bench-matrix-27030890788` (a **warm-up-enabled** CI
  run on `main`, a clean GitHub-hosted `ubuntu-latest`).
- Captured with `--warmup 1`: one discarded warm-up run primes the page cache so
  every measured run is cache-warm. Bands are tight (p95 ≈ 1.0–1.2× across
  scenarios), except json-tokenize throughput (CPU-contention swing, see above).
- Aggregation: **median-of-3** (`runs: 3`), matching what `bench-matrix.sh`
  produces in CI — the gate refuses to compare mismatched aggregations.
- Still a shared-runner snapshot, so absolute values carry runner variance; the
  gate compares *relative* deltas with a band guard.

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
