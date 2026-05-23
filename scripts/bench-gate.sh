#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/bench-matrix}

python3 scripts/bench_regression_gate.py \
  --summary "$ROOT/summary.json" \
  --baseline "$ROOT/baseline.json" \
  --report-json "$ROOT/gate-report.json" \
  "$@"
