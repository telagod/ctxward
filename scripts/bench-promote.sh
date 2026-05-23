#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/bench-matrix}
SUMMARY_PATH="$ROOT/summary.json"
BASELINE_PATH="$ROOT/baseline.json"

if [[ ! -f "$SUMMARY_PATH" ]]; then
  echo "missing benchmark summary: $SUMMARY_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "$BASELINE_PATH")"
cp "$SUMMARY_PATH" "$BASELINE_PATH"
echo "bench_baseline_promoted"
echo "summary=$SUMMARY_PATH"
echo "baseline=$BASELINE_PATH"
