#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/bench-matrix}
GATEWAY_PORT=${GATEWAY_PORT:-18120}
UPSTREAM_PORT=${UPSTREAM_PORT:-19140}
OPA_PORT=${OPA_PORT:-18220}
PRESIDIO_PORT=${PRESIDIO_PORT:-19340}
RUNS=${RUNS:-3}

python3 scripts/bench_harness.py matrix \
  --root "$ROOT" \
  --gateway-port "$GATEWAY_PORT" \
  --upstream-port "$UPSTREAM_PORT" \
  --opa-port "$OPA_PORT" \
  --presidio-port "$PRESIDIO_PORT" \
  --runs "$RUNS"
