#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/bench-smoke}
GATEWAY_PORT=${GATEWAY_PORT:-18093}
UPSTREAM_PORT=${UPSTREAM_PORT:-19111}
OPA_PORT=${OPA_PORT:-18181}
PRESIDIO_PORT=${PRESIDIO_PORT:-19301}
REQUESTS=${REQUESTS:-80}
CONCURRENCY=${CONCURRENCY:-8}

python3 scripts/bench_harness.py scenario \
  --scenario json-redact \
  --root "$ROOT" \
  --gateway-port "$GATEWAY_PORT" \
  --upstream-port "$UPSTREAM_PORT" \
  --opa-port "$OPA_PORT" \
  --presidio-port "$PRESIDIO_PORT" \
  --requests "$REQUESTS" \
  --concurrency "$CONCURRENCY"
