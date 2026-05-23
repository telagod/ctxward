#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/smoke-bench-drift}
GATEWAY_PORT=${GATEWAY_PORT:-18094}
UPSTREAM_PORT=${UPSTREAM_PORT:-19112}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/admin.html \
  "$ROOT"/gateway.log \
  "$ROOT"/gate-output.txt \
  "$ROOT"/gate-report.json \
  "$ROOT"/summary.json \
  "$ROOT"/baseline.json \
  "$ROOT"/status-before.json \
  "$ROOT"/status-after.json \
  "$ROOT"/config-summary.json \
  "$ROOT"/promote.json

cargo build -q

cleanup() {
  if [[ -n "${gateway_pid:-}" ]]; then
    kill "$gateway_pid" >/dev/null 2>&1 || true
    wait "$gateway_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['ROOT'])
summary_path = root / 'summary.json'
baseline_path = root / 'baseline.json'
gate_report_path = root / 'gate-report.json'
config_path = root / 'config.yaml'

def scenario(name: str, description: str, requests: int, concurrency: int, throughput: float, avg: float, p95: float, *, payload_kind: str = 'json', request_ms: float = 0.1, response_ms: float = 0.2, upstream_ms: float = 2.5, tokenization: bool = False, session: bool = False, attachments: bool = False) -> dict:
    return {
        'scenario': name,
        'description': description,
        'generated_at': '2026-05-22T12:11:18Z',
        'requests': requests,
        'concurrency': concurrency,
        'throughput_rps': throughput,
        'latency_ms': {
            'min': round(max(avg * 0.6, 0.1), 3),
            'p50': round(avg * 0.9, 3),
            'p95': p95,
            'max': round(max(p95 * 1.2, avg * 1.3), 3),
            'avg': avg,
        },
        'payload_request_avg_ms': request_ms,
        'payload_response_avg_ms': response_ms,
        'upstream_avg_ms': upstream_ms,
        'request_payload_kind': payload_kind,
        'decision_sources': {
            'request': ['review_override_approved'] if session else ['builtin'],
            'response': ['builtin'],
        },
        'dependency_ready': {'opa': False, 'presidio': False},
        'features': {
            'attachment_scanning': attachments,
            'opa': False,
            'presidio': False,
            'response_filtering': True,
            'session_correlation': session,
            'tokenization': tokenization,
        },
        'artifacts_root': f'.tmp-smoke/smoke-bench-drift/{name}',
        'thresholds': {
            'throughput_rps_min': 100.0,
            'avg_ms_max': 40.0,
            'p95_ms_max': 250.0,
            'payload_request_avg_ms_max': 5.0,
            'payload_response_avg_ms_max': 5.0,
            'upstream_avg_ms_max': 20.0,
        },
        'ok': True,
        'aggregation': {
            'method': 'median',
            'runs': 3,
            'sample_runs': [
                {
                    'run': 'run-01',
                    'artifacts_root': f'.tmp-smoke/smoke-bench-drift/{name}/runs/run-01',
                    'throughput_rps': throughput - 10.0,
                    'avg_ms': avg + 0.1,
                    'p95_ms': p95 + 0.2,
                    'payload_request_avg_ms': request_ms,
                    'payload_response_avg_ms': response_ms,
                    'upstream_avg_ms': upstream_ms,
                    'ok': True,
                },
                {
                    'run': 'run-02',
                    'artifacts_root': f'.tmp-smoke/smoke-bench-drift/{name}/runs/run-02',
                    'throughput_rps': throughput,
                    'avg_ms': avg,
                    'p95_ms': p95,
                    'payload_request_avg_ms': request_ms,
                    'payload_response_avg_ms': response_ms,
                    'upstream_avg_ms': upstream_ms,
                    'ok': True,
                },
                {
                    'run': 'run-03',
                    'artifacts_root': f'.tmp-smoke/smoke-bench-drift/{name}/runs/run-03',
                    'throughput_rps': throughput + 10.0,
                    'avg_ms': avg - 0.1,
                    'p95_ms': p95 - 0.2,
                    'payload_request_avg_ms': request_ms,
                    'payload_response_avg_ms': response_ms,
                    'upstream_avg_ms': upstream_ms,
                    'ok': True,
                },
            ],
        },
    }

current = {
    'generated_at': '2026-05-22T12:40:21.488828+00:00',
    'scenario_count': 4,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario('json-redact', 'regression candidate', 80, 8, 1500.0, 4.2, 6.0),
        scenario('json-tokenize', 'improvement candidate', 80, 8, 1500.0, 6.0, 8.0, tokenization=True),
        scenario('json-review-replay', 'unchanged candidate', 60, 6, 1020.0, 5.2, 6.1, session=True),
        scenario('pdf-redact', 'new scenario not in baseline', 20, 2, 280.0, 7.0, 9.0, payload_kind='multipart', request_ms=2.1, response_ms=0.15, upstream_ms=3.0, attachments=True),
    ],
}

baseline = {
    'generated_at': '2026-05-21T10:01:00+00:00',
    'scenario_count': 3,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario('json-redact', 'regression candidate', 80, 8, 2000.0, 3.0, 4.0),
        scenario('json-tokenize', 'improvement candidate', 80, 8, 1200.0, 8.0, 10.0, tokenization=True),
        scenario('json-review-replay', 'unchanged candidate', 60, 6, 1000.0, 5.0, 6.0, session=True),
    ],
}

summary_path.write_text(json.dumps(current, indent=2), encoding='utf-8')
baseline_path.write_text(json.dumps(baseline, indent=2), encoding='utf-8')
config_path.write_text(f'''server:
  bind: 127.0.0.1:{os.environ['GATEWAY_PORT']}
  request_body_limit_bytes: 1048576
upstream:
  base_url: http://127.0.0.1:{os.environ['UPSTREAM_PORT']}/
  timeout_ms: 60000
  connect_timeout_ms: 5000
  auth_header: Authorization
  auth_value_env: OPENAI_API_KEY
  forward_headers:
    - content-type
    - accept
    - x-request-id
auth:
  header_name: authorization
  principals:
    - name: demo-app
      tenant_id: engineering
      role: employee
      clearance: internal
      secret_sha256: cd577fe2561ebff23505db0bb006300c7cdecbd46bc0e03c449afafaca2c25bf
      allowed_labels: []
    - name: security-admin
      tenant_id: secops
      role: admin
      clearance: restricted
      secret_sha256: 16175223c8ddce5ace0493c948569c211b03c4c6bb3d3e484434999448cffe01
      allowed_labels:
        - email
        - phone
        - national_id
        - api_key
        - bearer_token
detection:
  ignore_json_pointers:
    - /model
  presidio:
    enabled: false
    analyzer_url: http://127.0.0.1:3000/analyze
    healthcheck_url: http://127.0.0.1:3000/health
    timeout_ms: 250
    language: en
    entities: []
  rules:
    - name: email
      label: email
      pattern: '(?i)(?:^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{{2,}})(?:$|[^A-Z0-9._%+-])'
      severity: medium
      authorized_action: allow
      unauthorized_action: redact
      min_clearance: internal
      masking: partial_email
policy_backend:
  opa:
    enabled: false
    url: http://127.0.0.1:8181/v1/data/llm/privacy/decision
    healthcheck_url: http://127.0.0.1:8181/health
    timeout_ms: 150
    fail_open: true
tokenization:
  enabled: true
  key_env: CONTEXT_GURD_TOKENIZATION_KEY
  token_prefix: CGT1
session:
  enabled: true
  header_name: x-session-id
  ttl_secs: 1800
  max_entries: 5000
  correlation_threshold: 1
  trigger_action: review
response_filtering:
  enabled: true
  scan_json: true
  scan_sse: true
attachments:
  enabled: true
  max_bytes: 5242880
  max_text_chars: 32768
  allowed_media_types:
    - text/*
    - application/pdf
review:
  capacity: 1000
  preview_chars: 256
  approval_ttl_secs: 900
  jsonl_path: {root.resolve() / 'review.log'}
audit:
  jsonl_path: {root.resolve() / 'audit.log'}
  emit_stdout: false
  buffer_capacity: 1000
benchmarks:
  enabled: true
  summary_json_path: {summary_path.resolve()}
  baseline_summary_json_path: {baseline_path.resolve()}
  gate_report_json_path: {gate_report_path.resolve()}
''', encoding='utf-8')
PY

: > "$ROOT/audit.log"
: > "$ROOT/review.log"

if ROOT="$ROOT" bash scripts/bench-gate.sh > "$ROOT/gate-output.txt" 2>&1; then
  echo "expected bench gate failure for drift smoke fixture" >&2
  exit 1
fi

env \
  CONTEXT_GURD_TOKENIZATION_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  OPENAI_API_KEY=dummy-upstream-key \
  RUST_LOG=info \
  target/debug/context-gurd --config "$ROOT/config.yaml" > "$ROOT/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 80); do
  curl -fsS "$GATEWAY_URL/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "$GATEWAY_URL/healthz" >/dev/null

curl -fsS "$GATEWAY_URL/admin" | tee "$ROOT/admin.html" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status-before.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/config-summary.json" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['ROOT'])
html = root.joinpath('admin.html').read_text()
status = json.loads(root.joinpath('status-before.json').read_text())
config = json.loads(root.joinpath('config-summary.json').read_text())
bench = status['observability']['benchmarks']
baseline = bench['baseline']
gate = bench['gate']
scenarios = {row['scenario']: row for row in baseline['scenarios']}
gate_rows = {row['scenario']: row for row in gate['rows']}

assert 'Top regressions / drift watchlist' in html
assert 'benchmarkDriftSummary' in html
assert 'benchmarkDriftTable' in html
assert 'Gate verdict' in html
assert 'Gate report' in html
assert 'gate failure captured' in html
assert 'volatility band' in html
assert 'Current' in html
assert 'Baseline' in html
assert 'Proxy hard-fails' in html
assert 'Pre-upstream failure radar' in html
assert 'proxyErrorTable' in html
assert bench['enabled'] is True
assert bench['loaded'] is True
assert bench['scenario_count'] == 4
assert bench['aggregation']['method'] == 'median'
assert bench['aggregation']['runs'] == 3
assert baseline['loaded'] is True
assert baseline['scenario_count'] == 3
assert baseline['regressions'] == 1
assert baseline['improvements'] == 1
assert baseline['unchanged'] == 1
assert baseline['missing_in_baseline'] == 1
assert gate['loaded'] is True
assert gate['status'] == 'fail'
assert gate['fresh'] is True
assert gate['aggregation_compatible'] is True
assert gate['summary_generated_at'] == bench['generated_at']
assert gate['baseline_generated_at'] == baseline['generated_at']
assert gate['scenario_count'] == 4
assert gate['baseline_scenario_count'] == 3
assert gate['regressions'] == 1
assert gate['improvements'] == 1
assert gate['unchanged'] == 1
assert gate['new_scenarios'] == 1
assert gate['thresholds']['avg_latency_floor_ms'] == 0.25
assert gate['thresholds']['p95_latency_floor_ms'] == 0.5
assert gate['thresholds']['volatility_guard_mode'] == 'sample-range-overlap'
assert len(gate['rows']) == 4
assert len(gate['failures']) == 2
assert any('regression count 1 exceeds allowed 0' in item for item in gate['failures'])
assert any('json-redact' in item for item in gate['failures'])
assert scenarios['json-redact']['classification'] == 'regression'
assert scenarios['json-tokenize']['classification'] == 'improvement'
assert scenarios['json-review-replay']['classification'] == 'unchanged'
assert scenarios['pdf-redact']['classification'] == 'new'
assert gate_rows['json-redact']['classification'] == 'regression'
assert gate_rows['json-tokenize']['classification'] == 'improvement'
assert gate_rows['json-review-replay']['classification'] == 'unchanged'
assert gate_rows['pdf-redact']['classification'] == 'new'
assert gate_rows['json-review-replay']['suppressed_regression_metrics'] == []
assert scenarios['json-redact']['throughput_delta_pct'] < -20.0
assert scenarios['json-tokenize']['avg_delta_pct'] < -20.0
assert scenarios['pdf-redact']['throughput_delta_pct'] is None
assert bench['scenarios'][0]['aggregation']['runs'] == 3
assert len(bench['scenarios'][0]['aggregation']['sample_runs']) == 3
assert config['benchmarks']['enabled'] is True
assert config['benchmarks']['summary_json_path'].endswith('summary.json')
assert config['benchmarks']['baseline_summary_json_path'].endswith('baseline.json')
assert config['benchmarks']['gate_report_json_path'].endswith('gate-report.json')
PY

curl -fsS -X POST \
  -H 'Authorization: Bearer admin-secret' \
  "$GATEWAY_URL/admin/benchmarks/promote" | tee "$ROOT/promote.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status-after.json" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['ROOT'])
status = json.loads(root.joinpath('status-after.json').read_text())
promotion = json.loads(root.joinpath('promote.json').read_text())
summary_raw = root.joinpath('summary.json').read_text()
baseline_raw = root.joinpath('baseline.json').read_text()
bench = status['observability']['benchmarks']
baseline = bench['baseline']
gate = bench['gate']

assert promotion['status'] == 'baseline_promoted'
assert summary_raw == baseline_raw
assert baseline['loaded'] is True
assert baseline['regressions'] == 0
assert baseline['improvements'] == 0
assert baseline['unchanged'] == 4
assert baseline['missing_in_baseline'] == 0
assert all(row['classification'] == 'unchanged' for row in baseline['scenarios'])
assert gate['loaded'] is True
assert gate['status'] == 'fail'
assert gate['fresh'] is False
assert gate['aggregation_compatible'] is True
assert gate['regressions'] == 1
assert gate['new_scenarios'] == 1
assert gate['baseline_generated_at'] != baseline['generated_at']
print('smoke_bench_drift_ok')
print('before=regression:1 improvement:1 unchanged:1 new:1')
print('gate_before=fail:fresh gate_after=fail:stale')
print('after=unchanged:4')
PY
