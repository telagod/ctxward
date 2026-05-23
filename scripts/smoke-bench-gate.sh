#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/smoke-bench-gate}
PASS_ROOT="$ROOT/pass"
FAIL_ROOT="$ROOT/fail"
MISMATCH_ROOT="$ROOT/mismatch"
JITTER_ROOT="$ROOT/jitter"
export ROOT PASS_ROOT FAIL_ROOT MISMATCH_ROOT JITTER_ROOT

rm -rf "$ROOT"
mkdir -p "$PASS_ROOT" "$FAIL_ROOT" "$MISMATCH_ROOT" "$JITTER_ROOT"

python3 - <<'PY'
import json
import os
from pathlib import Path

pass_root = Path(os.environ['PASS_ROOT'])
fail_root = Path(os.environ['FAIL_ROOT'])
mismatch_root = Path(os.environ['MISMATCH_ROOT'])
jitter_root = Path(os.environ['JITTER_ROOT'])


def scenario(name, throughput, avg_ms, p95_ms, *, tokenization=False, sample_runs=None):
    runs = sample_runs or [
        {
            'run': 'run-01',
            'artifacts_root': f'.tmp-smoke/{name}/runs/run-01',
            'throughput_rps': throughput - 10.0,
            'avg_ms': avg_ms + 0.1,
            'p95_ms': p95_ms + 0.2,
            'payload_request_avg_ms': 0.1,
            'payload_response_avg_ms': 0.2,
            'upstream_avg_ms': 2.5,
            'ok': True,
        },
        {
            'run': 'run-02',
            'artifacts_root': f'.tmp-smoke/{name}/runs/run-02',
            'throughput_rps': throughput,
            'avg_ms': avg_ms,
            'p95_ms': p95_ms,
            'payload_request_avg_ms': 0.1,
            'payload_response_avg_ms': 0.2,
            'upstream_avg_ms': 2.5,
            'ok': True,
        },
        {
            'run': 'run-03',
            'artifacts_root': f'.tmp-smoke/{name}/runs/run-03',
            'throughput_rps': throughput + 10.0,
            'avg_ms': avg_ms - 0.1,
            'p95_ms': p95_ms - 0.2,
            'payload_request_avg_ms': 0.1,
            'payload_response_avg_ms': 0.2,
            'upstream_avg_ms': 2.5,
            'ok': True,
        },
    ]
    return {
        'scenario': name,
        'description': name,
        'generated_at': '2026-05-22T12:11:18Z',
        'requests': 80,
        'concurrency': 8,
        'throughput_rps': throughput,
        'latency_ms': {'min': 1.0, 'p50': 2.0, 'p95': p95_ms, 'max': 4.0, 'avg': avg_ms},
        'payload_request_avg_ms': 0.1,
        'payload_response_avg_ms': 0.2,
        'upstream_avg_ms': 2.5,
        'request_payload_kind': 'json',
        'decision_sources': {'request': ['builtin'], 'response': ['builtin']},
        'dependency_ready': {'opa': False, 'presidio': False},
        'features': {
            'attachment_scanning': False,
            'opa': False,
            'presidio': False,
            'response_filtering': True,
            'session_correlation': False,
            'tokenization': tokenization,
        },
        'artifacts_root': f'.tmp-smoke/{name}',
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
            'sample_runs': runs,
        },
    }

pass_current = {
    'generated_at': '2026-05-22T12:40:21.488828+00:00',
    'scenario_count': 3,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario('json-redact', 1900.0, 3.8, 5.2),
        scenario('json-tokenize', 1500.0, 5.2, 7.6, tokenization=True),
        scenario('pdf-redact', 240.0, 7.0, 8.0),
    ],
}
pass_baseline = {
    'generated_at': '2026-05-21T10:01:00+00:00',
    'scenario_count': 2,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario('json-redact', 1750.0, 4.4, 6.0),
        scenario('json-tokenize', 1490.0, 5.5, 8.1, tokenization=True),
    ],
}
fail_current = {
    'generated_at': '2026-05-22T12:40:21.488828+00:00',
    'scenario_count': 2,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario('json-redact', 1200.0, 6.6, 9.5),
        scenario('json-tokenize', 1300.0, 5.8, 8.0, tokenization=True),
    ],
}
fail_baseline = {
    'generated_at': '2026-05-21T10:01:00+00:00',
    'scenario_count': 2,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario('json-redact', 1800.0, 4.0, 6.0),
        scenario('json-tokenize', 1250.0, 6.4, 8.8, tokenization=True),
    ],
}
jitter_current = {
    'generated_at': '2026-05-22T12:40:21.488828+00:00',
    'scenario_count': 1,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario(
            'json-review-replay',
            930.0,
            5.55,
            7.05,
            sample_runs=[
                {
                    'run': 'run-01',
                    'artifacts_root': '.tmp-smoke/json-review-replay/runs/run-01',
                    'throughput_rps': 900.0,
                    'avg_ms': 5.1,
                    'p95_ms': 6.3,
                    'payload_request_avg_ms': 0.1,
                    'payload_response_avg_ms': 0.2,
                    'upstream_avg_ms': 2.5,
                    'ok': True,
                },
                {
                    'run': 'run-02',
                    'artifacts_root': '.tmp-smoke/json-review-replay/runs/run-02',
                    'throughput_rps': 930.0,
                    'avg_ms': 5.55,
                    'p95_ms': 7.05,
                    'payload_request_avg_ms': 0.1,
                    'payload_response_avg_ms': 0.2,
                    'upstream_avg_ms': 2.5,
                    'ok': True,
                },
                {
                    'run': 'run-03',
                    'artifacts_root': '.tmp-smoke/json-review-replay/runs/run-03',
                    'throughput_rps': 1080.0,
                    'avg_ms': 5.95,
                    'p95_ms': 7.25,
                    'payload_request_avg_ms': 0.1,
                    'payload_response_avg_ms': 0.2,
                    'upstream_avg_ms': 2.5,
                    'ok': True,
                },
            ],
        ),
    ],
}
jitter_baseline = {
    'generated_at': '2026-05-21T10:01:00+00:00',
    'scenario_count': 1,
    'aggregation': {'method': 'median', 'runs': 3},
    'scenarios': [
        scenario(
            'json-review-replay',
            1000.0,
            5.0,
            6.5,
            sample_runs=[
                {
                    'run': 'run-01',
                    'artifacts_root': '.tmp-smoke/json-review-replay/runs/run-01',
                    'throughput_rps': 880.0,
                    'avg_ms': 4.8,
                    'p95_ms': 6.1,
                    'payload_request_avg_ms': 0.1,
                    'payload_response_avg_ms': 0.2,
                    'upstream_avg_ms': 2.5,
                    'ok': True,
                },
                {
                    'run': 'run-02',
                    'artifacts_root': '.tmp-smoke/json-review-replay/runs/run-02',
                    'throughput_rps': 1000.0,
                    'avg_ms': 5.0,
                    'p95_ms': 6.5,
                    'payload_request_avg_ms': 0.1,
                    'payload_response_avg_ms': 0.2,
                    'upstream_avg_ms': 2.5,
                    'ok': True,
                },
                {
                    'run': 'run-03',
                    'artifacts_root': '.tmp-smoke/json-review-replay/runs/run-03',
                    'throughput_rps': 1120.0,
                    'avg_ms': 5.6,
                    'p95_ms': 7.2,
                    'payload_request_avg_ms': 0.1,
                    'payload_response_avg_ms': 0.2,
                    'upstream_avg_ms': 2.5,
                    'ok': True,
                },
            ],
        ),
    ],
}

for root, current, baseline in [
    (pass_root, pass_current, pass_baseline),
    (fail_root, fail_current, fail_baseline),
    (jitter_root, jitter_current, jitter_baseline),
]:
    root.mkdir(parents=True, exist_ok=True)
    root.joinpath('summary.json').write_text(json.dumps(current, indent=2), encoding='utf-8')
    root.joinpath('baseline.json').write_text(json.dumps(baseline, indent=2), encoding='utf-8')

mismatch_root.joinpath('summary.json').write_text(json.dumps(pass_current, indent=2), encoding='utf-8')
mismatch_baseline = dict(pass_baseline)
mismatch_baseline.pop('aggregation', None)
mismatch_root.joinpath('baseline.json').write_text(json.dumps(mismatch_baseline, indent=2), encoding='utf-8')
PY

ROOT="$PASS_ROOT" ./scripts/bench-gate.sh | tee "$PASS_ROOT/output.txt" >/dev/null
if ROOT="$FAIL_ROOT" ./scripts/bench-gate.sh > "$FAIL_ROOT/output.txt" 2>&1; then
  echo "expected bench gate failure but command passed" >&2
  exit 1
fi
ROOT="$JITTER_ROOT" ./scripts/bench-gate.sh | tee "$JITTER_ROOT/output.txt" >/dev/null
if ROOT="$MISMATCH_ROOT" ./scripts/bench-gate.sh > "$MISMATCH_ROOT/output.txt" 2>&1; then
  echo "expected aggregation mismatch gate failure but command passed" >&2
  exit 1
fi

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['ROOT'])
pass_report = json.loads(root.joinpath('pass/gate-report.json').read_text())
fail_report = json.loads(root.joinpath('fail/gate-report.json').read_text())
jitter_report = json.loads(root.joinpath('jitter/gate-report.json').read_text())
mismatch_report = json.loads(root.joinpath('mismatch/gate-report.json').read_text())
pass_output = root.joinpath('pass/output.txt').read_text()
fail_output = root.joinpath('fail/output.txt').read_text()
jitter_output = root.joinpath('jitter/output.txt').read_text()
mismatch_output = root.joinpath('mismatch/output.txt').read_text()

assert pass_report['status'] == 'pass'
assert pass_report['aggregation_compatible'] is True
assert pass_report['regressions'] == 0
assert pass_report['improvements'] >= 1
assert pass_report['new_scenarios'] == 1
assert 'benchmark_regression_gate: PASS' in pass_output
assert 'json-redact' in pass_output

assert fail_report['status'] == 'fail'
assert fail_report['aggregation_compatible'] is True
assert fail_report['regressions'] == 1
assert any('json-redact' in item for item in fail_report['failures'])
assert 'benchmark_regression_gate: FAIL' in fail_output
assert 'regression count 1 exceeds allowed 0' in fail_output

assert jitter_report['status'] == 'pass'
assert jitter_report['aggregation_compatible'] is True
assert jitter_report['regressions'] == 0
assert jitter_report['unchanged'] == 1
jitter_row = jitter_report['rows'][0]
assert jitter_row['scenario'] == 'json-review-replay'
assert jitter_row['classification'] == 'unchanged'
assert sorted(jitter_row['suppressed_regression_metrics']) == ['avg_ms', 'throughput_rps']
assert jitter_report['thresholds']['volatility_guard_mode'] == 'sample-range-overlap'
assert 'noise-suppressed=regression:throughput_rps,avg_ms' in jitter_output

assert mismatch_report['status'] == 'fail'
assert mismatch_report['aggregation_compatible'] is False
assert any('aggregation mismatch' in item for item in mismatch_report['failures'])
assert 'compatible=no' in mismatch_output
print('smoke_bench_gate_ok')
print('pass=0 regressions / 1 new allowed')
print('fail=1 regression rejected')
print('jitter=raw delta suppressed by overlapping sample ranges')
print('mismatch=aggregation mismatch rejected')
PY
