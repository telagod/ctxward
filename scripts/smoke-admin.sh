#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/smoke-admin}
GATEWAY_PORT=${GATEWAY_PORT:-18092}
UPSTREAM_PORT=${UPSTREAM_PORT:-19110}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/summary.json \
  "$ROOT"/status.json \
  "$ROOT"/metrics.txt \
  "$ROOT"/response-body.json \
  "$ROOT"/response-headers.txt \
  "$ROOT"/review-list.json \
  "$ROOT"/resolve-body.json \
  "$ROOT"/resolve.json \
  "$ROOT"/reload-body.json \
  "$ROOT"/audit-list.json \
  "$ROOT"/detokenize.json \
  "$ROOT"/detokenize-body.json \
  "$ROOT"/request-upstream-*.json \
  "$ROOT"/upstream-count.txt \
  "$ROOT"/replay-body.json \
  "$ROOT"/replay-headers.txt \
  "$ROOT"/reload-request.json \
  "$ROOT"/reload-request-body.json \
  "$ROOT"/reload-request-headers.txt \
  "$ROOT"/summary-after-reload.json \
  "$ROOT"/report.txt
: > "$ROOT"/audit.log
: > "$ROOT"/review.log

cargo build -q

cleanup() {
  if [[ -n "${gateway_pid:-}" ]]; then
    kill "$gateway_pid" >/dev/null 2>&1 || true
    wait "$gateway_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${upstream_pid:-}" ]]; then
    kill "$upstream_pid" >/dev/null 2>&1 || true
    wait "$upstream_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY'
import os
from pathlib import Path
root = Path(os.environ['ROOT'])
root.mkdir(parents=True, exist_ok=True)
root.joinpath('config.yaml').write_text(f'''server:
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
  high_entropy:
    enabled: true
    min_length: 20
    min_entropy: 3.6
    label: secret_like
    severity: high
    authorized_action: redact
    unauthorized_action: block
    min_clearance: confidential
    masking: hash
  rules:
    - name: email
      label: email
      pattern: '(?i)(?:^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{{2,}})(?:$|[^A-Z0-9._%+-])'
      severity: medium
      authorized_action: allow
      unauthorized_action: redact
      min_clearance: internal
      masking: tokenize
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
  enabled: false
  max_bytes: 5242880
  max_text_chars: 32768
review:
  capacity: 1000
  preview_chars: 256
  approval_ttl_secs: 900
  jsonl_path: {root.resolve() / 'review.log'}
audit:
  jsonl_path: {root.resolve() / 'audit.log'}
  emit_stdout: false
  buffer_capacity: 1000
''', encoding='utf-8')
PY

python3 - <<'PY' > "$ROOT/upstream.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import os
ROOT = Path(os.environ['ROOT'])
COUNT = ROOT / 'upstream-count.txt'
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', '0'))
        body = self.rfile.read(length)
        current = int(COUNT.read_text(encoding='utf-8') or '0') if COUNT.exists() else 0
        current += 1
        COUNT.write_text(str(current), encoding='utf-8')
        ROOT.joinpath(f'request-upstream-{current:02d}.json').write_bytes(body)
        payload = json.dumps({'ok': True, 'echo': json.loads(body.decode('utf-8'))}).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *_):
        return
HTTPServer(('127.0.0.1', int(os.environ['UPSTREAM_PORT'])), H).serve_forever()
PY
upstream_pid=$!

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

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

cat > "$ROOT/request.json" <<'JSON'
{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"邮箱 admin@example.com"}],"stream":false}
JSON

curl -sS -D "$ROOT/response-headers.txt" \
  -o "$ROOT/response-body.json" \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: smoke-admin-1' \
  --data-binary @"$ROOT/request.json" \
  "$GATEWAY_URL/v1/chat/completions"

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/reviews?status=pending&limit=20" | tee "$ROOT/review-list.json" >/dev/null
TICKET_ID=$(ROOT="$ROOT" python3 - <<'PY'
import json
from pathlib import Path
import os
payload = json.loads(Path(os.environ['ROOT']).joinpath('review-list.json').read_text())
records = payload.get('records', [])
assert records, 'no review tickets returned'
print(records[0]['id'])
PY
)

TICKET_ID="$TICKET_ID" ROOT="$ROOT" python3 - <<'PY' > /dev/null
import json
from pathlib import Path
import os
Path(os.environ['ROOT']).joinpath('resolve.json').write_text(json.dumps({
    'id': os.environ['TICKET_ID'],
    'approve': True,
    'note': 'smoke-admin auto-approve'
}), encoding='utf-8')
PY
curl -fsS -X POST \
  -H 'Authorization: Bearer admin-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/resolve.json" \
  "$GATEWAY_URL/admin/reviews/resolve" | tee "$ROOT/resolve-body.json" >/dev/null

curl -sS -D "$ROOT/replay-headers.txt" \
  -o "$ROOT/replay-body.json" \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: smoke-admin-1' \
  -H "X-Review-Ticket-Id: $TICKET_ID" \
  --data-binary @"$ROOT/request.json" \
  "$GATEWAY_URL/v1/chat/completions"

TOKEN=$(python3 - <<'PY'
import json, re
from pathlib import Path
import os
root = Path(os.environ['ROOT'])
payload = json.loads(root.joinpath('resolve-body.json').read_text())
assert payload['status'] == 'ok'
up = json.loads(root.joinpath('request-upstream-01.json').read_text())
content = up['messages'][0]['content']
m = re.search(r'(\[[A-Z_]+:CGT1\.[^\]]+\])', content)
assert m, f'no token found in upstream content: {content}'
print(m.group(1))
PY
)

TOKEN="$TOKEN" ROOT="$ROOT" python3 - <<'PY' > /dev/null
import json, os
from pathlib import Path
Path(os.environ['ROOT']).joinpath('detokenize-body.json').write_text(
    json.dumps({'token': os.environ['TOKEN']}),
    encoding='utf-8',
)
PY
curl -fsS -X POST \
  -H 'Authorization: Bearer admin-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/detokenize-body.json" \
  "$GATEWAY_URL/admin/detokenize" | tee "$ROOT/detokenize.json" >/dev/null

ROOT="$ROOT" python3 - <<'PY' > /dev/null
from pathlib import Path
import yaml
import os

config_path = Path(os.environ['ROOT']).joinpath('config.yaml')
config = yaml.safe_load(config_path.read_text(encoding='utf-8'))
for rule in config['detection']['rules']:
    if rule.get('name') == 'email':
        rule['masking'] = 'partial_email'
        break
else:
    raise SystemExit('email rule not found in config.yaml')
config['session']['correlation_threshold'] = 2
config_path.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding='utf-8')
PY

curl -fsS -X POST \
  -H 'Authorization: Bearer admin-secret' \
  "$GATEWAY_URL/admin/reload" | tee "$ROOT/reload-body.json" >/dev/null

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary-after-reload.json" >/dev/null

cp "$ROOT/request.json" "$ROOT/reload-request.json"
ROOT="$ROOT" python3 - <<'PY' > /dev/null
import json
import os
from pathlib import Path

Path(os.environ['ROOT']).joinpath('reload-request.json').write_text(
    json.dumps(
        {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "reload-case reload@example.com"}],
            "stream": False,
        },
        ensure_ascii=False,
    ),
    encoding='utf-8',
)
PY
curl -sS -D "$ROOT/reload-request-headers.txt" \
  -o "$ROOT/reload-request-body.json" \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: smoke-admin-2' \
  --data-binary @"$ROOT/reload-request.json" \
  "$GATEWAY_URL/v1/chat/completions"

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/audits?source=both&session_id=smoke-admin-1&limit=20" | tee "$ROOT/audit-list.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
from pathlib import Path
import os
root = Path(os.environ['ROOT'])
status = json.loads(root.joinpath('status.json').read_text())
summary = json.loads(root.joinpath('summary.json').read_text())
summary_after = json.loads(root.joinpath('summary-after-reload.json').read_text())
reviews = json.loads(root.joinpath('review-list.json').read_text())
audits = json.loads(root.joinpath('audit-list.json').read_text())
detok = json.loads(root.joinpath('detokenize.json').read_text())
response = json.loads(root.joinpath('response-body.json').read_text())
replay = json.loads(root.joinpath('replay-body.json').read_text())
reload_payload = json.loads(root.joinpath('reload-body.json').read_text())
reload_request = json.loads(root.joinpath('reload-request-body.json').read_text())
upstream_replay = json.loads(root.joinpath('request-upstream-01.json').read_text())
upstream_reload = json.loads(root.joinpath('request-upstream-02.json').read_text())
metrics = root.joinpath('metrics.txt').read_text()

assert status['status'] == 'ok'
assert summary['status'] == 'ok'
assert summary['tokenization']['enabled'] is True
assert summary['tokenization']['key_env_present'] is True
assert summary['runtime']['upstream_auth_env_present'] is True
assert summary['tokenization']['required_by_rules'] is True
assert summary['policy_backend']['opa']['runtime_loaded'] is False
assert reload_payload['status'] == 'reloaded'
assert summary_after['tokenization']['enabled'] is True
assert summary_after['tokenization']['required_by_rules'] is False
assert summary_after['session']['correlation_threshold'] == 2
assert response['error']['code'] == 'review_required'
assert response['review']['post_approval_action'] == 'redact'
assert reviews['count'] >= 1
assert replay['ok'] is True
assert reload_request['ok'] is True
assert reload_request['echo']['messages'][0]['content'] == 'reload-case r***@example.com'
assert status['sessions'] >= 1
assert status['review_queue']['pending'] == 0
assert detok['value'] == 'admin@example.com'
assert '[EMAIL_TOKEN:CGT1.' in upstream_replay['messages'][0]['content']
assert 'admin@example.com' not in upstream_replay['messages'][0]['content']
assert upstream_reload['messages'][0]['content'] == 'reload-case r***@example.com'
assert audits['count'] >= 1
assert any(record['policy_source'] == 'review_override_approved' for record in audits['records'])
assert 'gateway_policy_decisions_total' in metrics
assert 'gateway_review_events_total' in metrics
assert status['observability']['metrics_summary']['counters']['review_events_total']['created'] >= 1
assert status['observability']['metrics_summary']['counters']['review_events_total']['approved'] >= 1
print('smoke_admin_ok')
print(upstream_replay['messages'][0]['content'])
print(detok['value'])
PY

ROOT="$ROOT" python3 - <<'PY' > "$ROOT/report.txt"
import json
from pathlib import Path
import os
root = Path(os.environ['ROOT'])
status = json.loads(root.joinpath('status.json').read_text())
summary = json.loads(root.joinpath('summary.json').read_text())
summary_after = json.loads(root.joinpath('summary-after-reload.json').read_text())
reviews = json.loads(root.joinpath('review-list.json').read_text())
detok = json.loads(root.joinpath('detokenize.json').read_text())
upstream_replay = json.loads(root.joinpath('request-upstream-01.json').read_text())
upstream_reload = json.loads(root.joinpath('request-upstream-02.json').read_text())
print('status=ok')
print(f"review_count={reviews['count']}")
print(f"tokenization_enabled={summary['tokenization']['enabled']}")
print(f"tokenization_env_present={summary['tokenization']['key_env_present']}")
print(f"upstream_auth_env_present={summary['runtime']['upstream_auth_env_present']}")
print(f"masked_upstream={upstream_replay['messages'][0]['content']}")
print(f"reload_masked_upstream={upstream_reload['messages'][0]['content']}")
print(f"detokenized={detok['value']}")
print(f"sessions={status['sessions']}")
print(f"reload_tokenization_enabled={summary_after['tokenization']['enabled']}")
print(f"reload_threshold={summary_after['session']['correlation_threshold']}")
PY

cat "$ROOT/report.txt"
