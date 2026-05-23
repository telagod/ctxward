#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-builtin-block}
GATEWAY_PORT=${GATEWAY_PORT:-18105}
UPSTREAM_PORT=${UPSTREAM_PORT:-19125}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/status.json \
  "$ROOT"/summary.json \
  "$ROOT"/metrics.txt \
  "$ROOT"/audit-list.json \
  "$ROOT"/request-phone.json \
  "$ROOT"/request-id.json \
  "$ROOT"/phone-body.json \
  "$ROOT"/phone-headers.txt \
  "$ROOT"/phone-status.txt \
  "$ROOT"/id-body.json \
  "$ROOT"/id-headers.txt \
  "$ROOT"/id-status.txt \
  "$ROOT"/upstream-count.txt \
  "$ROOT"/upstream-request-*.json \
  "$ROOT"/upstream_json.py

: > "$ROOT/audit.log"
: > "$ROOT/review.log"

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

root = Path(os.environ["ROOT"]).resolve()
root.mkdir(parents=True, exist_ok=True)
root.joinpath("config.yaml").write_text(
    f"""server:
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
    enabled: false
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
      masking: partial_email
    - name: phone_cn
      label: phone
      pattern: '(?:^|[^0-9])(1[3-9]\\d{{9}})(?:$|[^0-9])'
      severity: high
      authorized_action: allow
      unauthorized_action: block
      min_clearance: confidential
      masking: partial_phone
    - name: china_national_id
      label: national_id
      pattern: '(?:^|[^0-9Xx])(\\d{{17}}[\\dXx])(?:$|[^0-9Xx])'
      severity: critical
      authorized_action: allow
      unauthorized_action: block
      min_clearance: restricted
      masking: keep_last4
policy_backend:
  opa:
    enabled: false
    url: http://127.0.0.1:8181/v1/data/llm/privacy/decision
    healthcheck_url: http://127.0.0.1:8181/health
    timeout_ms: 150
    fail_open: true
tokenization:
  enabled: false
  key_env: CONTEXT_GURD_TOKENIZATION_KEY
  token_prefix: CGT1
session:
  enabled: false
  header_name: x-session-id
  ttl_secs: 1800
  max_entries: 5000
  correlation_threshold: 2
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
  jsonl_path: {root / 'review.log'}
audit:
  jsonl_path: {root / 'audit.log'}
  emit_stdout: false
  buffer_capacity: 1000
""",
    encoding="utf-8",
)
root.joinpath("request-phone.json").write_text(
    '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"手机号 13812341234"}],"stream":false}',
    encoding="utf-8",
)
root.joinpath("request-id.json").write_text(
    '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"身份证 110101199003074512"}],"stream":false}',
    encoding="utf-8",
)
PY

cat > "$ROOT/upstream_json.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"]).resolve()
COUNT_FILE = ROOT / "upstream-count.txt"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        current = int(COUNT_FILE.read_text(encoding="utf-8") or "0") if COUNT_FILE.exists() else 0
        current += 1
        COUNT_FILE.write_text(str(current), encoding="utf-8")
        ROOT.joinpath(f"upstream-request-{current:02d}.json").write_bytes(raw)
        body = json.dumps({"ok": True, "request_index": current}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return

HTTPServer(("127.0.0.1", int(os.environ["UPSTREAM_PORT"])), Handler).serve_forever()
PY

python3 "$ROOT/upstream_json.py" > "$ROOT/upstream.log" 2>&1 &
upstream_pid=$!

for _ in $(seq 1 80); do
  curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/health" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/health" >/dev/null

env \
  OPENAI_API_KEY=dummy-upstream-key \
  RUST_LOG=info \
  target/debug/context-gurd --config "$ROOT/config.yaml" > "$ROOT/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 80); do
  curl -fsS "$GATEWAY_URL/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "$GATEWAY_URL/healthz" >/dev/null

curl -sS -D "$ROOT/phone-headers.txt" \
  -o "$ROOT/phone-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/request-phone.json" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/phone-status.txt"

curl -sS -D "$ROOT/id-headers.txt" \
  -o "$ROOT/id-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/request-id.json" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/id-status.txt"

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/audits?source=both&direction=request&decision=block&limit=20" | tee "$ROOT/audit-list.json" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
phone_status = root.joinpath("phone-status.txt").read_text(encoding="utf-8").strip()
id_status = root.joinpath("id-status.txt").read_text(encoding="utf-8").strip()
phone_body = json.loads(root.joinpath("phone-body.json").read_text(encoding="utf-8"))
id_body = json.loads(root.joinpath("id-body.json").read_text(encoding="utf-8"))
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
summary = json.loads(root.joinpath("summary.json").read_text(encoding="utf-8"))
audits = json.loads(root.joinpath("audit-list.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
audit_text = root.joinpath("audit.log").read_text(encoding="utf-8")
review_text = root.joinpath("review.log").read_text(encoding="utf-8")

count_file = root.joinpath("upstream-count.txt")
upstream_count = int(count_file.read_text(encoding="utf-8") or "0") if count_file.exists() else 0

assert phone_status == "403", phone_status
assert id_status == "403", id_status
assert phone_body["error"]["code"] == "blocked_sensitive_payload", phone_body
assert id_body["error"]["code"] == "blocked_sensitive_payload", id_body
assert phone_body["request_id"], phone_body
assert id_body["request_id"], id_body
assert "request contains sensitive data not permitted by policy" in phone_body["error"]["message"], phone_body
assert "request contains sensitive data not permitted by policy" in id_body["error"]["message"], id_body

assert upstream_count == 0, upstream_count
assert not list(root.glob("upstream-request-*.json"))

assert status["status"] == "ok", status
assert summary["status"] == "ok", summary
assert summary["session"]["enabled"] is False, summary
assert summary["review"]["capacity"] == 1000, summary

assert audits["count"] >= 2, audits
records = audits["records"]
assert any("phone" in record["matched_labels"] and record["decision"] == "block" for record in records), records
assert any("national_id" in record["matched_labels"] and record["decision"] == "block" for record in records), records
assert all(record["policy_source"] == "builtin" for record in records[:2]), records
assert all(record["status_code"] == 403 for record in records[:2]), records

assert "13812341234" not in audit_text, audit_text
assert "110101199003074512" not in audit_text, audit_text
assert review_text.strip() == "", review_text

assert status["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]["block"]["builtin"] == 2, status
assert 'gateway_policy_decisions_total{decision="block",direction="request",source="builtin"} 2' in metrics, metrics
assert 'gateway_detections_total{direction="request",label="phone"} 1' in metrics, metrics
assert 'gateway_detections_total{direction="request",label="national_id"} 1' in metrics, metrics

print("smoke_builtin_block_ok")
print("unauthorized phone and national_id were blocked before upstream forwarding")
print("audit captured builtin block decisions without leaking raw PII")
print("metrics recorded request block decisions and label detections")
PY
