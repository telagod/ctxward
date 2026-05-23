#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-presidio}
GATEWAY_PORT=${GATEWAY_PORT:-18101}
UPSTREAM_PORT=${UPSTREAM_PORT:-19121}
PRESIDIO_PORT=${PRESIDIO_PORT:-19321}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT PRESIDIO_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/presidio.log \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/request.json \
  "$ROOT"/readyz.json \
  "$ROOT"/status.json \
  "$ROOT"/summary.json \
  "$ROOT"/metrics.txt \
  "$ROOT"/response-body.json \
  "$ROOT"/response-headers.txt \
  "$ROOT"/upstream-request.json \
  "$ROOT"/presidio-inputs.jsonl \
  "$ROOT"/upstream_json.py \
  "$ROOT"/presidio_stub.py

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
  if [[ -n "${presidio_pid:-}" ]]; then
    kill "$presidio_pid" >/dev/null 2>&1 || true
    wait "$presidio_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY'
import json
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
    enabled: true
    analyzer_url: http://127.0.0.1:{os.environ['PRESIDIO_PORT']}/analyze
    healthcheck_url: http://127.0.0.1:{os.environ['PRESIDIO_PORT']}/health
    timeout_ms: 250
    language: en
    entities:
      - entity_type: EMAIL_ADDRESS
        label: email
        severity: medium
        authorized_action: allow
        unauthorized_action: redact
        min_clearance: internal
        masking: partial_email
        min_score: 0.35
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
  rules: []
policy_backend:
  opa:
    enabled: false
    url: http://127.0.0.1:18181/v1/data/llm/privacy/decision
    healthcheck_url: http://127.0.0.1:18181/health
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
  allowed_media_types:
    - text/*
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
root.joinpath("request.json").write_text(
    json.dumps(
        {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "邮箱 admin@example.com"}],
            "stream": False,
        },
        ensure_ascii=False,
    ),
    encoding="utf-8",
)
PY

: > "$ROOT/audit.log"
: > "$ROOT/review.log"
: > "$ROOT/presidio-inputs.jsonl"

cat > "$ROOT/upstream_json.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
OUT = ROOT / "upstream-request.json"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"ok": True}).encode("utf-8")
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
        payload = json.loads(raw.decode("utf-8"))
        OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        body = json.dumps(
            {
                "ok": True,
                "echo": payload,
                "model_output": "联系人 admin@example.com",
            },
            ensure_ascii=False,
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", int(os.environ["UPSTREAM_PORT"])), Handler).serve_forever()
PY

cat > "$ROOT/presidio_stub.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
OUT = ROOT / "presidio-inputs.jsonl"
NEEDLE = "admin@example.com"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            payload = json.dumps({"ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        with OUT.open("ab") as handle:
            handle.write(raw + b"\n")
        payload = json.loads(raw.decode("utf-8"))
        text = payload.get("text", "")
        findings = []
        start = text.find(NEEDLE)
        if start >= 0:
            findings.append(
                {
                    "start": start,
                    "end": start + len(NEEDLE),
                    "score": 0.99,
                    "entity_type": "EMAIL_ADDRESS",
                }
            )
        body = json.dumps(findings).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", int(os.environ["PRESIDIO_PORT"])), Handler).serve_forever()
PY

python3 "$ROOT/upstream_json.py" > "$ROOT/upstream.log" 2>&1 &
upstream_pid=$!

python3 "$ROOT/presidio_stub.py" > "$ROOT/presidio.log" 2>&1 &
presidio_pid=$!

for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/health" >/dev/null 2>&1 \
    && curl -fsS "http://127.0.0.1:${PRESIDIO_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/health" >/dev/null
curl -fsS "http://127.0.0.1:${PRESIDIO_PORT}/health" >/dev/null

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

curl -sS -D "$ROOT/response-headers.txt" \
  -o "$ROOT/response-body.json" \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/request.json" \
  "$GATEWAY_URL/v1/chat/completions" >/dev/null

curl -fsS "$GATEWAY_URL/readyz" | tee "$ROOT/readyz.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

for _ in $(seq 1 40); do
  if [[ -s "$ROOT/upstream-request.json" ]] \
    && grep -q '"direction":"response"' "$ROOT/audit.log" 2>/dev/null \
    && grep -q 'admin@example.com' "$ROOT/presidio-inputs.jsonl" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
body_bytes = root.joinpath("response-body.json").read_bytes()
body_text = body_bytes.decode("utf-8")
headers = root.joinpath("response-headers.txt").read_text(encoding="utf-8").lower()
readyz = json.loads(root.joinpath("readyz.json").read_text(encoding="utf-8"))
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
summary = json.loads(root.joinpath("summary.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
upstream_request = json.loads(root.joinpath("upstream-request.json").read_text(encoding="utf-8"))
audit_records = [
    json.loads(line)
    for line in root.joinpath("audit.log").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
presidio_inputs = [
    json.loads(line)
    for line in root.joinpath("presidio-inputs.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
response_payload = json.loads(body_text)

assert upstream_request["messages"][0]["content"] == "邮箱 a***@example.com", upstream_request
assert "admin@example.com" not in json.dumps(upstream_request, ensure_ascii=False), upstream_request

assert response_payload["echo"]["messages"][0]["content"] == "邮箱 a***@example.com", response_payload
assert response_payload["model_output"] == "联系人 a***@example.com", response_payload
assert "admin@example.com" not in body_text, body_text

assert "http/1.1 200 ok" in headers, headers
assert "content-type: application/json" in headers, headers
assert "x-privacy-gateway-action: redact" in headers, headers
assert "transfer-encoding:" not in headers, headers
assert f"content-length: {len(body_bytes)}" in headers, headers

assert readyz["ready"] is True, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["configured"] is True, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["reachable"] is True, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["status_code"] == 200, readyz

assert status["features"]["presidio"] is True, status
assert status["dependencies"]["presidio"]["configured"] is True, status
assert status["dependencies"]["presidio"]["reachable"] is True, status
assert status["dependencies"]["presidio"]["status_code"] == 200, status
assert status["observability"]["runtime_summary"]["dependency_ready"]["presidio"] is True, status

summary_counters = status["observability"]["metrics_summary"]["counters"]
assert summary_counters["detections_total"]["request"]["email"] == 1, summary_counters
assert summary_counters["detections_total"]["response"]["email"] == 1, summary_counters
assert summary_counters["policy_decisions_total"]["request"]["redact"]["builtin"] == 1, summary_counters
assert summary_counters["policy_decisions_total"]["response"]["redact"]["builtin"] == 1, summary_counters

presidio_summary = summary["detection"]["presidio"]
assert presidio_summary["enabled"] is True, presidio_summary
assert presidio_summary["entity_count"] == 1, presidio_summary
assert presidio_summary["entities"][0]["entity_type"] == "EMAIL_ADDRESS", presidio_summary
assert presidio_summary["entities"][0]["label"] == "email", presidio_summary
assert presidio_summary["analyzer_url"].endswith("/analyze"), presidio_summary
assert presidio_summary["healthcheck_url"].endswith("/health"), presidio_summary

assert 'gateway_dependency_configured{dependency="presidio"} 1' in metrics, metrics
assert 'gateway_dependency_ready{dependency="presidio"} 1' in metrics, metrics
assert 'gateway_dependency_status_code{dependency="presidio"} 200' in metrics, metrics
assert 'gateway_detections_total{direction="request",label="email"} 1' in metrics, metrics
assert 'gateway_detections_total{direction="response",label="email"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="redact",direction="request",source="builtin"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="redact",direction="response",source="builtin"} 1' in metrics, metrics

assert "admin@example.com" not in root.joinpath("audit.log").read_text(encoding="utf-8")
request_record = next(item for item in audit_records if item["direction"] == "request")
response_record = next(item for item in audit_records if item["direction"] == "response")
assert request_record["decision"] == "redact", request_record
assert response_record["decision"] == "redact", response_record
assert request_record["policy_source"] == "builtin", request_record
assert response_record["policy_source"] == "builtin", response_record
assert "presidio:EMAIL_ADDRESS" in request_record["matched_rules"], request_record
assert "presidio:EMAIL_ADDRESS" in response_record["matched_rules"], response_record
assert "email" in request_record["matched_labels"], request_record
assert "email" in response_record["matched_labels"], response_record

texts = [item.get("text", "") for item in presidio_inputs]
assert any(text == "邮箱 admin@example.com" for text in texts), texts
assert any(text == "联系人 admin@example.com" for text in texts), texts

print("smoke_presidio_ok")
print("presidio sidecar redacted request and response")
print("utf8 char-offset conversion proved with chinese prefix")
print("readyz status config-summary metrics and audit evidence captured")
PY
