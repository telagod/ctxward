#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-sse}
GATEWAY_PORT=${GATEWAY_PORT:-18098}
UPSTREAM_PORT=${UPSTREAM_PORT:-19118}
OPA_PORT=${OPA_PORT:-18182}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT OPA_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/opa.log \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/opa-inputs.jsonl \
  "$ROOT"/mode.txt \
  "$ROOT"/request.json \
  "$ROOT"/upstream-request.json \
  "$ROOT"/response-body.txt \
  "$ROOT"/response-headers.txt \
  "$ROOT"/upstream_sse.py \
  "$ROOT"/opa_response_only.py

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
  if [[ -n "${opa_pid:-}" ]]; then
    kill "$opa_pid" >/dev/null 2>&1 || true
    wait "$opa_pid" >/dev/null 2>&1 || true
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
      allowed_labels:
        - email
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
  rules: []
policy_backend:
  opa:
    enabled: true
    url: http://127.0.0.1:{os.environ['OPA_PORT']}/v1/data/llm/privacy/decision
    healthcheck_url: http://127.0.0.1:{os.environ['OPA_PORT']}/health
    timeout_ms: 300
    fail_open: false
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
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        },
        ensure_ascii=False,
    ),
    encoding="utf-8",
)
root.joinpath("mode.txt").write_text("block\n", encoding="utf-8")
PY

: > "$ROOT/audit.log"
: > "$ROOT/review.log"
: > "$ROOT/opa-inputs.jsonl"

cat > "$ROOT/upstream_sse.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
OUT = ROOT / "upstream-request.json"
BODY = 'data: {"choices":[{"delta":{"content":"普通响应内容"}}]}\n\ndata: [DONE]\n'.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {"raw_body": raw.decode("utf-8", errors="replace")}
        OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", int(os.environ["UPSTREAM_PORT"])), Handler).serve_forever()
PY

cat > "$ROOT/opa_response_only.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
MODE_FILE = ROOT / "mode.txt"
AUDIT_FILE = ROOT / "opa-inputs.jsonl"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        with AUDIT_FILE.open("ab") as handle:
            handle.write(raw + b"\n")
        data = json.loads(raw or b"{}")
        direction = data.get("input", {}).get("direction")
        mode = MODE_FILE.read_text(encoding="utf-8").strip() if MODE_FILE.exists() else "review"
        result = None
        if direction == "response":
            if mode == "review":
                result = {"action": "review", "reason": "response requires approval"}
            elif mode == "block":
                result = {"action": "block", "reason": "stream policy denied"}
        payload = json.dumps({"result": result}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", int(os.environ["OPA_PORT"])), Handler).serve_forever()
PY

python3 "$ROOT/upstream_sse.py" > "$ROOT/upstream.log" 2>&1 &
upstream_pid=$!

python3 "$ROOT/opa_response_only.py" > "$ROOT/opa.log" 2>&1 &
opa_pid=$!

for _ in $(seq 1 80); do
  curl -fsS "http://127.0.0.1:${OPA_PORT}/health" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${OPA_PORT}/health" >/dev/null

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

curl -fsS -N -D "$ROOT/response-headers.txt" \
  -o "$ROOT/response-body.txt" \
  -H 'Authorization: Bearer admin-secret' \
  -H 'Content-Type: application/json' \
  -H 'Accept: text/event-stream' \
  --data-binary @"$ROOT/request.json" \
  "$GATEWAY_URL/v1/chat/completions" >/dev/null

for _ in $(seq 1 40); do
  if grep -q '"direction":"response"' "$ROOT/audit.log" 2>/dev/null \
    && grep -q '"direction":"response"' "$ROOT/opa-inputs.jsonl" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
body = root.joinpath("response-body.txt").read_text(encoding="utf-8")
headers = root.joinpath("response-headers.txt").read_text(encoding="utf-8").lower()
audit_records = [
    json.loads(line)
    for line in root.joinpath("audit.log").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
opa_inputs = [
    json.loads(line)
    for line in root.joinpath("opa-inputs.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
upstream_request = json.loads(
    root.joinpath("upstream-request.json").read_text(encoding="utf-8")
)

assert 'data: {"error":"response redacted by gateway"}' in body, body
assert "普通响应内容" not in body, body
assert "data: [DONE]" in body, body

assert "http/1.1 200 ok" in headers, headers
assert "content-type: text/event-stream" in headers, headers
assert "x-privacy-gateway-action: stream" in headers, headers
assert "content-length:" not in headers, headers

assert upstream_request["stream"] is True
assert upstream_request["messages"][0]["content"] == "hi"

response_record = next(
    record for record in audit_records if record.get("direction") == "response"
)
assert response_record["path"] == "/v1/chat/completions"
assert response_record["decision"] == "redact"
assert response_record["policy_source"] == "opa"
assert response_record["decision_reason"] == "stream policy denied"
assert response_record["status_code"] == 200

assert any(
    item.get("input", {}).get("direction") == "request" for item in opa_inputs
), "missing request-side OPA input"
response_input = next(
    item for item in opa_inputs if item.get("input", {}).get("direction") == "response"
)
assert response_input["input"]["path"] == "/v1/chat/completions"
assert response_input["input"]["current_decision"] == "allow"

print("smoke_sse_ok")
print("sse sentinel redacted before client")
print("opa response decision and audit evidence captured")
PY
