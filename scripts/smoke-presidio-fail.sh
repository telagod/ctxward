#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-presidio-fail}
GATEWAY_PORT=${GATEWAY_PORT:-18102}
UPSTREAM_PORT=${UPSTREAM_PORT:-19122}
PRESIDIO_PORT=${PRESIDIO_PORT:-19322}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT PRESIDIO_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/request-allow.json \
  "$ROOT"/request-fail.json \
  "$ROOT"/readyz.json \
  "$ROOT"/status.json \
  "$ROOT"/summary.json \
  "$ROOT"/metrics.txt \
  "$ROOT"/response-fallback-body.json \
  "$ROOT"/response-fallback-headers.txt \
  "$ROOT"/request-fail-body.json \
  "$ROOT"/request-fail-headers.txt \
  "$ROOT"/request-fail-status.txt \
  "$ROOT"/upstream-count.txt \
  "$ROOT"/upstream-request-*.json \
  "$ROOT"/upstream_json.py

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
root.joinpath("request-allow.json").write_text(
    json.dumps({"model": "gpt-4.1-mini"}, ensure_ascii=False),
    encoding="utf-8",
)
root.joinpath("request-fail.json").write_text(
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

cat > "$ROOT/upstream_json.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
COUNT_FILE = ROOT / "upstream-count.txt"


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
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {"raw_body": raw.decode("utf-8", errors="replace")}
        current = int(COUNT_FILE.read_text(encoding="utf-8") or "0") if COUNT_FILE.exists() else 0
        current += 1
        COUNT_FILE.write_text(str(current), encoding="utf-8")
        ROOT.joinpath(f"upstream-request-{current:02d}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        body = json.dumps(
            {
                "ok": True,
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

curl -sS -D "$ROOT/response-fallback-headers.txt" \
  -o "$ROOT/response-fallback-body.json" \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/request-allow.json" \
  "$GATEWAY_URL/v1/chat/completions" >/dev/null

curl -sS -D "$ROOT/request-fail-headers.txt" \
  -o "$ROOT/request-fail-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer demo-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/request-fail.json" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/request-fail-status.txt"

curl -fsS "$GATEWAY_URL/readyz" | tee "$ROOT/readyz.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

for _ in $(seq 1 40); do
  if [[ -s "$ROOT/response-fallback-body.json" ]] \
    && [[ -s "$ROOT/request-fail-body.json" ]] \
    && [[ -s "$ROOT/status.json" ]]; then
    break
  fi
  sleep 0.1
done

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
fallback_body = root.joinpath("response-fallback-body.json").read_text(encoding="utf-8")
fallback_headers = root.joinpath("response-fallback-headers.txt").read_text(encoding="utf-8").lower()
fail_body = json.loads(root.joinpath("request-fail-body.json").read_text(encoding="utf-8"))
fail_headers = root.joinpath("request-fail-headers.txt").read_text(encoding="utf-8").lower()
fail_status = root.joinpath("request-fail-status.txt").read_text(encoding="utf-8").strip()
readyz = json.loads(root.joinpath("readyz.json").read_text(encoding="utf-8"))
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
summary = json.loads(root.joinpath("summary.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
audit_text = root.joinpath("audit.log").read_text(encoding="utf-8")
audit_records = [json.loads(line) for line in audit_text.splitlines() if line.strip()]

count = int(root.joinpath("upstream-count.txt").read_text(encoding="utf-8"))
assert count == 1, count
upstream_request = json.loads(root.joinpath("upstream-request-01.json").read_text(encoding="utf-8"))

assert fallback_body == '{"error":"response redacted by gateway"}', fallback_body
assert "admin@example.com" not in fallback_body, fallback_body
assert "http/1.1 200 ok" in fallback_headers, fallback_headers
assert "content-type: application/json" in fallback_headers, fallback_headers
assert "x-privacy-gateway-action: redact" in fallback_headers, fallback_headers
assert "content-length: 40" in fallback_headers, fallback_headers

assert fail_status == "502", fail_status
assert "http/1.1 502 bad gateway" in fail_headers, fail_headers
assert fail_body["error"]["code"] == "upstream_error", fail_body
assert "presidio request failed" in fail_body["error"]["message"], fail_body
assert "admin@example.com" not in json.dumps(fail_body, ensure_ascii=False), fail_body

assert upstream_request == {"model": "gpt-4.1-mini"}, upstream_request
assert not root.joinpath("upstream-request-02.json").exists()

assert readyz["ready"] is False, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["configured"] is True, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["reachable"] is False, readyz
assert "status_code" not in readyz["runtime"]["dependencies"]["presidio"], readyz

assert status["features"]["presidio"] is True, status
assert status["dependencies"]["presidio"]["configured"] is True, status
assert status["dependencies"]["presidio"]["reachable"] is False, status
assert status["observability"]["runtime_summary"]["dependency_ready"]["presidio"] is False, status

presidio_summary = summary["detection"]["presidio"]
assert presidio_summary["enabled"] is True, presidio_summary
assert presidio_summary["entity_count"] == 1, presidio_summary
assert presidio_summary["entities"][0]["entity_type"] == "EMAIL_ADDRESS", presidio_summary

summary_counters = status["observability"]["metrics_summary"]["counters"]
assert summary_counters["policy_decisions_total"]["request"]["allow"]["builtin"] == 1, summary_counters
assert summary_counters["policy_decisions_total"]["response"]["redact"]["processing_error_fallback"] == 1, summary_counters
assert summary_counters["processing_fallback_total"]["processing_error_fallback"] == 1, summary_counters

assert 'gateway_dependency_configured{dependency="presidio"} 1' in metrics, metrics
assert 'gateway_dependency_ready{dependency="presidio"} 0' in metrics, metrics
assert 'gateway_dependency_status_code{dependency="presidio"} 0' in metrics, metrics
assert 'gateway_processing_fallback_total{kind="processing_error_fallback"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="allow",direction="request",source="builtin"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="redact",direction="response",source="processing_error_fallback"} 1' in metrics, metrics
assert 'gateway_proxy_errors_total{kind="presidio",stage="request_pre_upstream"} 1' in metrics, metrics
assert fail_body["request_id"], fail_body
assert summary_counters["proxy_errors_total"]["request_pre_upstream"]["presidio"] == 1, summary_counters

assert len(audit_records) == 3, audit_records
request_record = next(item for item in audit_records if item["direction"] == "request")
response_record = next(item for item in audit_records if item["direction"] == "response")
hard_fail_record = next(
    item for item in audit_records
    if item["policy_source"] == "request_pre_upstream_error"
)
assert request_record["decision"] == "allow", request_record
assert request_record["policy_source"] == "builtin", request_record
assert response_record["decision"] == "redact", response_record
assert response_record["policy_source"] == "processing_error_fallback", response_record
assert response_record["decision_reason"] == "payload processing failed", response_record
assert hard_fail_record["decision"] == "block", hard_fail_record
assert hard_fail_record["direction"] == "request", hard_fail_record
assert hard_fail_record["status_code"] == 502, hard_fail_record
assert hard_fail_record["matched_labels"] == [], hard_fail_record
assert hard_fail_record["matched_rules"] == [], hard_fail_record
assert hard_fail_record["findings"] == [], hard_fail_record
assert "request_pre_upstream/presidio" in (hard_fail_record["decision_reason"] or ""), hard_fail_record
assert "admin@example.com" not in audit_text

print("smoke_presidio_fail_ok")
print("response path failed safe with generic redacted body")
print("request path hard-failed before upstream when sidecar was unreachable")
print("readyz status metrics and skeleton audit captured dependency degradation")
PY
