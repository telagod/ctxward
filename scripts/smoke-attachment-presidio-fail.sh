#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-attachment-presidio-fail}
GATEWAY_PORT=${GATEWAY_PORT:-18104}
UPSTREAM_PORT=${UPSTREAM_PORT:-19124}
PRESIDIO_PORT=${PRESIDIO_PORT:-19324}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT PRESIDIO_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/admin.html \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/audit-list.json \
  "$ROOT"/attachment.txt \
  "$ROOT"/readyz.json \
  "$ROOT"/status.json \
  "$ROOT"/summary.json \
  "$ROOT"/metrics.txt \
  "$ROOT"/request-fail-body.json \
  "$ROOT"/request-fail-headers.txt \
  "$ROOT"/request-fail-status.txt \
  "$ROOT"/upstream-count.txt \
  "$ROOT"/upstream-request-*.bin \
  "$ROOT"/upstream_capture.py

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
  enabled: true
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
root.joinpath("attachment.txt").write_text("邮箱 admin@example.com\n", encoding="utf-8")
PY

: > "$ROOT/audit.log"
: > "$ROOT/review.log"

cat > "$ROOT/upstream_capture.py" <<'PY'
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
        current = int(COUNT_FILE.read_text(encoding="utf-8") or "0") if COUNT_FILE.exists() else 0
        current += 1
        COUNT_FILE.write_text(str(current), encoding="utf-8")
        ROOT.joinpath(f"upstream-request-{current:02d}.bin").write_bytes(raw)
        body = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", int(os.environ["UPSTREAM_PORT"])), Handler).serve_forever()
PY

python3 "$ROOT/upstream_capture.py" > "$ROOT/upstream.log" 2>&1 &
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

curl -sS -D "$ROOT/request-fail-headers.txt" \
  -o "$ROOT/request-fail-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer demo-secret' \
  -F 'model=gpt-4.1-mini' \
  -F "file=@$ROOT/attachment.txt;type=text/plain" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/request-fail-status.txt"

curl -fsS "$GATEWAY_URL/admin" | tee "$ROOT/admin.html" >/dev/null
curl -fsS "$GATEWAY_URL/readyz" | tee "$ROOT/readyz.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/audits?source=both&direction=request&decision=block&limit=20" | tee "$ROOT/audit-list.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/audits?source=both&policy_source=request_pre_upstream_error&error_stage=request_pre_upstream&error_kind=attachment&limit=20" | tee "$ROOT/audit-hard-fail.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
fail_body = json.loads(root.joinpath("request-fail-body.json").read_text(encoding="utf-8"))
fail_headers = root.joinpath("request-fail-headers.txt").read_text(encoding="utf-8").lower()
fail_status = root.joinpath("request-fail-status.txt").read_text(encoding="utf-8").strip()
readyz = json.loads(root.joinpath("readyz.json").read_text(encoding="utf-8"))
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
summary = json.loads(root.joinpath("summary.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
admin_html = root.joinpath("admin.html").read_text(encoding="utf-8")
audit_text = root.joinpath("audit.log").read_text(encoding="utf-8")
audit_list = json.loads(root.joinpath("audit-list.json").read_text(encoding="utf-8"))
hard_fail_list = json.loads(root.joinpath("audit-hard-fail.json").read_text(encoding="utf-8"))
review_text = root.joinpath("review.log").read_text(encoding="utf-8")

upstream_count = 0
count_file = root.joinpath("upstream-count.txt")
if count_file.exists():
    upstream_count = int(count_file.read_text(encoding="utf-8") or "0")

assert fail_status == "502", fail_status
assert "http/1.1 502 bad gateway" in fail_headers, fail_headers
assert "content-type: application/json" in fail_headers, fail_headers
assert fail_body["error"]["code"] == "upstream_error", fail_body
assert "attachment text analysis failed" in fail_body["error"]["message"], fail_body
assert "presidio request failed" in fail_body["error"]["message"], fail_body
assert "admin@example.com" not in json.dumps(fail_body, ensure_ascii=False), fail_body

assert upstream_count == 0, upstream_count
assert not list(root.glob("upstream-request-*.bin"))

assert readyz["ready"] is False, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["configured"] is True, readyz
assert readyz["runtime"]["dependencies"]["presidio"]["reachable"] is False, readyz
assert "status_code" not in readyz["runtime"]["dependencies"]["presidio"], readyz

assert status["features"]["presidio"] is True, status
assert status["features"]["attachment_scanning"] is True, status
assert status["dependencies"]["presidio"]["configured"] is True, status
assert status["dependencies"]["presidio"]["reachable"] is False, status
assert "status_code" not in status["dependencies"]["presidio"], status
assert status["observability"]["runtime_summary"]["dependency_ready"]["presidio"] is False, status

presidio_summary = summary["detection"]["presidio"]
assert presidio_summary["enabled"] is True, presidio_summary
assert presidio_summary["entity_count"] == 1, presidio_summary
assert presidio_summary["entities"][0]["entity_type"] == "EMAIL_ADDRESS", presidio_summary
assert summary["attachments"]["enabled"] is True, summary
assert summary["attachments"]["allowed_media_types"] == ["text/*"], summary
assert "Proxy hard-fails" in admin_html, admin_html
assert "Pre-upstream failure radar" in admin_html, admin_html
assert "proxyErrorTable" in admin_html, admin_html
assert "Latest hard-fails" in admin_html, admin_html
assert "latestHardFailsList" in admin_html, admin_html
assert "latestHardFailsRefreshBtn" in admin_html, admin_html
assert "data-hard-fail-focus" in admin_html, admin_html
assert "auditPolicySource" in admin_html, admin_html
assert "auditRequestId" in admin_html, admin_html
assert "auditErrorStage" in admin_html, admin_html
assert "auditErrorKind" in admin_html, admin_html

assert 'gateway_dependency_configured{dependency="presidio"} 1' in metrics, metrics
assert 'gateway_dependency_ready{dependency="presidio"} 0' in metrics, metrics
assert 'gateway_dependency_status_code{dependency="presidio"} 0' in metrics, metrics
assert 'gateway_proxy_errors_total{kind="attachment",stage="request_pre_upstream"} 1' in metrics, metrics
assert 'gateway_processing_fallback_total{kind="attachment_review_fallback"}' not in metrics, metrics
assert 'gateway_policy_decisions_total{decision="redact",direction="request",source="builtin"}' not in metrics, metrics
assert fail_body["request_id"], fail_body
assert status["observability"]["metrics_summary"]["counters"]["proxy_errors_total"]["request_pre_upstream"]["attachment"] == 1, status
assert audit_list["count"] >= 1, audit_list
record = audit_list["records"][0]
assert record["policy_source"] == "request_pre_upstream_error", record
assert record["decision"] == "block", record
assert record["direction"] == "request", record
assert record["status_code"] == 502, record
assert record["session_id"] is None, record
assert record["matched_labels"] == [], record
assert record["matched_rules"] == [], record
assert record["findings"] == [], record
assert "request_pre_upstream/attachment" in (record["decision_reason"] or ""), record
assert "presidio request failed" in (record["decision_reason"] or ""), record
assert hard_fail_list["count"] == 1, hard_fail_list
assert hard_fail_list["records"][0]["error_stage"] == "request_pre_upstream", hard_fail_list
assert hard_fail_list["records"][0]["error_kind"] == "attachment", hard_fail_list

assert '"policy_source":"request_pre_upstream_error"' in audit_text, audit_text
assert "admin@example.com" not in audit_text, audit_text
assert review_text.strip() == "", review_text

print("smoke_attachment_presidio_fail_ok")
print("attachment multipart request hard-failed before upstream when presidio was unreachable")
print("readyz status config-summary and metrics exposed dependency degradation")
print("skeleton audit captured request_pre_upstream_error without leaking source text")
PY
