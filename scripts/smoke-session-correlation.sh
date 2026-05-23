#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-session-correlation}
GATEWAY_PORT=${GATEWAY_PORT:-18093}
UPSTREAM_PORT=${UPSTREAM_PORT:-19111}
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
  "$ROOT"/review-list.json \
  "$ROOT"/audit-list.json \
  "$ROOT"/resolve.json \
  "$ROOT"/resolve-body.json \
  "$ROOT"/request-email.json \
  "$ROOT"/request-phone.json \
  "$ROOT"/response-email-body.json \
  "$ROOT"/response-email-headers.txt \
  "$ROOT"/response-email-status.txt \
  "$ROOT"/response-review-body.json \
  "$ROOT"/response-review-headers.txt \
  "$ROOT"/response-review-status.txt \
  "$ROOT"/replay-body.json \
  "$ROOT"/replay-headers.txt \
  "$ROOT"/replay-status.txt \
  "$ROOT"/upstream-count.txt \
  "$ROOT"/upstream-request-*.json \
  "$ROOT"/report.txt \
  "$ROOT"/upstream_capture.py
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
import hashlib
import os
from pathlib import Path

root = Path(os.environ["ROOT"]).resolve()
root.mkdir(parents=True, exist_ok=True)

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

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
      secret_sha256: {sha256('demo-secret')}
      allowed_labels: []
    - name: privileged-analyst
      tenant_id: security
      role: employee
      clearance: restricted
      secret_sha256: {sha256('analyst-secret')}
      allowed_labels:
        - email
        - phone
    - name: security-admin
      tenant_id: secops
      role: admin
      clearance: restricted
      secret_sha256: {sha256('admin-secret')}
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
      min_clearance: restricted
      masking: partial_phone
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
  enabled: true
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
PY

python3 - <<'PY' > "$ROOT/upstream.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"]).resolve()
COUNT = ROOT / "upstream-count.txt"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        current = int(COUNT.read_text(encoding="utf-8") or "0") if COUNT.exists() else 0
        current += 1
        COUNT.write_text(str(current), encoding="utf-8")
        ROOT.joinpath(f"upstream-request-{current:02d}.json").write_bytes(body)
        payload = json.dumps({"ok": True, "request_index": current}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        return

HTTPServer(("127.0.0.1", int(os.environ["UPSTREAM_PORT"])), H).serve_forever()
PY
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

cat > "$ROOT/request-email.json" <<'JSON'
{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"邮箱 admin@example.com"}],"stream":false}
JSON

cat > "$ROOT/request-phone.json" <<'JSON'
{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"手机号 13812341234"}],"stream":false}
JSON

curl -sS -D "$ROOT/response-email-headers.txt" \
  -o "$ROOT/response-email-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer analyst-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: sess-corr-1' \
  --data-binary @"$ROOT/request-email.json" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/response-email-status.txt"

curl -sS -D "$ROOT/response-review-headers.txt" \
  -o "$ROOT/response-review-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer analyst-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: sess-corr-1' \
  --data-binary @"$ROOT/request-phone.json" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/response-review-status.txt"

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/reviews?status=pending&limit=20" | tee "$ROOT/review-list.json" >/dev/null

TICKET_ID=$(ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

payload = json.loads(Path(os.environ["ROOT"]).joinpath("review-list.json").read_text(encoding="utf-8"))
records = payload.get("records", [])
assert records, "no review tickets returned"
print(records[0]["id"])
PY
)

TICKET_ID="$TICKET_ID" ROOT="$ROOT" python3 - <<'PY' > /dev/null
import json
import os
from pathlib import Path

Path(os.environ["ROOT"]).joinpath("resolve.json").write_text(
    json.dumps({
        "id": os.environ["TICKET_ID"],
        "approve": True,
        "note": "session correlation smoke approve",
    }),
    encoding="utf-8",
)
PY

curl -fsS -X POST \
  -H 'Authorization: Bearer admin-secret' \
  -H 'Content-Type: application/json' \
  --data-binary @"$ROOT/resolve.json" \
  "$GATEWAY_URL/admin/reviews/resolve" | tee "$ROOT/resolve-body.json" >/dev/null

curl -sS -D "$ROOT/replay-headers.txt" \
  -o "$ROOT/replay-body.json" \
  -w '%{http_code}' \
  -H 'Authorization: Bearer analyst-secret' \
  -H 'Content-Type: application/json' \
  -H 'X-Session-Id: sess-corr-1' \
  -H "X-Review-Ticket-Id: $TICKET_ID" \
  --data-binary @"$ROOT/request-phone.json" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/replay-status.txt"

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/audits?source=both&session_id=sess-corr-1&limit=20" | tee "$ROOT/audit-list.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
email_status = root.joinpath("response-email-status.txt").read_text(encoding="utf-8").strip()
review_status = root.joinpath("response-review-status.txt").read_text(encoding="utf-8").strip()
replay_status = root.joinpath("replay-status.txt").read_text(encoding="utf-8").strip()
email_body = json.loads(root.joinpath("response-email-body.json").read_text(encoding="utf-8"))
review_body = json.loads(root.joinpath("response-review-body.json").read_text(encoding="utf-8"))
replay_body = json.loads(root.joinpath("replay-body.json").read_text(encoding="utf-8"))
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
summary = json.loads(root.joinpath("summary.json").read_text(encoding="utf-8"))
reviews = json.loads(root.joinpath("review-list.json").read_text(encoding="utf-8"))
resolve = json.loads(root.joinpath("resolve-body.json").read_text(encoding="utf-8"))
audits = json.loads(root.joinpath("audit-list.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
audit_text = root.joinpath("audit.log").read_text(encoding="utf-8")
review_text = root.joinpath("review.log").read_text(encoding="utf-8")

count_file = root.joinpath("upstream-count.txt")
upstream_count = int(count_file.read_text(encoding="utf-8") or "0") if count_file.exists() else 0
upstream_1 = json.loads(root.joinpath("upstream-request-01.json").read_text(encoding="utf-8"))
upstream_2 = json.loads(root.joinpath("upstream-request-02.json").read_text(encoding="utf-8"))

assert email_status == "200", email_status
assert review_status == "409", review_status
assert replay_status == "200", replay_status
assert email_body["ok"] is True, email_body
assert review_body["error"]["code"] == "review_required", review_body
assert review_body["review"]["post_approval_action"] == "allow", review_body
assert replay_body["ok"] is True, replay_body

assert upstream_count == 2, upstream_count
assert "admin@example.com" in upstream_1["messages"][0]["content"], upstream_1
assert "13812341234" in upstream_2["messages"][0]["content"], upstream_2

assert status["status"] == "ok", status
assert status["sessions"] >= 1, status
assert status["review_queue"]["pending"] == 0, status
assert summary["status"] == "ok", summary
assert summary["session"]["enabled"] is True, summary
assert summary["session"]["correlation_threshold"] == 2, summary

assert reviews["count"] >= 1, reviews
record = reviews["records"][0]
assert record["session_id"] == "sess-corr-1", record
assert record["session_escalated"] is True, record
assert record["post_approval_action"] == "allow", record
assert resolve["status"] == "ok", resolve
assert resolve["record"]["status"] == "approved", resolve

assert audits["count"] >= 3, audits
assert any(
    item["decision"] == "review" and item["session_escalated"] is True and item["policy_source"] == "builtin"
    for item in audits["records"]
), audits
assert any(
    item["decision"] == "allow" and item["policy_source"] == "review_override_approved"
    for item in audits["records"]
), audits

assert '"session_escalated":true' in audit_text.replace(" ", ""), audit_text
assert "admin@example.com" not in audit_text, audit_text
assert "13812341234" not in audit_text, audit_text
assert '"status":"approved"' in review_text, review_text

assert status["observability"]["metrics_summary"]["counters"]["review_events_total"]["created"] == 1, status
assert status["observability"]["metrics_summary"]["counters"]["review_events_total"]["approved"] == 1, status
assert status["observability"]["metrics_summary"]["counters"]["review_events_total"]["override_approved"] == 1, status
assert status["observability"]["metrics_summary"]["gauges"]["active_sessions"] >= 1, status
assert status["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]["review"]["builtin"] == 1, status
assert status["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]["allow"]["review_override_approved"] == 1, status

assert 'gateway_review_events_total{event="created"} 1' in metrics, metrics
assert 'gateway_review_events_total{event="approved"} 1' in metrics, metrics
assert 'gateway_review_events_total{event="override_approved"} 1' in metrics, metrics
assert 'gateway_active_sessions 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="review",direction="request",source="builtin"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="allow",direction="request",source="review_override_approved"} 1' in metrics, metrics

print("smoke_session_correlation_ok")
print("multi-turn session correlation escalated the second sensitive label into admin review")
print("approved replay forwarded exactly once after review_override_approved")
print("audit and metrics captured session_escalated without leaking raw email or phone")
PY

ROOT="$ROOT" python3 - <<'PY' > "$ROOT/report.txt"
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
reviews = json.loads(root.joinpath("review-list.json").read_text(encoding="utf-8"))

print("status=ok")
print(f"pending_reviews_before_resolve={reviews['count']}")
print(f"sessions={status['sessions']}")
print(
    "request_review_source="
    + str(status["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]["review"]["builtin"])
)
print(
    "override_approved="
    + str(status["observability"]["metrics_summary"]["counters"]["review_events_total"]["override_approved"])
)
PY

cat "$ROOT/report.txt"
