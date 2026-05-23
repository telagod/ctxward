#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-builtin-regex}
GATEWAY_PORT=${GATEWAY_PORT:-18106}
UPSTREAM_PORT=${UPSTREAM_PORT:-19126}
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
  "$ROOT"/request-*.json \
  "$ROOT"/response-*.json \
  "$ROOT"/headers-*.txt \
  "$ROOT"/status-*.txt \
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
config = Path("config/example.yaml").read_text(encoding="utf-8")
config = config.replace("bind: 127.0.0.1:8080", f"bind: 127.0.0.1:{os.environ['GATEWAY_PORT']}")
config = config.replace("base_url: https://api.openai.com/", f"base_url: http://127.0.0.1:{os.environ['UPSTREAM_PORT']}/")
config = config.replace("jsonl_path: ./review.log", f"jsonl_path: {root / 'review.log'}")
config = config.replace("jsonl_path: ./audit.log", f"jsonl_path: {root / 'audit.log'}")
config = config.replace("./.tmp-smoke/bench-matrix/summary.json", str(root / "bench-summary.json"))
config = config.replace("./.tmp-smoke/bench-matrix/baseline.json", str(root / "baseline.json"))
config = config.replace("./.tmp-smoke/bench-matrix/gate-report.json", str(root / "gate-report.json"))
root.joinpath("config.yaml").write_text(config, encoding="utf-8")

requests = {
    "ip": '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"服务器地址 10.20.30.40"}],"stream":false}',
    "mac": '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"网卡地址 00:1A:2B:3C:4D:5E"}],"stream":false}',
    "vin": '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"车辆 VIN 1HGCM82633A004352"}],"stream":false}',
    "imei": '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"设备 IMEI 490154203237518"}],"stream":false}',
    "bank": '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"卡号 6222021234567890"}],"stream":false}',
}
for name, body in requests.items():
    root.joinpath(f"request-{name}.json").write_text(body, encoding="utf-8")
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
        payload = json.dumps({"ok": True, "request_index": current}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

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

for case_name in ip mac vin imei bank; do
  curl -sS -D "$ROOT/headers-${case_name}.txt" \
    -o "$ROOT/response-${case_name}.json" \
    -w '%{http_code}' \
    -H 'Authorization: Bearer demo-secret' \
    -H 'Content-Type: application/json' \
    --data-binary @"$ROOT/request-${case_name}.json" \
    "$GATEWAY_URL/v1/chat/completions" > "$ROOT/status-${case_name}.txt"
done

curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/config-summary" | tee "$ROOT/summary.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null
curl -fsS -H 'Authorization: Bearer admin-secret' "$GATEWAY_URL/admin/audits?source=both&direction=request&limit=20" | tee "$ROOT/audit-list.json" >/dev/null

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
summary = json.loads(root.joinpath("summary.json").read_text(encoding="utf-8"))
audits = json.loads(root.joinpath("audit-list.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
audit_text = root.joinpath("audit.log").read_text(encoding="utf-8")
review_text = root.joinpath("review.log").read_text(encoding="utf-8")

def read_status(name: str) -> str:
    return root.joinpath(f"status-{name}.txt").read_text(encoding="utf-8").strip()

assert read_status("ip") == "200"
assert read_status("mac") == "200"
assert read_status("vin") == "200"
assert read_status("imei") == "403"
assert read_status("bank") == "403"

imei_body = json.loads(root.joinpath("response-imei.json").read_text(encoding="utf-8"))
bank_body = json.loads(root.joinpath("response-bank.json").read_text(encoding="utf-8"))
assert imei_body["error"]["code"] == "blocked_sensitive_payload", imei_body
assert bank_body["error"]["code"] == "blocked_sensitive_payload", bank_body

count_file = root.joinpath("upstream-count.txt")
upstream_count = int(count_file.read_text(encoding="utf-8") or "0") if count_file.exists() else 0
assert upstream_count == 3, upstream_count

forwarded = {
    "ip": json.loads(root.joinpath("upstream-request-01.json").read_text(encoding="utf-8")),
    "mac": json.loads(root.joinpath("upstream-request-02.json").read_text(encoding="utf-8")),
    "vin": json.loads(root.joinpath("upstream-request-03.json").read_text(encoding="utf-8")),
}

ip_content = forwarded["ip"]["messages"][0]["content"]
mac_content = forwarded["mac"]["messages"][0]["content"]
vin_content = forwarded["vin"]["messages"][0]["content"]

assert "10.20.30.40" not in ip_content, ip_content
assert "[IP_ADDRESS]" in ip_content, ip_content
assert "00:1A:2B:3C:4D:5E" not in mac_content, mac_content
assert "[MAC_ADDRESS]" in mac_content, mac_content
assert "1HGCM82633A004352" not in vin_content, vin_content
assert "[VIN]" in vin_content, vin_content

assert status["status"] == "ok", status
assert summary["status"] == "ok", summary
assert summary["detection"]["regex_rule_count"] == 10, summary
rule_names = {rule["name"] for rule in summary["detection"]["rules"]}
for expected in ["ip_address", "mac_address", "imei", "vin", "bank_card"]:
    assert expected in rule_names, rule_names

assert audits["count"] >= 5, audits
records = audits["records"]
assert any("ip_address" in record["matched_labels"] and record["decision"] == "redact" for record in records), records
assert any("mac_address" in record["matched_labels"] and record["decision"] == "redact" for record in records), records
assert any("vin" in record["matched_labels"] and record["decision"] == "redact" for record in records), records
assert any("imei" in record["matched_labels"] and record["decision"] == "block" for record in records), records
assert any("bank_card" in record["matched_labels"] and record["decision"] == "block" for record in records), records

for secret in [
    "10.20.30.40",
    "00:1A:2B:3C:4D:5E",
    "1HGCM82633A004352",
    "490154203237518",
    "6222021234567890",
]:
    assert secret not in audit_text, secret

assert review_text.strip() == "", review_text

request_counters = status["observability"]["metrics_summary"]["counters"]["policy_decisions_total"]["request"]
assert request_counters["redact"]["builtin"] == 3, request_counters
assert request_counters["block"]["builtin"] == 2, request_counters

for metric in [
    'gateway_detections_total{direction="request",label="ip_address"} 1',
    'gateway_detections_total{direction="request",label="mac_address"} 1',
    'gateway_detections_total{direction="request",label="vin"} 1',
    'gateway_detections_total{direction="request",label="imei"} 1',
    'gateway_detections_total{direction="request",label="bank_card"} 1',
]:
    assert metric in metrics, metric

print("smoke_builtin_regex_ok")
print("extended builtin regex matrix redacted lower-risk literals and blocked higher-risk identifiers")
print("example config summary exposed all builtin rule categories without leaking raw values")
print("audit and metrics recorded builtin decisions for ip/mac/vin/imei/bank_card")
PY
