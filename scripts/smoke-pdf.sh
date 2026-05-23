#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-pdf}
GATEWAY_PORT=${GATEWAY_PORT:-18089}
UPSTREAM_PORT=${UPSTREAM_PORT:-19108}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT

if ! command -v pdftotext >/dev/null 2>&1; then
  echo "pdftotext is required for scripts/smoke-pdf.sh" >&2
  exit 1
fi

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/readyz.json \
  "$ROOT"/status.json \
  "$ROOT"/metrics.txt \
  "$ROOT"/response-body.json \
  "$ROOT"/response-headers.txt \
  "$ROOT"/request-status.txt \
  "$ROOT"/secret.pdf \
  "$ROOT"/original-text.txt \
  "$ROOT"/forwarded.pdf \
  "$ROOT"/forwarded-text.txt \
  "$ROOT"/upstream-request.bin \
  "$ROOT"/upstream-meta.json \
  "$ROOT"/upstream-error.txt \
  "$ROOT"/audit-tail.txt \
  "$ROOT"/sha256.txt \
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
  enabled: true
  max_bytes: 5242880
  max_text_chars: 32768
  allowed_media_types:
    - application/pdf
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


def build_pdf(text: str) -> bytes:
    stream = f"BT\n/F1 12 Tf\n72 720 Td\n({text}) Tj\nET\n".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n%bendstream" % (len(stream), stream),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{index} 0 obj\n".encode("ascii"))
        out.extend(obj)
        out.extend(b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(out)


root.joinpath("secret.pdf").write_bytes(build_pdf("contact admin@example.com"))
PY

: > "$ROOT/audit.log"
: > "$ROOT/review.log"

cat > "$ROOT/upstream_capture.py" <<'PY'
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path

ROOT = Path(os.environ["ROOT"]).resolve()
OUT = ROOT / "upstream-request.bin"
META = ROOT / "upstream-meta.json"
FORWARDED = ROOT / "forwarded.pdf"
ERROR = ROOT / "upstream-error.txt"


def extract_pdf(body: bytes, content_type: str) -> tuple[str, bytes]:
    message = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + content_type.encode("utf-8") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    if not message.is_multipart():
        raise ValueError("request body is not multipart")

    for part in message.iter_parts():
        filename = part.get_filename() or "upload.pdf"
        media_type = part.get_content_type()
        if media_type == "application/pdf" or filename.lower().endswith(".pdf"):
            payload = part.get_payload(decode=True)
            if payload is None:
                raise ValueError("pdf part payload decode failed")
            return filename, payload

    raise ValueError("no pdf attachment found in multipart body")


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
        content_type = self.headers.get("content-type", "")
        body = self.rfile.read(length)
        OUT.write_bytes(body)

        meta = {
            "path": self.path,
            "content_type": content_type,
            "content_length": length,
            "extract_status": "error",
        }
        response_payload = b'{"ok":true,"pdf_extracted":false}'
        try:
            filename, pdf_bytes = extract_pdf(body, content_type)
            FORWARDED.write_bytes(pdf_bytes)
            if ERROR.exists():
                ERROR.unlink()
            meta.update(
                {
                    "extract_status": "ok",
                    "pdf_filename": filename,
                    "pdf_bytes": len(pdf_bytes),
                }
            )
            response_payload = b'{"ok":true,"pdf_extracted":true}'
        except Exception as exc:  # noqa: BLE001
            ERROR.write_text(str(exc), encoding="utf-8")
            meta["error"] = str(exc)

        META.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_payload)))
        self.end_headers()
        self.wfile.write(response_payload)

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

env OPENAI_API_KEY=dummy-upstream-key \
  RUST_LOG=info \
  target/debug/context-gurd --config "$ROOT/config.yaml" > "$ROOT/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 80); do
  curl -fsS "$GATEWAY_URL/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "$GATEWAY_URL/healthz" >/dev/null

pdftotext "$ROOT/secret.pdf" - | tee "$ROOT/original-text.txt" >/dev/null
curl -sS -D "$ROOT/response-headers.txt" \
  -o "$ROOT/response-body.json" \
  -w '%{http_code}' \
  -H "Authorization: Bearer demo-secret" \
  -F "file=@$ROOT/secret.pdf;type=application/pdf" \
  "$GATEWAY_URL/v1/chat/completions" > "$ROOT/request-status.txt"

for _ in $(seq 1 40); do
  [[ -s "$ROOT/forwarded.pdf" ]] && break
  sleep 0.1
done

curl -fsS "$GATEWAY_URL/readyz" | tee "$ROOT/readyz.json" >/dev/null
curl -fsS -H "Authorization: Bearer admin-secret" "$GATEWAY_URL/admin/status" | tee "$ROOT/status.json" >/dev/null
curl -fsS "$GATEWAY_URL/metrics" | tee "$ROOT/metrics.txt" >/dev/null

if [[ ! -s "$ROOT/forwarded.pdf" ]]; then
  echo "forwarded.pdf missing" >&2
  [[ -f "$ROOT/upstream-error.txt" ]] && cat "$ROOT/upstream-error.txt" >&2
  exit 1
fi

pdftotext "$ROOT/forwarded.pdf" - | tee "$ROOT/forwarded-text.txt" >/dev/null
sha256sum "$ROOT/secret.pdf" "$ROOT/forwarded.pdf" > "$ROOT/sha256.txt"
tail -n 5 "$ROOT/audit.log" > "$ROOT/audit-tail.txt"

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["ROOT"])
request_status = root.joinpath("request-status.txt").read_text(encoding="utf-8").strip()
response_body = json.loads(root.joinpath("response-body.json").read_text(encoding="utf-8"))
readyz = json.loads(root.joinpath("readyz.json").read_text(encoding="utf-8"))
status = json.loads(root.joinpath("status.json").read_text(encoding="utf-8"))
metrics = root.joinpath("metrics.txt").read_text(encoding="utf-8")
meta = json.loads(root.joinpath("upstream-meta.json").read_text(encoding="utf-8"))
audit_text = root.joinpath("audit.log").read_text(encoding="utf-8")
original_text = root.joinpath("original-text.txt").read_text(encoding="utf-8")
forwarded_text = root.joinpath("forwarded-text.txt").read_text(encoding="utf-8")
forwarded_bytes = root.joinpath("forwarded.pdf").read_bytes()
review_text = root.joinpath("review.log").read_text(encoding="utf-8")

records = [
    json.loads(line)
    for line in audit_text.splitlines()
    if line.strip()
]
request_record = next(record for record in records if record.get("direction") == "request")
response_record = next(record for record in records if record.get("direction") == "response")

assert request_status == "200", request_status
assert response_body["ok"] is True, response_body
assert response_body["pdf_extracted"] is True, response_body

assert readyz["ready"] is True, readyz
assert status["features"]["attachment_scanning"] is True, status
assert status["dependencies"]["opa"]["configured"] is False, status
assert status["dependencies"]["presidio"]["configured"] is False, status

assert meta["extract_status"] == "ok", meta
assert meta["pdf_filename"] == "secret.pdf", meta
assert meta["path"] == "/v1/chat/completions", meta

assert "admin@example.com" in original_text, original_text
assert "a***@example.com" in forwarded_text, forwarded_text
assert "admin@example.com" not in forwarded_text, forwarded_text
assert b"admin@example.com" not in forwarded_bytes, "raw email leaked in forwarded pdf bytes"
assert b"a***@example.com" in forwarded_bytes, "masked email missing in forwarded pdf bytes"

assert request_record["decision"] == "redact", request_record
assert request_record["policy_source"] == "builtin", request_record
assert request_record["matched_labels"] == ["email"], request_record
assert request_record["findings"][0]["pointer"] == "/attachments/file/page/1", request_record
assert response_record["decision"] == "allow", response_record
assert response_record["status_code"] == 200, response_record
assert "admin@example.com" not in audit_text, audit_text
assert review_text.strip() == "", review_text

assert 'gateway_detections_total{direction="request",label="email"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="redact",direction="request",source="builtin"} 1' in metrics, metrics
assert 'gateway_policy_decisions_total{decision="allow",direction="response",source="builtin"} 1' in metrics, metrics

print("smoke_pdf_ok")
print("pdf multipart attachment was redacted before upstream forwarding")
print("upstream received masked pdf bytes and audit pointer tracked /attachments/file/page/1")
print("readyz status and metrics stayed green without leaking source text")
PY
