#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-.tmp-smoke/live-ooxml}
GATEWAY_PORT=${GATEWAY_PORT:-18096}
UPSTREAM_PORT=${UPSTREAM_PORT:-19116}
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
export ROOT GATEWAY_PORT UPSTREAM_PORT

mkdir -p "$ROOT"
rm -f \
  "$ROOT"/config.yaml \
  "$ROOT"/gateway.log \
  "$ROOT"/upstream.log \
  "$ROOT"/upstream-request.bin \
  "$ROOT"/upstream-meta.json \
  "$ROOT"/response-body-*.json \
  "$ROOT"/response-headers-*.txt \
  "$ROOT"/forwarded-*.zip \
  "$ROOT"/forwarded-*.xml \
  "$ROOT"/audit.log \
  "$ROOT"/review.log \
  "$ROOT"/secret.docx \
  "$ROOT"/secret.xlsx \
  "$ROOT"/secret.pptx

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
    - application/vnd.openxmlformats-officedocument.wordprocessingml.document
    - application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
    - application/vnd.openxmlformats-officedocument.presentationml.presentation
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

: > "$ROOT/audit.log"
: > "$ROOT/review.log"

cat > "$ROOT/upstream_capture.py" <<'PY'
import json
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'upstream-request.bin'
META = ROOT / 'upstream-meta.json'

def parse_parts(body: bytes, content_type: str):
    message = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: ' + content_type.encode('utf-8') + b'\r\nMIME-Version: 1.0\r\n\r\n' + body
    )
    if not message.is_multipart():
        raise ValueError('request body is not multipart')
    for part in message.iter_parts():
        filename = part.get_filename() or 'upload.bin'
        media_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload is not None and part.get_filename():
            return filename, media_type, payload
    raise ValueError('no attachment part found')

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', '0'))
        content_type = self.headers.get('content-type', '')
        body = self.rfile.read(length)
        OUT.write_bytes(body)
        filename, media_type, payload = parse_parts(body, content_type)
        ROOT.joinpath(f'forwarded-{filename}').write_bytes(payload)
        META.write_text(json.dumps({
            'path': self.path,
            'content_type': content_type,
            'content_length': length,
            'filename': filename,
            'media_type': media_type,
            'payload_bytes': len(payload),
        }, indent=2), encoding='utf-8')
        raw = b'{"ok":true}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        return

HTTPServer(('127.0.0.1', int(__import__('os').environ['UPSTREAM_PORT'])), Handler).serve_forever()
PY

cat > "$ROOT/make_ooxml.py" <<'PY'
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile

ROOT = Path(__file__).resolve().parent
fixtures = {
    'secret.docx': [('word/document.xml', '<w:document xmlns:w="urn:x"><w:body><w:p><w:r><w:t>邮箱 admin@example.com</w:t></w:r></w:p></w:body></w:document>')],
    'secret.xlsx': [('xl/sharedStrings.xml', '<sst xmlns="urn:x"><si><t>邮箱 admin@example.com</t></si></sst>')],
    'secret.pptx': [('ppt/slides/slide1.xml', '<p:sld xmlns:p="urn:x"><p:cSld><p:spTree><p:sp><p:txBody><a:p xmlns:a="urn:y"><a:r><a:t>邮箱 admin@example.com</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>')],
}
for name, entries in fixtures.items():
    with ZipFile(ROOT / name, 'w', compression=ZIP_STORED) as z:
        z.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types></Types>')
        for path, xml in entries:
            z.writestr(path, xml)
PY

python3 "$ROOT/make_ooxml.py"
python3 "$ROOT/upstream_capture.py" > "$ROOT/upstream.log" 2>&1 &
upstream_pid=$!

env OPENAI_API_KEY=dummy-upstream-key \
  CONTEXT_GURD_TOKENIZATION_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  RUST_LOG=info \
  target/debug/context-gurd --config "$ROOT/config.yaml" > "$ROOT/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 80); do
  curl -fsS "$GATEWAY_URL/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "$GATEWAY_URL/healthz" >/dev/null

for file in secret.docx secret.xlsx secret.pptx; do
  base="${file%.*}"
  curl -sS -D "$ROOT/response-headers-${base}.txt" \
    -o "$ROOT/response-body-${base}.json" \
    -H "Authorization: Bearer demo-secret" \
    -F "file=@$ROOT/$file" \
    "$GATEWAY_URL/v1/chat/completions" >/dev/null
  sleep 0.2
done

ROOT="$ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path
from zipfile import ZipFile

root = Path(os.environ['ROOT'])
cases = [
    ('secret.docx', 'forwarded-secret.docx', 'word/document.xml'),
    ('secret.xlsx', 'forwarded-secret.xlsx', 'xl/sharedStrings.xml'),
    ('secret.pptx', 'forwarded-secret.pptx', 'ppt/slides/slide1.xml'),
]
for original_name, forwarded_name, entry_name in cases:
    forwarded = root / forwarded_name
    assert forwarded.exists(), f'missing {forwarded_name}'
    with ZipFile(forwarded) as z:
        xml = z.read(entry_name).decode('utf-8')
    (root / f'{forwarded_name}.xml').write_text(xml, encoding='utf-8')
    assert 'a***@example.com' in xml, f'masked email missing in {entry_name}'
    assert 'admin@example.com' not in xml, f'raw email leaked in {entry_name}'

audit = root.joinpath('audit.log').read_text(encoding='utf-8')
assert '/attachments/file/word/document.xml#text/0' in audit
assert '/attachments/file/xl/sharedStrings.xml#text/0' in audit
assert '/attachments/file/ppt/slides/slide1.xml#text/0' in audit
print('smoke_ooxml_ok')
print('docx/xlsx/pptx rewritten before upstream')
PY
