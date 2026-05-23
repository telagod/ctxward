#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import dataclasses
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PDF_SAMPLE_B64 = (
    "JVBERi0xLjUKJbutwN4KMSAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbNSAwIFJdL0NvdW50IDEv"
    "UmVzb3VyY2VzIDMgMCBSL01lZGlhQm94WzAgMCA1OTUgODQyXT4+CmVuZG9iagoyIDAgb2JqCjw8"
    "L1R5cGUvRm9udC9TdWJ0eXBlL1R5cGUxL0Jhc2VGb250L0hlbHZldGljYT4+CmVuZG9iagozIDAg"
    "b2JqCjw8L0ZvbnQ8PC9GMSAyIDAgUj4+Pj4KZW5kb2JqCjQgMCBvYmoKPDwvTGVuZ3RoIDU1Pj5z"
    "dHJlYW0KQlQKL0YxIDEyIFRmCjcyIDcyMCBUZAoo6YKu566xIGFkbWluQGV4YW1wbGUuY29tKSBU"
    "agpFVAplbmRzdHJlYW0gCmVuZG9iago1IDAgb2JqCjw8L1R5cGUvUGFnZS9QYXJlbnQgMSAwIFIv"
    "Q29udGVudHMgNCAwIFI+PgplbmRvYmoKNiAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMSAw"
    "IFI+PgplbmRvYmoKNyAwIG9iago8PC9Sb290IDYgMCBSL1R5cGUvWFJlZi9TaXplIDgvV1sxIDQg"
    "Ml0vSW5kZXhbMSA3XS9MZW5ndGggNDk+PnN0cmVhbQoBAAAADwAAAQAAAGgAAAEAAACnAAABAAAA"
    "zQAAAQAAATQAAAEAAAFuAAABAAABmwAACmVuZHN0cmVhbSAKZW5kb2JqCgpzdGFydHhyZWYKNDEx"
    "CiUlRU9G"
)
TOKENIZATION_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
DEMO_AUTH = "Bearer demo-secret"
ADMIN_AUTH = "Bearer admin-secret"
EMAIL_PATTERN = r"\[EMAIL_TOKEN:CGT1\.[^\]]+\]"


@dataclass(frozen=True)
class Thresholds:
    throughput_rps_min: float
    avg_ms_max: float
    p95_ms_max: float
    payload_request_avg_ms_max: float
    payload_response_avg_ms_max: float
    upstream_avg_ms_max: float


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    description: str
    request_kind: str
    payload_request_kind: str
    default_requests: int
    default_concurrency: int
    thresholds: Thresholds
    tokenization: bool = False
    review: bool = False
    opa: bool = False
    presidio: bool = False
    attachments: bool = False
    email_masking: str | None = "partial_email"


SCENARIOS: dict[str, ScenarioSpec] = {
    "json-redact": ScenarioSpec(
        name="json-redact",
        description="JSON request/response redact hot path",
        request_kind="json",
        payload_request_kind="json",
        default_requests=80,
        default_concurrency=8,
        thresholds=Thresholds(100.0, 40.0, 250.0, 5.0, 5.0, 20.0),
    ),
    "json-tokenize": ScenarioSpec(
        name="json-tokenize",
        description="JSON request tokenization + response redact",
        request_kind="json",
        payload_request_kind="json",
        default_requests=80,
        default_concurrency=8,
        thresholds=Thresholds(90.0, 50.0, 280.0, 8.0, 5.0, 20.0),
        tokenization=True,
        email_masking="tokenize",
    ),
    "json-review-replay": ScenarioSpec(
        name="json-review-replay",
        description="Review create/approve prime + replay override hot path",
        request_kind="json",
        payload_request_kind="json",
        default_requests=60,
        default_concurrency=6,
        thresholds=Thresholds(80.0, 60.0, 320.0, 8.0, 5.0, 20.0),
        review=True,
    ),
    "json-opa": ScenarioSpec(
        name="json-opa",
        description="JSON redact with OPA sidecar decision on request/response",
        request_kind="json",
        payload_request_kind="json",
        default_requests=60,
        default_concurrency=6,
        thresholds=Thresholds(70.0, 70.0, 350.0, 8.0, 5.0, 25.0),
        opa=True,
    ),
    "json-presidio": ScenarioSpec(
        name="json-presidio",
        description="JSON redact driven only by Presidio sidecar detections",
        request_kind="json",
        payload_request_kind="json",
        default_requests=40,
        default_concurrency=4,
        thresholds=Thresholds(45.0, 90.0, 450.0, 20.0, 20.0, 25.0),
        presidio=True,
        email_masking=None,
    ),
    "pdf-redact": ScenarioSpec(
        name="pdf-redact",
        description="Multipart PDF simple-text rewrite + response redact",
        request_kind="pdf",
        payload_request_kind="multipart",
        default_requests=20,
        default_concurrency=2,
        thresholds=Thresholds(10.0, 180.0, 800.0, 80.0, 10.0, 30.0),
        attachments=True,
    ),
}


class ScenarioError(RuntimeError):
    pass


class JsonUpstreamHandler(BaseHTTPRequestHandler):
    scenario: ScenarioSpec
    root: Path

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"ok": True})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        self.root.joinpath("request-upstream.json").write_bytes(body)
        payload = json.loads(body.decode("utf-8"))
        response = {
            "ok": True,
            "echo": payload,
            "model_output": "server contact admin@example.com",
        }
        time.sleep(0.001)
        self._send_json(200, response)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


class PdfUpstreamHandler(BaseHTTPRequestHandler):
    root: Path

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"ok": True})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        content_type = self.headers.get("content-type", "")
        body = self.rfile.read(length)
        self.root.joinpath("upstream-request.bin").write_bytes(body)

        response = {
            "ok": True,
            "pdf_extracted": False,
            "pdf_masked": False,
            "model_output": "server contact admin@example.com",
        }
        meta = {
            "path": self.path,
            "content_type": content_type,
            "content_length": length,
        }
        try:
            filename, pdf_bytes = extract_pdf_part(body, content_type)
            self.root.joinpath("forwarded.pdf").write_bytes(pdf_bytes)
            meta.update(
                {
                    "extract_status": "ok",
                    "pdf_filename": filename,
                    "pdf_bytes": len(pdf_bytes),
                }
            )
            response["pdf_extracted"] = True
            response["pdf_masked"] = (
                b"admin@example.com" not in pdf_bytes
                and b"a***@example.com" in pdf_bytes
            )
        except Exception as exc:  # noqa: BLE001
            meta.update({"extract_status": "error", "error": str(exc)})
        self.root.joinpath("upstream-meta.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )
        time.sleep(0.001)
        self._send_json(200, response)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


class OpaHandler(BaseHTTPRequestHandler):
    root: Path

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"ok": True})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        self.root.joinpath("opa-last-input.json").write_bytes(body)
        self._send_json(
            200,
            {"result": {"action": "allow", "reason": "matrix bench allow"}},
        )

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


class PresidioHandler(BaseHTTPRequestHandler):
    root: Path

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"ok": True})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        self.root.joinpath("presidio-last-input.json").write_bytes(body)
        payload = json.loads(body.decode("utf-8"))
        text = payload.get("text", "")
        findings: list[dict[str, Any]] = []
        needle = "admin@example.com"
        start = text.find(needle)
        if start >= 0:
            findings.append(
                {
                    "start": start,
                    "end": start + len(needle),
                    "score": 0.99,
                    "entity_type": "EMAIL_ADDRESS",
                }
            )
        self._send_json(200, findings)

    def _send_json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


@dataclass
class RunningServer:
    name: str
    server: ThreadingHTTPServer
    thread: threading.Thread

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@dataclass
class ScenarioRuntime:
    root: Path
    gateway_port: int
    upstream_port: int
    opa_port: int
    presidio_port: int
    requests: int
    concurrency: int
    scenario: ScenarioSpec


@dataclass
class ScenarioRunResult:
    report: dict[str, Any]
    report_text: str


class GatewayProcess:
    def __init__(self, runtime: ScenarioRuntime) -> None:
        self.runtime = runtime
        self.log_path = runtime.root / "gateway.log"
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        env = os.environ.copy()
        env.setdefault("OPENAI_API_KEY", "dummy-upstream-key")
        env.setdefault("RUST_LOG", "info")
        env.setdefault("CONTEXT_GURD_TOKENIZATION_KEY", TOKENIZATION_KEY)
        log_file = self.log_path.open("wb")
        self.proc = subprocess.Popen(
            [
                str(PROJECT_ROOT / "target" / "debug" / "context-gurd"),
                "--config",
                str(self.runtime.root / "config.yaml"),
            ],
            cwd=PROJECT_ROOT,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        wait_for_health(self.runtime.gateway_port)

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


@dataclass
class PreparedRequest:
    url: str
    body: bytes
    headers: dict[str, str]
    validate_response: callable


@dataclass
class BenchArtifacts:
    bench_output: dict[str, Any]
    status: dict[str, Any]
    summary: dict[str, Any]
    readyz: dict[str, Any]
    metrics_text: str


class SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_pdf_part(body: bytes, content_type: str) -> tuple[str, bytes]:
    message = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: "
        + content_type.encode("utf-8")
        + b"\r\nMIME-Version: 1.0\r\n\r\n"
        + body
    )
    if not message.is_multipart():
        raise ValueError("request body is not multipart")
    for part in message.iter_parts():
        filename = part.get_filename() or "upload.pdf"
        media_type = part.get_content_type()
        if media_type == "application/pdf" or filename.lower().endswith(".pdf"):
            payload = part.get_payload(decode=True)
            if payload is None:
                raise ValueError("pdf payload decode failed")
            return filename, payload
    raise ValueError("no pdf attachment found in multipart body")


def start_server(handler_cls: type[BaseHTTPRequestHandler], port: int, **attrs: Any) -> RunningServer:
    handler = type(
        f"Bench{handler_cls.__name__}{port}",
        (handler_cls,),
        attrs,
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name=f"{handler.__name__}-thread")
    thread.daemon = True
    thread.start()
    return RunningServer(handler.__name__, server, thread)


def wait_for_health(port: int, path: str = "/healthz", attempts: int = 80) -> None:
    last_error: Exception | None = None
    url = f"http://127.0.0.1:{port}{path}"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(0.25)
    raise ScenarioError(f"health check failed for {url}: {last_error}")


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 20.0,
) -> tuple[int, bytes, dict[str, str]]:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                response.read(),
                dict(response.headers.items()),
            )
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers.items())


def json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    body = None
    final_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    status, raw, response_headers = http_request(
        url,
        method=method,
        headers=final_headers,
        body=body,
        timeout=timeout,
    )
    if not raw:
        data: dict[str, Any] = {}
    else:
        data = json.loads(raw.decode("utf-8"))
    return status, data, response_headers


def sanitize_root(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for path in root.iterdir():
        if path.is_file() or path.is_symlink():
            path.unlink()
        elif path.is_dir():
            for nested in sorted(path.rglob("*"), reverse=True):
                if nested.is_file() or nested.is_symlink():
                    nested.unlink()
                elif nested.is_dir():
                    nested.rmdir()
            path.rmdir()
    root.mkdir(parents=True, exist_ok=True)


def write_base_files(runtime: ScenarioRuntime) -> None:
    root = runtime.root
    root.mkdir(parents=True, exist_ok=True)
    root.joinpath("audit.log").write_text("", encoding="utf-8")
    root.joinpath("review.log").write_text("", encoding="utf-8")
    root.joinpath("config.yaml").write_text(build_config_yaml(runtime), encoding="utf-8")
    if runtime.scenario.request_kind == "json":
        body = build_json_request().encode("utf-8")
        root.joinpath("request.json").write_bytes(body)
    elif runtime.scenario.request_kind == "pdf":
        pdf_bytes = base64.b64decode(PDF_SAMPLE_B64)
        root.joinpath("secret.pdf").write_bytes(pdf_bytes)
        multipart_body, content_type = build_pdf_multipart_request(pdf_bytes)
        root.joinpath("request.bin").write_bytes(multipart_body)
        root.joinpath("request-content-type.txt").write_text(content_type, encoding="utf-8")
    else:
        raise ScenarioError(f"unsupported request kind: {runtime.scenario.request_kind}")


def build_json_request() -> str:
    return json.dumps(
        {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "邮箱 admin@example.com"}],
            "stream": False,
        },
        ensure_ascii=False,
    ) + "\n"


def build_pdf_multipart_request(pdf_bytes: bytes) -> tuple[bytes, str]:
    boundary = "----context-gurd-bench-pdf-boundary"
    body = (
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"secret.pdf\"\r\n"
        "Content-Type: application/pdf\r\n\r\n"
    ).encode("utf-8") + pdf_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, f"multipart/form-data; boundary={boundary}"


def build_config_yaml(runtime: ScenarioRuntime) -> str:
    scenario = runtime.scenario
    presidio_block = presidio_config_block(runtime.presidio_port, scenario.presidio)
    rules_block = detection_rules_block(scenario.email_masking)
    attachments_enabled = "true" if scenario.attachments else "false"
    tokenization_enabled = "true" if scenario.tokenization else "false"
    session_enabled = "true" if scenario.review else "false"
    correlation_threshold = 1 if scenario.review else 2
    opa_enabled = "true" if scenario.opa else "false"
    allowed_media_types = ["application/pdf"] if scenario.attachments else ["text/*"]
    media_yaml = "\n".join([f"    - {item}" for item in allowed_media_types])
    template = """
server:
  bind: 127.0.0.1:{gateway_port}
  request_body_limit_bytes: 1048576
upstream:
  base_url: http://127.0.0.1:{upstream_port}/
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
{presidio_block}{rules_block}policy_backend:
  opa:
    enabled: {opa_enabled}
    url: http://127.0.0.1:{opa_port}/v1/data/llm/privacy/decision
    healthcheck_url: http://127.0.0.1:{opa_port}/health
    timeout_ms: 150
    fail_open: true
tokenization:
  enabled: {tokenization_enabled}
  key_env: CONTEXT_GURD_TOKENIZATION_KEY
  token_prefix: CGT1
session:
  enabled: {session_enabled}
  header_name: x-session-id
  ttl_secs: 1800
  max_entries: 5000
  correlation_threshold: {correlation_threshold}
  trigger_action: review
response_filtering:
  enabled: true
  scan_json: true
  scan_sse: true
attachments:
  enabled: {attachments_enabled}
  max_bytes: 5242880
  max_text_chars: 32768
  allowed_media_types:
{media_yaml}
review:
  capacity: 1000
  preview_chars: 256
  approval_ttl_secs: 900
  jsonl_path: {review_path}
audit:
  jsonl_path: {audit_path}
  emit_stdout: false
  buffer_capacity: 1000
"""
    return template.format_map(
        SafeDict(
            gateway_port=runtime.gateway_port,
            upstream_port=runtime.upstream_port,
            opa_port=runtime.opa_port,
            presidio_block=presidio_block,
            rules_block=rules_block,
            opa_enabled=opa_enabled,
            tokenization_enabled=tokenization_enabled,
            session_enabled=session_enabled,
            correlation_threshold=correlation_threshold,
            attachments_enabled=attachments_enabled,
            media_yaml=media_yaml,
            review_path=runtime.root.joinpath("review.log").resolve(),
            audit_path=runtime.root.joinpath("audit.log").resolve(),
        )
    ).lstrip()


def presidio_config_block(port: int, enabled: bool) -> str:
    if enabled:
        return (
            "  presidio:\n"
            "    enabled: true\n"
            f"    analyzer_url: http://127.0.0.1:{port}/analyze\n"
            f"    healthcheck_url: http://127.0.0.1:{port}/health\n"
            "    timeout_ms: 250\n"
            "    language: en\n"
            "    entities:\n"
            "      - entity_type: EMAIL_ADDRESS\n"
            "        label: email\n"
            "        severity: medium\n"
            "        authorized_action: allow\n"
            "        unauthorized_action: redact\n"
            "        min_clearance: internal\n"
            "        masking: partial_email\n"
            "        min_score: 0.35\n"
        )
    return (
        "  presidio:\n"
        "    enabled: false\n"
        f"    analyzer_url: http://127.0.0.1:{port}/analyze\n"
        f"    healthcheck_url: http://127.0.0.1:{port}/health\n"
        "    timeout_ms: 250\n"
        "    language: en\n"
        "    entities: []\n"
    )


def detection_rules_block(masking: str | None) -> str:
    if masking is None:
        return "  rules: []\n"
    return (
        "  rules:\n"
        "    - name: email\n"
        "      label: email\n"
        "      pattern: '(?i)(?:^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,})(?:$|[^A-Z0-9._%+-])'\n"
        "      severity: medium\n"
        "      authorized_action: allow\n"
        "      unauthorized_action: redact\n"
        "      min_clearance: internal\n"
        f"      masking: {masking}\n"
    )


def build_request(runtime: ScenarioRuntime, ticket_id: str | None = None) -> PreparedRequest:
    root = runtime.root
    url = f"http://127.0.0.1:{runtime.gateway_port}/v1/chat/completions"
    headers = {"Authorization": DEMO_AUTH}
    if runtime.scenario.request_kind == "json":
        body = root.joinpath("request.json").read_bytes()
        headers["Content-Type"] = "application/json"
        if runtime.scenario.review:
            headers["X-Session-Id"] = "bench-review-1"
            if ticket_id:
                headers["X-Review-Ticket-Id"] = ticket_id
        return PreparedRequest(url, body, headers, lambda payload: validate_json_response(runtime.scenario, payload))
    content_type = root.joinpath("request-content-type.txt").read_text(encoding="utf-8").strip()
    body = root.joinpath("request.bin").read_bytes()
    headers["Content-Type"] = content_type
    return PreparedRequest(url, body, headers, validate_pdf_response)


def validate_json_response(scenario: ScenarioSpec, payload: dict[str, Any]) -> None:
    model_output = payload.get("model_output", "")
    content = payload["echo"]["messages"][0]["content"]
    if scenario.tokenization:
        if not re.search(EMAIL_PATTERN, content):
            raise ScenarioError(f"tokenized content missing in upstream echo: {content}")
        if "admin@example.com" in content:
            raise ScenarioError(f"raw email leaked in tokenized upstream echo: {content}")
        if not re.search(EMAIL_PATTERN, model_output):
            raise ScenarioError(f"tokenized response content missing: {model_output}")
        if "admin@example.com" in model_output:
            raise ScenarioError(f"raw email leaked in tokenized response content: {model_output}")
    else:
        if "a***@example.com" not in content or "admin@example.com" in content:
            raise ScenarioError(f"masked request content mismatch: {content}")
        if "a***@example.com" not in model_output or "admin@example.com" in model_output:
            raise ScenarioError(f"masked response content mismatch: {model_output}")


def validate_pdf_response(payload: dict[str, Any]) -> None:
    if payload.get("pdf_extracted") is not True:
        raise ScenarioError(f"pdf extraction failed: {payload}")
    if payload.get("pdf_masked") is not True:
        raise ScenarioError(f"pdf masking failed: {payload}")
    model_output = payload.get("model_output", "")
    if "a***@example.com" not in model_output or "admin@example.com" in model_output:
        raise ScenarioError(f"masked response content mismatch: {model_output}")


def benchmark_requests(runtime: ScenarioRuntime, ticket_id: str | None = None) -> dict[str, Any]:
    prepared = build_request(runtime, ticket_id=ticket_id)
    requests = runtime.requests
    concurrency = runtime.concurrency

    def one(_: int) -> float:
        started = time.perf_counter()
        status, raw, _ = http_request(
            prepared.url,
            method="POST",
            headers=prepared.headers,
            body=prepared.body,
            timeout=20.0,
        )
        elapsed = time.perf_counter() - started
        if status != 200:
            raise ScenarioError(f"unexpected status {status}: {raw.decode('utf-8', 'replace')}")
        payload = json.loads(raw.decode("utf-8"))
        prepared.validate_response(payload)
        return elapsed

    wall_started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        samples = list(pool.map(one, range(requests)))
    wall_seconds = time.perf_counter() - wall_started
    samples_sorted = sorted(samples)

    def pct(p: float) -> float:
        idx = min(len(samples_sorted) - 1, max(0, int((len(samples_sorted) - 1) * p)))
        return samples_sorted[idx]

    return {
        "requests": requests,
        "concurrency": concurrency,
        "wall_seconds": wall_seconds,
        "throughput_rps": requests / wall_seconds,
        "latency_ms": {
            "min": min(samples) * 1000,
            "p50": pct(0.50) * 1000,
            "p95": pct(0.95) * 1000,
            "max": max(samples) * 1000,
            "avg": (sum(samples) / len(samples)) * 1000,
        },
    }


def median_float(values: list[float]) -> float:
    if not values:
        raise ScenarioError("cannot compute median for empty samples")
    return float(statistics.median(values))


def aggregate_scenario_runs(runtime: ScenarioRuntime, runs: list[ScenarioRunResult]) -> ScenarioRunResult:
    if not runs:
        raise ScenarioError(f"no scenario runs recorded for {runtime.scenario.name}")

    reports = [item.report for item in runs]
    sample_runs = [
        {
            "run": f"run-{index:02d}",
            "artifacts_root": report["artifacts_root"],
            "throughput_rps": round(float(report["throughput_rps"]), 2),
            "avg_ms": round(float(report["latency_ms"]["avg"]), 3),
            "p95_ms": round(float(report["latency_ms"]["p95"]), 3),
            "payload_request_avg_ms": round(float(report["payload_request_avg_ms"]), 3),
            "payload_response_avg_ms": round(float(report["payload_response_avg_ms"]), 3),
            "upstream_avg_ms": round(float(report["upstream_avg_ms"]), 3),
            "ok": bool(report.get("ok", False)),
        }
        for index, report in enumerate(reports, start=1)
    ]

    aggregated = {
        "scenario": runtime.scenario.name,
        "description": runtime.scenario.description,
        "generated_at": now_iso(),
        "requests": runtime.requests,
        "concurrency": runtime.concurrency,
        "throughput_rps": round(median_float([float(report["throughput_rps"]) for report in reports]), 2),
        "latency_ms": {
            key: round(
                median_float([float(report["latency_ms"][key]) for report in reports]),
                3,
            )
            for key in ("min", "p50", "p95", "max", "avg")
        },
        "payload_request_avg_ms": round(
            median_float([float(report["payload_request_avg_ms"]) for report in reports]),
            3,
        ),
        "payload_response_avg_ms": round(
            median_float([float(report["payload_response_avg_ms"]) for report in reports]),
            3,
        ),
        "upstream_avg_ms": round(
            median_float([float(report["upstream_avg_ms"]) for report in reports]),
            3,
        ),
        "request_payload_kind": reports[0]["request_payload_kind"],
        "decision_sources": {
            "request": sorted(
                {
                    source
                    for report in reports
                    for source in report["decision_sources"].get("request", [])
                }
            ),
            "response": sorted(
                {
                    source
                    for report in reports
                    for source in report["decision_sources"].get("response", [])
                }
            ),
        },
        "dependency_ready": {
            "opa": all(bool(report["dependency_ready"]["opa"]) for report in reports),
            "presidio": all(bool(report["dependency_ready"]["presidio"]) for report in reports),
        },
        "features": reports[0]["features"],
        "artifacts_root": str(runtime.root),
        "thresholds": reports[0]["thresholds"],
        "ok": all(bool(report.get("ok", False)) for report in reports),
        "aggregation": {
            "method": "median",
            "runs": len(reports),
            "sample_runs": sample_runs,
        },
    }

    aggregation_payload = {
        "scenario": runtime.scenario.name,
        "description": runtime.scenario.description,
        "generated_at": aggregated["generated_at"],
        "method": "median",
        "runs": len(reports),
        "aggregated_report": aggregated,
        "sample_runs": sample_runs,
    }
    runtime.root.joinpath("aggregation.json").write_text(
        json.dumps(aggregation_payload, indent=2),
        encoding="utf-8",
    )
    runtime.root.joinpath("report.json").write_text(
        json.dumps(aggregated, indent=2),
        encoding="utf-8",
    )
    report_text = "\n".join(
        [
            json.dumps(aggregated, indent=2),
            "aggregation_runs:",
            *[
                (
                    f"  - {sample['run']} thr={sample['throughput_rps']:.2f} "
                    f"avg={sample['avg_ms']:.3f} p95={sample['p95_ms']:.3f} "
                    f"root={sample['artifacts_root']}"
                )
                for sample in sample_runs
            ],
            "bench_scenario_ok",
            "",
        ]
    )
    runtime.root.joinpath("report.txt").write_text(report_text, encoding="utf-8")
    return ScenarioRunResult(report=aggregated, report_text=report_text)


def run_scenario_repeated(runtime: ScenarioRuntime, *, runs: int, build: bool) -> ScenarioRunResult:
    if runs <= 1:
        return run_scenario(runtime, build=build)

    sanitize_root(runtime.root)
    runs_root = runtime.root / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    results: list[ScenarioRunResult] = []
    for index in range(1, runs + 1):
        run_runtime = dataclasses.replace(
            runtime,
            root=runs_root / f"run-{index:02d}",
        )
        results.append(run_scenario(run_runtime, build=build if index == 1 else False))
    return aggregate_scenario_runs(runtime, results)


def prime_review(runtime: ScenarioRuntime) -> str:
    prepared = build_request(runtime)
    status, raw, _ = http_request(
        prepared.url,
        method="POST",
        headers=prepared.headers,
        body=prepared.body,
        timeout=20.0,
    )
    if status != 409:
        raise ScenarioError(
            f"review prime expected 409, got {status}: {raw.decode('utf-8', 'replace')}"
        )
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("error", {}).get("code") != "review_required":
        raise ScenarioError(f"unexpected review prime payload: {payload}")
    ticket_id = payload.get("review", {}).get("ticket_id")
    if not ticket_id:
        raise ScenarioError(f"review ticket id missing: {payload}")
    resolve_url = f"http://127.0.0.1:{runtime.gateway_port}/admin/reviews/resolve"
    status, resolve_payload, _ = json_request(
        resolve_url,
        method="POST",
        headers={"Authorization": ADMIN_AUTH},
        payload={
            "id": ticket_id,
            "approve": True,
            "note": "bench-matrix auto approve",
        },
    )
    if status != 200 or resolve_payload.get("status") != "ok":
        raise ScenarioError(f"review resolve failed: {status} {resolve_payload}")
    runtime.root.joinpath("prime-review.json").write_text(
        json.dumps({"prime": payload, "resolve": resolve_payload}, indent=2),
        encoding="utf-8",
    )
    return ticket_id


def collect_artifacts(runtime: ScenarioRuntime, bench_output: dict[str, Any]) -> BenchArtifacts:
    gateway_url = f"http://127.0.0.1:{runtime.gateway_port}"
    metrics_status, metrics_raw, _ = http_request(f"{gateway_url}/metrics")
    if metrics_status != 200:
        raise ScenarioError(f"metrics fetch failed: {metrics_status}")
    metrics_text = metrics_raw.decode("utf-8")
    runtime.root.joinpath("metrics.txt").write_text(metrics_text, encoding="utf-8")

    ready_status, readyz_payload, _ = json_request(f"{gateway_url}/readyz")
    if ready_status != 200:
        raise ScenarioError(f"readyz fetch failed: {ready_status} {readyz_payload}")
    runtime.root.joinpath("readyz.json").write_text(
        json.dumps(readyz_payload, indent=2), encoding="utf-8"
    )

    status_code, status_payload, _ = json_request(
        f"{gateway_url}/admin/status",
        headers={"Authorization": ADMIN_AUTH},
    )
    if status_code != 200:
        raise ScenarioError(f"admin/status failed: {status_code} {status_payload}")
    runtime.root.joinpath("status.json").write_text(
        json.dumps(status_payload, indent=2), encoding="utf-8"
    )

    summary_code, summary_payload, _ = json_request(
        f"{gateway_url}/admin/config-summary",
        headers={"Authorization": ADMIN_AUTH},
    )
    if summary_code != 200:
        raise ScenarioError(f"admin/config-summary failed: {summary_code} {summary_payload}")
    runtime.root.joinpath("summary.json").write_text(
        json.dumps(summary_payload, indent=2), encoding="utf-8"
    )

    runtime.root.joinpath("bench-output.json").write_text(
        json.dumps(bench_output, indent=2), encoding="utf-8"
    )
    return BenchArtifacts(
        bench_output=bench_output,
        status=status_payload,
        summary=summary_payload,
        readyz=readyz_payload,
        metrics_text=metrics_text,
    )


def get_path(payload: dict[str, Any], path: list[str]) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ScenarioError(f"missing path {'/'.join(path)}")
        current = current[key]
    return current


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ScenarioError(message)


def histogram_avg_ms(meta: dict[str, Any]) -> float:
    count = float(meta.get("count", 0) or 0)
    if count <= 0:
        return 0.0
    return (float(meta.get("sum_seconds", 0.0)) / count) * 1000.0


def validate_artifacts(runtime: ScenarioRuntime, artifacts: BenchArtifacts) -> dict[str, Any]:
    bench = artifacts.bench_output
    status = artifacts.status
    summary = artifacts.summary
    metrics = artifacts.metrics_text
    scenario = runtime.scenario
    thresholds = scenario.thresholds
    summary_metrics = status["observability"]["metrics_summary"]
    counters = summary_metrics["counters"]
    latency = summary_metrics["latency"]
    payload_request = latency["payload_processing_duration_seconds"]["request"][scenario.payload_request_kind]
    payload_response = latency["payload_processing_duration_seconds"]["response"]["json"]
    upstream_latency = latency["upstream_duration_seconds"]["/v1/chat/completions"]

    request_payload_expected = runtime.requests + (1 if scenario.review else 0)
    expect(int(bench["requests"]) == runtime.requests, "bench requests mismatch")
    expect(int(payload_request["count"]) == request_payload_expected, "request payload count mismatch")
    expect(int(payload_response["count"]) == runtime.requests, "response payload count mismatch")
    expect(int(upstream_latency["count"]) == runtime.requests, "upstream latency count mismatch")
    expect(bench["latency_ms"]["avg"] < thresholds.avg_ms_max, f"avg latency too high: {bench['latency_ms']['avg']}")
    expect(bench["latency_ms"]["p95"] < thresholds.p95_ms_max, f"p95 latency too high: {bench['latency_ms']['p95']}")
    expect(bench["throughput_rps"] > thresholds.throughput_rps_min, f"throughput too low: {bench['throughput_rps']}")
    expect(histogram_avg_ms(payload_request) < thresholds.payload_request_avg_ms_max, "request payload latency too high")
    expect(histogram_avg_ms(payload_response) < thresholds.payload_response_avg_ms_max, "response payload latency too high")
    expect(histogram_avg_ms(upstream_latency) < thresholds.upstream_avg_ms_max, "upstream latency too high")
    expect("gateway_payload_processing_duration_seconds" in metrics, "payload metric missing")
    expect("gateway_upstream_duration_seconds" in metrics, "upstream metric missing")
    expect(summary["response_filtering"]["enabled"] is True, "response filtering disabled")

    if scenario.tokenization:
        expect(summary["tokenization"]["enabled"] is True, "tokenization runtime not enabled")
        expect(summary["tokenization"]["key_env_present"] is True, "tokenization key missing")
        expect(
            counters["policy_decisions_total"]["request"]["redact"]["builtin"] == runtime.requests,
            "tokenization request decision mismatch",
        )
    elif scenario.review:
        request_decisions = counters["policy_decisions_total"]["request"]
        expect(request_decisions["review"]["builtin"] == 1, "review create count mismatch")
        expect(
            request_decisions["redact"]["review_override_approved"] == runtime.requests,
            "review override count mismatch",
        )
        expect(counters["review_events_total"]["created"] == 1, "review created metric mismatch")
        expect(counters["review_events_total"]["approved"] == 1, "review approved metric mismatch")
        expect(
            counters["review_events_total"]["override_approved"] == runtime.requests,
            "review override approved metric mismatch",
        )
        expect(summary["session"]["enabled"] is True, "session correlation disabled")
    elif scenario.opa:
        expect(summary["policy_backend"]["opa"]["runtime_loaded"] is True, "OPA runtime not loaded")
        expect(status["dependencies"]["opa"]["reachable"] is True, "OPA not reachable")
        expect(
            counters["policy_decisions_total"]["request"]["redact"]["opa"] == runtime.requests,
            "OPA request decision mismatch",
        )
        expect(
            counters["policy_decisions_total"]["response"]["redact"]["opa"] == runtime.requests,
            "OPA response decision mismatch",
        )
    elif scenario.presidio:
        expect(status["dependencies"]["presidio"]["reachable"] is True, "Presidio not reachable")
        expect(summary["detection"]["presidio"]["enabled"] is True, "Presidio not enabled")
        expect(counters["detections_total"]["request"]["email"] == runtime.requests, "Presidio request detections mismatch")
        expect(counters["detections_total"]["response"]["email"] == runtime.requests, "Presidio response detections mismatch")
    elif scenario.attachments:
        expect(summary["attachments"]["enabled"] is True, "attachments not enabled")
        meta_path = runtime.root / "upstream-meta.json"
        expect(meta_path.exists(), "upstream meta missing for pdf scenario")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        expect(meta.get("extract_status") == "ok", f"pdf extract status mismatch: {meta}")
        forwarded = runtime.root.joinpath("forwarded.pdf")
        expect(forwarded.exists(), "forwarded pdf missing")
        pdf_bytes = forwarded.read_bytes()
        expect(b"admin@example.com" not in pdf_bytes, "raw email leaked in forwarded pdf")
        expect(b"a***@example.com" in pdf_bytes, "masked email missing in forwarded pdf")
    else:
        expect(
            counters["policy_decisions_total"]["request"]["redact"]["builtin"] == runtime.requests,
            "request decision mismatch",
        )

    if not scenario.review and not scenario.opa:
        expect(
            counters["policy_decisions_total"]["response"]["redact"]["builtin"] == runtime.requests,
            "response decision mismatch",
        )
    if scenario.review:
        expect(
            counters["policy_decisions_total"]["response"]["redact"]["builtin"] == runtime.requests,
            "review response decision mismatch",
        )
    if scenario.attachments:
        expect(
            counters["policy_decisions_total"]["request"]["redact"]["builtin"] == runtime.requests,
            "pdf request decision mismatch",
        )
        expect(
            counters["policy_decisions_total"]["response"]["redact"]["builtin"] == runtime.requests,
            "pdf response decision mismatch",
        )

    report = {
        "scenario": scenario.name,
        "description": scenario.description,
        "generated_at": now_iso(),
        "requests": runtime.requests,
        "concurrency": runtime.concurrency,
        "throughput_rps": round(float(bench["throughput_rps"]), 2),
        "latency_ms": {key: round(float(value), 3) for key, value in bench["latency_ms"].items()},
        "payload_request_avg_ms": round(histogram_avg_ms(payload_request), 3),
        "payload_response_avg_ms": round(histogram_avg_ms(payload_response), 3),
        "upstream_avg_ms": round(histogram_avg_ms(upstream_latency), 3),
        "request_payload_kind": scenario.payload_request_kind,
        "decision_sources": {
            "request": sorted({
                source
                for sources in (counters["policy_decisions_total"].get("request") or {}).values()
                for source in sources.keys()
            }),
            "response": sorted({
                source
                for sources in (counters["policy_decisions_total"].get("response") or {}).values()
                for source in sources.keys()
            }),
        },
        "dependency_ready": {
            "opa": status["dependencies"]["opa"].get("reachable", False),
            "presidio": status["dependencies"]["presidio"].get("reachable", False),
        },
        "features": status["features"],
        "artifacts_root": str(runtime.root),
        "thresholds": dataclasses.asdict(thresholds),
        "ok": True,
    }
    runtime.root.joinpath("report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_text = json.dumps(report, indent=2) + "\nbench_scenario_ok\n"
    runtime.root.joinpath("report.txt").write_text(report_text, encoding="utf-8")
    return report


def ensure_build(build: bool) -> None:
    if not build:
        return
    subprocess.run(["cargo", "build", "-q"], cwd=PROJECT_ROOT, check=True)


def run_scenario(runtime: ScenarioRuntime, *, build: bool) -> ScenarioRunResult:
    sanitize_root(runtime.root)
    write_base_files(runtime)
    ensure_build(build)

    servers: list[RunningServer] = []
    gateway = GatewayProcess(runtime)
    try:
        if runtime.scenario.request_kind == "pdf":
            servers.append(start_server(PdfUpstreamHandler, runtime.upstream_port, root=runtime.root))
        else:
            servers.append(
                start_server(
                    JsonUpstreamHandler,
                    runtime.upstream_port,
                    root=runtime.root,
                    scenario=runtime.scenario,
                )
            )
        if runtime.scenario.opa:
            servers.append(start_server(OpaHandler, runtime.opa_port, root=runtime.root))
            wait_for_health(runtime.opa_port, "/health")
        if runtime.scenario.presidio:
            servers.append(start_server(PresidioHandler, runtime.presidio_port, root=runtime.root))
            wait_for_health(runtime.presidio_port, "/health")

        gateway.start()
        ticket_id = prime_review(runtime) if runtime.scenario.review else None
        bench_output = benchmark_requests(runtime, ticket_id=ticket_id)
        artifacts = collect_artifacts(runtime, bench_output)
        report = validate_artifacts(runtime, artifacts)
        report_text = runtime.root.joinpath("report.txt").read_text(encoding="utf-8")
        return ScenarioRunResult(report=report, report_text=report_text)
    finally:
        gateway.stop()
        for server in reversed(servers):
            with contextlib.suppress(Exception):
                server.stop()


def matrix_report(root: Path, reports: list[dict[str, Any]], *, runs: int) -> str:
    header = [
        "scenario                requests conc  thr(rps)  avg(ms)  p95(ms)  req(ms)  resp(ms)  up(ms)",
        "----------------------  -------- ----  --------  -------  -------  -------  --------  ------",
    ]
    rows = []
    for item in reports:
        rows.append(
            f"{item['scenario']:<22}  {item['requests']:>8} {item['concurrency']:>4}  "
            f"{item['throughput_rps']:>8.2f}  {item['latency_ms']['avg']:>7.3f}  "
            f"{item['latency_ms']['p95']:>7.3f}  {item['payload_request_avg_ms']:>7.3f}  "
            f"{item['payload_response_avg_ms']:>8.3f}  {item['upstream_avg_ms']:>6.3f}"
        )
    footer = [f"aggregation            median-of-{runs}" if runs > 1 else "aggregation            single-run"]
    return "\n".join(header + rows + footer + ["bench_matrix_ok"])


def command_scenario(args: argparse.Namespace) -> int:
    if args.runs < 1:
        raise ScenarioError("--runs must be >= 1")
    scenario = SCENARIOS[args.scenario]
    runtime = ScenarioRuntime(
        root=Path(args.root),
        gateway_port=args.gateway_port,
        upstream_port=args.upstream_port,
        opa_port=args.opa_port,
        presidio_port=args.presidio_port,
        requests=args.requests or scenario.default_requests,
        concurrency=args.concurrency or scenario.default_concurrency,
        scenario=scenario,
    )
    result = run_scenario_repeated(runtime, runs=args.runs, build=not args.skip_build)
    sys.stdout.write(result.report_text)
    return 0


def command_matrix(args: argparse.Namespace) -> int:
    if args.runs < 1:
        raise ScenarioError("--runs must be >= 1")
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    scenarios = [SCENARIOS[name] for name in args.scenarios]
    ensure_build(True)
    reports: list[dict[str, Any]] = []
    base_gateway = args.gateway_port
    base_upstream = args.upstream_port
    base_opa = args.opa_port
    base_presidio = args.presidio_port
    for index, scenario in enumerate(scenarios):
        runtime = ScenarioRuntime(
            root=root / scenario.name,
            gateway_port=base_gateway + index,
            upstream_port=base_upstream + index,
            opa_port=base_opa + index,
            presidio_port=base_presidio + index,
            requests=scenario.default_requests,
            concurrency=scenario.default_concurrency,
            scenario=scenario,
        )
        result = run_scenario_repeated(runtime, runs=args.runs, build=False)
        reports.append(result.report)
    summary = {
        "generated_at": now_iso(),
        "scenario_count": len(reports),
        "scenarios": reports,
        "aggregation": {
            "method": "median" if args.runs > 1 else "single-run",
            "runs": args.runs,
        },
    }
    summary_json = json.dumps(summary, indent=2)
    root.joinpath("summary.json").write_text(summary_json, encoding="utf-8")
    if not root.joinpath("baseline.json").exists():
        root.joinpath("baseline.json").write_text(summary_json, encoding="utf-8")
    report_text = matrix_report(root, reports, runs=args.runs)
    root.joinpath("report.txt").write_text(report_text + "\n", encoding="utf-8")
    sys.stdout.write(report_text + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="context-gurd benchmark harness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scenario_parser = subparsers.add_parser("scenario", help="run one benchmark scenario")
    scenario_parser.add_argument("--scenario", choices=sorted(SCENARIOS.keys()), required=True)
    scenario_parser.add_argument("--root", required=True)
    scenario_parser.add_argument("--gateway-port", type=int, default=18093)
    scenario_parser.add_argument("--upstream-port", type=int, default=19111)
    scenario_parser.add_argument("--opa-port", type=int, default=18181)
    scenario_parser.add_argument("--presidio-port", type=int, default=19301)
    scenario_parser.add_argument("--requests", type=int)
    scenario_parser.add_argument("--concurrency", type=int)
    scenario_parser.add_argument("--runs", type=int, default=1)
    scenario_parser.add_argument("--skip-build", action="store_true")
    scenario_parser.set_defaults(func=command_scenario)

    matrix_parser = subparsers.add_parser("matrix", help="run the full benchmark matrix")
    matrix_parser.add_argument("--root", required=True)
    matrix_parser.add_argument(
        "--scenarios",
        nargs="+",
        default=list(SCENARIOS.keys()),
        choices=sorted(SCENARIOS.keys()),
    )
    matrix_parser.add_argument("--gateway-port", type=int, default=18120)
    matrix_parser.add_argument("--upstream-port", type=int, default=19140)
    matrix_parser.add_argument("--opa-port", type=int, default=18220)
    matrix_parser.add_argument("--presidio-port", type=int, default=19340)
    matrix_parser.add_argument("--runs", type=int, default=3)
    matrix_parser.set_defaults(func=command_matrix)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except subprocess.CalledProcessError as exc:
        print(f"command failed: {exc}", file=sys.stderr)
        return exc.returncode or 1
    except ScenarioError as exc:
        print(f"scenario failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
