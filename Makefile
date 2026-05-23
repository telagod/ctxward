.PHONY: test clippy smoke-admin smoke-session-correlation smoke-builtin-block smoke-builtin-regex smoke-pdf smoke-ooxml smoke-presidio smoke-presidio-fail smoke-attachment-presidio-fail smoke-response-json smoke-sse smoke-sse-fail smoke-bench-drift smoke-bench-gate bench-smoke bench-matrix bench-gate bench-ci bench-promote smoke-all

test:
	cargo test -q

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

smoke-admin:
	bash ./scripts/smoke-admin.sh

smoke-session-correlation:
	bash ./scripts/smoke-session-correlation.sh

smoke-builtin-block:
	bash ./scripts/smoke-builtin-block.sh

smoke-builtin-regex:
	bash ./scripts/smoke-builtin-regex.sh

smoke-pdf:
	bash ./scripts/smoke-pdf.sh

smoke-ooxml:
	bash ./scripts/smoke-ooxml.sh

smoke-presidio:
	bash ./scripts/smoke-presidio.sh

smoke-presidio-fail:
	bash ./scripts/smoke-presidio-fail.sh

smoke-attachment-presidio-fail:
	bash ./scripts/smoke-attachment-presidio-fail.sh

smoke-response-json:
	bash ./scripts/smoke-response-json.sh

smoke-sse:
	bash ./scripts/smoke-sse.sh

smoke-sse-fail:
	bash ./scripts/smoke-sse-fail.sh

smoke-bench-drift:
	bash ./scripts/smoke-bench-drift.sh

smoke-bench-gate:
	bash ./scripts/smoke-bench-gate.sh

bench-smoke:
	bash ./scripts/bench-smoke.sh

bench-matrix:
	bash ./scripts/bench-matrix.sh

bench-gate:
	bash ./scripts/bench-gate.sh

bench-ci:
	bash ./scripts/bench-ci.sh

bench-promote:
	bash ./scripts/bench-promote.sh

smoke-all: test clippy smoke-admin smoke-session-correlation smoke-builtin-block smoke-builtin-regex smoke-pdf smoke-ooxml smoke-presidio smoke-presidio-fail smoke-attachment-presidio-fail smoke-response-json smoke-sse smoke-sse-fail smoke-bench-drift smoke-bench-gate bench-smoke bench-matrix
