# Ctxward Browser Extension (MV3)

Scrubs PII from LLM **web-chat** requests (chatgpt.com / claude.ai /
gemini.google.com) before they leave the browser — without installing a root
CA. The redaction engine is the **same `ctxward-core` compiled to WASM** as the
gateway, so detection never drifts.

> **Status: scaffold + verified core.** The redaction core (`ctxward-core`'s
> `redact_json`) is native-unit-tested and **compiles to `wasm32-unknown-unknown`**
> (`cargo build --target wasm32-unknown-unknown -p ctxward-core --features wasm`).
> The MV3 wiring below is written against the documented APIs but has not been
> loaded in a real browser in CI.

## Architecture

```
page (MAIN world)                 extension (ISOLATED world)
  mainworld-patch.js                isolated-bridge.js
  ─ wraps window.fetch/XHR          ─ loads ctxward-core WASM (CSP-allowed here)
  ─ on a provider request:          ─ redact_json(rules, body) (same engine)
      postMessage(body) ───────────▶ scrub
      await scrubbed   ◀───────────── postMessage(scrubbed)
  ─ send scrubbed body
```

- **Fail-closed**: if the isolated bridge does not answer within the timeout (or
  WASM init fails), the request is blocked rather than sent with raw PII.
- WASM runs only in the ISOLATED world (extension CSP allows `wasm-unsafe-eval`);
  the page CSP forbids it, hence the cross-world split.
- `default-rules.json` is the bundled `DetectionConfig` (same rule shape as the
  gateway's `config/example.yaml` detection section).

## Build the WASM core

```bash
# from the repo root
cargo install wasm-pack          # one-time
wasm-pack build crates/ctxward-core --target web --out-dir ../../ext/pkg --features wasm
# produces ext/pkg/ctxward_core.js + ext/pkg/ctxward_core_bg.wasm
```

(Compile-check without wasm-pack: `cargo build --target wasm32-unknown-unknown -p ctxward-core --features wasm`.)

## Load (Chrome/Edge)

`chrome://extensions` → Developer mode → **Load unpacked** → select `ext/`
(after building `ext/pkg/`).

## Remaining (next)

- v1 targets `chatgpt.com` + `claude.ai`; **Gemini is best-effort** (its
  Service-Worker routing can bypass `window.fetch`).
- Rule-set sync from the desktop app (shared signed rule-set) via
  `chrome.storage` / native messaging.
- Per-site on/off toggle + a redaction counter popup.
- Response-side scrubbing (currently request-only — the privacy-critical side).
