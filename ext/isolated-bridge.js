// ISOLATED world: the extension's own context (CSP allows wasm-unsafe-eval).
// Loads the ctxward-core WASM and answers redaction requests from the
// MAIN-world patch. The WASM is the SAME engine as the gateway — one source of
// truth, zero detection drift.
(() => {
  "use strict";

  let redactFn = null; // (configJson, body) => scrubbedBody
  let rulesJson = "{}";
  let ready = false;
  const queue = [];

  async function boot() {
    const wasmJsUrl = chrome.runtime.getURL("pkg/ctxward_core.js");
    const wasmBinUrl = chrome.runtime.getURL("pkg/ctxward_core_bg.wasm");
    const rulesUrl = chrome.runtime.getURL("default-rules.json");

    const [{ default: init, redact_json }, rulesResp] = await Promise.all([
      import(wasmJsUrl),
      fetch(rulesUrl),
    ]);
    await init(wasmBinUrl);
    rulesJson = await rulesResp.text();
    redactFn = redact_json;
    ready = true;
    // drain anything that arrived during boot
    while (queue.length) handle(queue.shift());
  }

  function handle(msg) {
    let body;
    try {
      body = redactFn(rulesJson, msg.body);
    } catch (e) {
      // fail-closed: do not echo the original (which may contain PII)
      console.warn("ctxward: redaction failed", e);
      body = "";
    }
    window.postMessage({ __ctxward: "redacted", id: msg.id, body }, window.location.origin);
  }

  window.addEventListener("message", (ev) => {
    if (ev.source !== window) return;
    const msg = ev.data;
    if (!msg || msg.__ctxward !== "redact") return;
    if (ready) handle(msg);
    else queue.push(msg);
  });

  boot().catch((e) => console.error("ctxward: failed to initialise WASM core", e));
})();
