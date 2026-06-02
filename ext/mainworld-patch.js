// MAIN world: runs in the page's context so it can wrap the page's own
// `window.fetch` / `XMLHttpRequest`. The page CSP forbids WASM here, so the
// actual redaction is delegated to the ISOLATED-world bridge via postMessage.
//
// Flow: intercept an outbound request body -> ask the isolated world to scrub
// it -> send the scrubbed body. Fail-closed: if the bridge does not answer in
// time, the request is aborted rather than sent with raw PII.
(() => {
  "use strict";

  // Only bodies going to the chat completion / message endpoints are scrubbed.
  const ENDPOINT_RE = /\/(backend-api\/conversation|v1\/(chat\/completions|messages)|api\/.*generate)/i;
  const RESPONSE_TIMEOUT_MS = 1500;

  let seq = 0;
  const pending = new Map();

  window.addEventListener("message", (ev) => {
    if (ev.source !== window) return;
    const msg = ev.data;
    if (!msg || msg.__ctxward !== "redacted") return;
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    entry.resolve(msg.body);
  });

  function scrub(body) {
    if (typeof body !== "string" || body.length === 0) return Promise.resolve(body);
    const id = ++seq;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (pending.delete(id)) resolve(null); // fail-closed sentinel
      }, RESPONSE_TIMEOUT_MS);
      pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
      });
      window.postMessage({ __ctxward: "redact", id, body }, window.location.origin);
    });
  }

  const origFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    try {
      const url = typeof input === "string" ? input : input && input.url;
      if (url && ENDPOINT_RE.test(url) && init && typeof init.body === "string") {
        const clean = await scrub(init.body);
        if (clean === null) throw new Error("ctxward: redaction unavailable; request blocked");
        init = { ...init, body: clean };
      }
    } catch (e) {
      // fail-closed: surface the error rather than silently sending raw PII
      return Promise.reject(e);
    }
    return origFetch(input, init);
  };

  // XHR cover for clients that use it instead of fetch.
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    if (typeof body === "string" && this.__ctxwardUrl && ENDPOINT_RE.test(this.__ctxwardUrl)) {
      scrub(body).then((clean) => {
        origSend.call(this, clean === null ? "" : clean);
      });
      return;
    }
    return origSend.call(this, body);
  };
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__ctxwardUrl = url;
    return origOpen.call(this, method, url, ...rest);
  };
})();
