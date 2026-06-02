# Ctxward Desktop (Tauri shell)

Clash-style desktop front-end for the transparent MITM proxy. Embeds
`context_gurd::proxy_mode::run_proxy` in-process and drives OS integration
(root-CA install, system-proxy toggle) via the per-OS command layer in
[`src/platform.rs`](../src/platform.rs).

> **Status: compiles (Tauri 2.11, Linux gtk/webkit2gtk-4.1).** Full feature set
> wired: tray (Start/Stop/Open/Quit), proxy lifecycle, CA install/uninstall and
> system-proxy set/clear (elevated ops batched through ONE pkexec/osascript/UAC
> prompt), live audit feed to the webview, and exit teardown. `cargo build` +
> `clippy -D warnings` + `fmt` are green; **runtime needs a desktop session**
> (GTK display) and a one-time elevation prompt for the CA/proxy actions — those
> aren't exercised in headless CI. This crate is a **standalone workspace** so
> the root `cargo build` / CI never builds it.

## What lives where

| Piece | File | Verified? |
|-------|------|-----------|
| Per-OS CA install + system-proxy command construction | `src/platform.rs` (root crate) | ✅ unit-tested |
| Proxy lifecycle, CA, system-proxy, audit pump, tray, teardown | `desktop/src-tauri/src/lib.rs` | ✅ compiles + clippy clean |
| Tray + window config | `desktop/src-tauri/tauri.conf.json` | ✅ build-validated |
| Control panel UI (status, CA, proxy, live audit feed) | `desktop/ui/index.html` | ⚠️ runtime (needs display) |

## Build (on a machine with the GUI toolchain)

Prerequisites:
- Rust 1.85+
- Tauri 2 system deps — Linux: `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`,
  `librsvg2-dev`, `patchelf`; macOS: Xcode CLT; Windows: WebView2 + MSVC.
- `cargo install tauri-cli --version '^2'`
- Tray icon at `desktop/src-tauri/icons/icon.png` (add before building).

```bash
cd desktop/src-tauri
cargo tauri dev      # run with hot-reload
cargo tauri build    # produce installers
```

By default the shell reads `CONTEXT_GURD_CONFIG` (a `mode: proxy` config) or
falls back to `config/example.yaml`.

## Done

- Tray menu (Start / Stop / Open / Quit) — menu-driven (Linux click events are
  unreliable); hide-to-tray on window close.
- Proxy lifecycle (`start_proxy` / `stop_proxy` / `proxy_status`) embedding
  `run_proxy` with a graceful-shutdown oneshot.
- CA install/uninstall + system-proxy set/clear — elevated `CommandSpec`s
  batched through **ONE** `pkexec` (Linux) / `osascript` (macOS) /
  `Start-Process -Verb RunAs` (Windows) prompt, with `sh_quote`d tokens.
- Live audit feed to the webview (`audit://record` Emitter broadcast, polled
  from the in-memory ring buffer).
- Exit teardown: signal proxy/pump shutdown + clear the system proxy if engaged.

## Remaining (hardening / later)

- Signed helper binary + polkit `.policy` with fixed action IDs (replace
  `pkexec sh -c`); Windows `-EncodedCommand` instead of the cmd `/c` stopgap.
- Per-NSS-db CA install on Linux (Firefox/Chrome); CA-removal-on-quit is
  intentionally NOT silent (explicit user action only).
- Cost dashboard view over the `gateway_llm_*` metrics; retention rotation.
