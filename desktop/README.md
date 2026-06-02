# Ctxward Desktop (Tauri shell)

Clash-style desktop front-end for the transparent MITM proxy. Embeds
`context_gurd::proxy_mode::run_proxy` in-process and drives OS integration
(root-CA install, system-proxy toggle) via the per-OS command layer in
[`src/platform.rs`](../src/platform.rs).

> **Status: scaffold.** The Rust integration points are real and reference the
> shipped kernel APIs, but the full Tauri build needs the GUI toolchain below
> and has **not** been compiled in the headless CI environment. The verified
> part of D2 is the `context_gurd::platform` command layer (unit-tested for all
> three OSes). This crate is a **standalone workspace** (`[workspace]` in its
> `Cargo.toml`) so the root `cargo build` / CI never tries to build it.

## What lives where

| Piece | File | Verified? |
|-------|------|-----------|
| Per-OS CA install + system-proxy command construction | `src/platform.rs` (root crate) | ✅ unit-tested |
| Proxy lifecycle (start/stop), CA export, integration plan | `desktop/src-tauri/src/lib.rs` | ⚠️ needs toolchain |
| Tray + window config | `desktop/src-tauri/tauri.conf.json` | ⚠️ needs toolchain |
| Control panel UI | `desktop/ui/index.html` | ⚠️ needs toolchain |

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

## Remaining D2 work (next session)

- Tray menu items (start/stop/quit) + status icon — driven by menu, not click.
- Privileged helper binary (`ctxward-helper`) for the elevated commands
  (`install_ca`, macOS proxy) via UAC / `osascript` / `pkexec`; the shell must
  never elevate itself wholesale.
- Live audit/metrics feed to the webview via a Tauri `ipc::Channel`.
- Teardown-on-quit + cleanup-on-launch self-heal (remove stale CA + proxy).
- Per-NSS-db CA install on Linux (Firefox/Chrome).
