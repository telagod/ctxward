//! Ctxward Desktop — Tauri 2.11 shell.
//!
//! Embeds `context_gurd::proxy_mode::run_proxy` in-process. Exposes commands to
//! the webview: start/stop the proxy, install/uninstall the local root CA,
//! set/clear the system proxy, and stream the live audit feed. Elevated OS
//! actions are batched through ONE `pkexec` (Linux) / `osascript` (macOS) /
//! `Start-Process -Verb RunAs` (Windows) prompt. The detection/redaction
//! pipeline, MITM proxy, CA and the per-OS command layer are reused verbatim
//! from `context-gurd`.
//!
//! Hardening endgame (NOT this scaffold): replace `pkexec sh -c <built string>`
//! with a signed helper binary + a polkit `.policy` exposing only the fixed
//! CA/proxy action IDs (no arbitrary shell). Acceptable here ONLY because every
//! token is app-generated and `sh_quote`d.

use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use context_gurd::app::build_state;
use context_gurd::audit::AuditStore;
use context_gurd::mitm::ca;
use context_gurd::platform::{self, CommandSpec, TargetOs};
use context_gurd::proxy_mode;

use tauri::menu::{MenuBuilder, MenuEvent, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{App, AppHandle, Emitter, Manager, RunEvent, State, WindowEvent, async_runtime};

use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, oneshot};

// ── Managed state ───────────────────────────────────────────────────────────

/// Lifecycle handles for the running proxy task + its audit pump.
#[derive(Default)]
struct ProxyHandle {
    /// Resolves → graceful proxy shutdown.
    stop: Option<oneshot::Sender<()>>,
    /// Resolves → audit-pump task exits (must die with the proxy).
    audit_pump_stop: Option<oneshot::Sender<()>>,
}

/// Managed app state. `parking_lot::Mutex` for the synchronous command bodies
/// (guards are dropped before any `spawn`); `proxy_engaged` is a
/// `tokio::sync::Mutex<bool>` because teardown (async) reads it.
struct Shared {
    proxy: Mutex<ProxyHandle>,
    config_path: PathBuf,
    /// True once the system proxy points at us, so teardown clears it on exit.
    proxy_engaged: AsyncMutex<bool>,
}

impl Shared {
    fn is_running(&self) -> bool {
        self.proxy.lock().stop.is_some()
    }
}

// ── Config helpers ──────────────────────────────────────────────────────────

fn load_proxy_cfg(config_path: &PathBuf) -> Result<context_gurd::config::ProxyConfig, String> {
    let cfg = context_gurd::config::AppConfig::load(config_path).map_err(|e| e.to_string())?;
    cfg.proxy
        .ok_or_else(|| "config has no `proxy` section (set mode: proxy)".into())
}

/// `listen_addr` is `host:port`; split it for `set_proxy_commands`.
fn proxy_host_port(cfg: &context_gurd::config::ProxyConfig) -> Result<(String, u16), String> {
    let (h, p) = cfg
        .listen_addr
        .rsplit_once(':')
        .ok_or_else(|| format!("malformed listen_addr `{}`", cfg.listen_addr))?;
    let port: u16 = p
        .parse()
        .map_err(|_| format!("bad port in `{}`", cfg.listen_addr))?;
    let host = if h.is_empty() || h == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else {
        h.to_string()
    };
    Ok((host, port))
}

fn cert_path_of(cfg: &context_gurd::config::ProxyConfig) -> String {
    cfg.ca_cert_path
        .clone()
        .unwrap_or_else(|| format!("{}/ctxward-ca.pem", cfg.ca_dir))
}

// ── (1) Proxy lifecycle commands ────────────────────────────────────────────

#[tauri::command]
fn start_proxy(app: AppHandle, state: State<'_, Shared>) -> Result<(), String> {
    let mut handle = state.proxy.lock();
    if handle.stop.is_some() {
        return Err("proxy already running".into());
    }
    let app_state = build_state(state.config_path.clone()).map_err(|e| e.to_string())?;

    let (tx, rx) = oneshot::channel::<()>();
    let (pump_tx, pump_rx) = oneshot::channel::<()>();
    handle.stop = Some(tx);
    handle.audit_pump_stop = Some(pump_tx);
    drop(handle); // never hold the lock across spawn

    spawn_audit_pump(app.clone(), app_state.audit_store.clone(), pump_rx);

    let app_for_task = app.clone();
    async_runtime::spawn(async move {
        if let Err(err) = proxy_mode::run_proxy(app_state, async move {
            let _ = rx.await;
        })
        .await
        {
            let _ = app_for_task.emit("proxy://error", err.to_string());
        }
    });

    app.emit("proxy://status", "running")
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_proxy(app: AppHandle, state: State<'_, Shared>) -> Result<(), String> {
    {
        let mut handle = state.proxy.lock();
        if let Some(tx) = handle.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = handle.audit_pump_stop.take() {
            let _ = t.send(());
        }
    }
    app.emit("proxy://status", "stopped")
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn proxy_status(state: State<'_, Shared>) -> bool {
    state.is_running()
}

// ── (1b) Audit pump — Emitter broadcast (1:N, survives reloads) ─────────────

/// Poll the bounded ring buffer and emit only *new* records. `AuditRecord`
/// derives `Clone + Serialize` → satisfies `Emitter::emit`.
fn spawn_audit_pump(app: AppHandle, store: Arc<AuditStore>, mut stop: oneshot::Receiver<()>) {
    async_runtime::spawn(async move {
        let mut cursor: usize = store.len();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = tick.tick() => {
                    let snap = store.snapshot();
                    // Ring evicts oldest when full → snapshot can shrink below
                    // cursor; clamp or the slice index panics.
                    if snap.len() < cursor {
                        cursor = snap.len();
                        continue;
                    }
                    for rec in &snap[cursor..] {
                        if app.emit("audit://record", rec.clone()).is_err() {
                            return;
                        }
                    }
                    cursor = snap.len();
                }
            }
        }
    });
}

// ── (2) CA + system-proxy commands (elevated batched into ONE prompt) ───────

/// POSIX single-quote a token so it survives `sh -c`. Load-bearing: CommandSpec
/// args are stored UNQUOTED — concatenating raw is an injection vector.
fn sh_quote(token: &str) -> String {
    let mut out = String::with_capacity(token.len() + 2);
    out.push('\'');
    for ch in token.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn spec_to_shell_line(spec: &CommandSpec) -> String {
    let mut parts = Vec::with_capacity(1 + spec.args.len());
    parts.push(sh_quote(&spec.program));
    for a in &spec.args {
        parts.push(sh_quote(a));
    }
    parts.join(" ")
}

/// Run every *elevated* CommandSpec through ONE privilege prompt; non-elevated
/// specs run directly via `platform::run`. Blocking — call from `spawn_blocking`.
fn apply_specs_blocking(os: TargetOs, specs: &[CommandSpec]) -> Result<(), String> {
    for spec in specs.iter().filter(|c| !c.elevated) {
        platform::run(spec).map_err(|e| format!("{}: {e}", spec.program))?;
    }

    let elevated: Vec<&CommandSpec> = specs.iter().filter(|c| c.elevated).collect();
    if elevated.is_empty() {
        return Ok(());
    }

    let script = std::iter::once("set -e".to_string())
        .chain(elevated.iter().map(|c| spec_to_shell_line(c)))
        .collect::<Vec<_>>()
        .join("\n");

    let status = match os {
        TargetOs::Linux => StdCommand::new("pkexec")
            .arg("sh")
            .arg("-c")
            .arg(&script)
            .status(),
        TargetOs::MacOs => {
            let osa_inner = script.replace('\\', "\\\\").replace('"', "\\\"");
            let apple = format!("do shell script \"{osa_inner}\" with administrator privileges");
            StdCommand::new("osascript").arg("-e").arg(&apple).status()
        }
        TargetOs::Windows => {
            // Stopgap: before shipping Windows, replace with
            // `powershell -EncodedCommand <base64 UTF-16LE>`.
            let ps = format!(
                "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c',{} -Verb RunAs -Wait",
                sh_quote(&script)
            );
            StdCommand::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
                .status()
        }
    }
    .map_err(|e| format!("failed to spawn elevation helper: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "elevated batch exited with {} (user may have cancelled the prompt)",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        ))
    }
}

/// Build specs Rust-side and run them off the event loop. CommandSpec is NOT
/// serde-derived, so it NEVER crosses the IPC boundary.
async fn run_specs(os: TargetOs, specs: Vec<CommandSpec>) -> Result<(), String> {
    async_runtime::spawn_blocking(move || apply_specs_blocking(os, &specs))
        .await
        .map_err(|e| format!("join error: {e}"))?
}

#[tauri::command]
async fn install_ca(state: State<'_, Shared>) -> Result<(), String> {
    let os = TargetOs::current().ok_or("unsupported OS")?;
    let cfg = load_proxy_cfg(&state.config_path)?;
    let cert = cert_path_of(&cfg);
    run_specs(os, platform::install_ca_commands(os, &cert)).await
}

#[tauri::command]
async fn uninstall_ca() -> Result<(), String> {
    let os = TargetOs::current().ok_or("unsupported OS")?;
    run_specs(os, platform::uninstall_ca_commands(os)).await
}

#[tauri::command]
async fn set_system_proxy(app: AppHandle, state: State<'_, Shared>) -> Result<(), String> {
    let os = TargetOs::current().ok_or("unsupported OS")?;
    let cfg = load_proxy_cfg(&state.config_path)?;
    let (host, port) = proxy_host_port(&cfg)?;
    run_specs(os, platform::set_proxy_commands(os, &host, port, "Wi-Fi")).await?;
    *state.proxy_engaged.lock().await = true;
    let _ = app.emit("proxy://system", "set");
    Ok(())
}

#[tauri::command]
async fn clear_system_proxy(app: AppHandle, state: State<'_, Shared>) -> Result<(), String> {
    let os = TargetOs::current().ok_or("unsupported OS")?;
    run_specs(os, platform::clear_proxy_commands(os, "Wi-Fi")).await?;
    *state.proxy_engaged.lock().await = false;
    let _ = app.emit("proxy://system", "cleared");
    Ok(())
}

/// Read-only: surface the CA PEM so the UI can show/export it (no elevation).
#[tauri::command]
fn ca_cert_pem(state: State<'_, Shared>) -> Result<Option<String>, String> {
    let cfg = load_proxy_cfg(&state.config_path)?;
    ca::export_ca_cert_pem(&cfg).map_err(|e| e.to_string())
}

// ── (3) Builder · tray · run-loop · teardown ────────────────────────────────

pub fn run() {
    let config_path = std::env::var("CONTEXT_GURD_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("config/example.yaml"));

    let ctx = tauri::generate_context!();

    let app: App = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Shared {
            proxy: Mutex::new(ProxyHandle::default()),
            config_path,
            proxy_engaged: AsyncMutex::new(false),
        })
        .setup(|app: &mut App| {
            #[cfg(target_os = "macos")]
            let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let start = MenuItemBuilder::with_id("start_proxy", "Start proxy").build(app)?;
            let stop = MenuItemBuilder::with_id("stop_proxy", "Stop proxy").build(app)?;
            let open = MenuItemBuilder::with_id("open_window", "Open window").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&start)
                .item(&stop)
                .separator()
                .item(&open)
                .separator()
                .item(&quit)
                .build()?;

            let _tray = TrayIconBuilder::with_id("main")
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .expect("bundle default window icon (icons/icon.png)"),
                )
                .tooltip("ctxward — LLM privacy gateway")
                .show_menu_on_left_click(false)
                .menu(&menu)
                .on_menu_event(|app: &AppHandle, event: MenuEvent| match event.id() {
                    id if id == "open_window" => {
                        #[cfg(target_os = "macos")]
                        let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    id if id == "start_proxy" => {
                        let state = app.state::<Shared>();
                        if let Err(e) = start_proxy(app.clone(), state) {
                            let _ = app.emit("proxy://error", e);
                        }
                    }
                    id if id == "stop_proxy" => {
                        let state = app.state::<Shared>();
                        let _ = stop_proxy(app.clone(), state);
                    }
                    id if id == "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        // Hide-to-tray: closing the window must NOT tear down the proxy.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                #[cfg(target_os = "macos")]
                {
                    let app = window.app_handle();
                    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            proxy_status,
            install_ca,
            uninstall_ca,
            set_system_proxy,
            clear_system_proxy,
            ca_cert_pem,
        ])
        .build(ctx)
        .expect("error while building ctxward desktop");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            teardown(app_handle);
        }
    });
}

/// Synchronous teardown from the `RunEvent::Exit` closure. That closure runs on
/// Tauri's tokio reactor thread → `block_on` there panics; escape to a fresh OS
/// thread, block_on there, join. The tokio guard is dropped before blocking work.
fn teardown(app_handle: &AppHandle) {
    let app_handle = app_handle.clone();
    let _ = std::thread::spawn(move || {
        let must_clear = async_runtime::block_on(async {
            let state = app_handle.state::<Shared>();
            {
                let mut h = state.proxy.lock();
                if let Some(tx) = h.stop.take() {
                    let _ = tx.send(());
                }
                if let Some(t) = h.audit_pump_stop.take() {
                    let _ = t.send(());
                }
            }
            *state.proxy_engaged.lock().await
        });

        if must_clear && let Some(os) = TargetOs::current() {
            let specs = platform::clear_proxy_commands(os, "Wi-Fi");
            if let Err(e) = apply_specs_blocking(os, &specs) {
                tracing::warn!(%e, "proxy teardown failed");
            }
        }
        // CA removal is an explicit user action, never silent teardown.
        std::thread::sleep(Duration::from_millis(150));
    })
    .join();
}
