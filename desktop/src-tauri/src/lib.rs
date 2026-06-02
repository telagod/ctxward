//! Ctxward Desktop — Tauri shell.
//!
//! Embeds the transparent MITM proxy (`context_gurd::proxy_mode::run_proxy`)
//! in-process and exposes commands to the webview: start/stop the proxy, install
//! or remove the local root CA, and toggle the system proxy. The detection /
//! redaction pipeline and per-OS command construction are reused verbatim from
//! the `context-gurd` crate — this shell only owns lifecycle + OS integration.
//!
//! Status: scaffold. The Rust integration points are real, but the full Tauri
//! build requires the GUI toolchain (see desktop/README.md) and has not been
//! compiled in the headless CI environment.

use std::{path::PathBuf, sync::Arc};

use context_gurd::{
    app::build_state,
    mitm::ca,
    platform::{self, TargetOs},
    proxy_mode,
};
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::oneshot;

/// Lifecycle handle for the running proxy task.
#[derive(Default)]
struct ProxyHandle {
    stop: Option<oneshot::Sender<()>>,
}

/// Managed app state.
struct Shared {
    proxy: Mutex<ProxyHandle>,
    config_path: PathBuf,
}

impl Shared {
    fn is_running(&self) -> bool {
        self.proxy.lock().stop.is_some()
    }
}

/// Start the MITM proxy from the configured `config.yaml` (must be `mode: proxy`).
#[tauri::command]
fn start_proxy(app: AppHandle, state: State<'_, Shared>) -> Result<(), String> {
    let mut handle = state.proxy.lock();
    if handle.stop.is_some() {
        return Err("proxy already running".into());
    }
    let app_state = build_state(state.config_path.clone()).map_err(|e| e.to_string())?;
    let (tx, rx) = oneshot::channel::<()>();
    handle.stop = Some(tx);
    drop(handle); // do not hold the lock across the spawn

    let app_for_task = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(err) = proxy_mode::run_proxy(app_state, async move {
            let _ = rx.await;
        })
        .await
        {
            let _ = app_for_task.emit("proxy://error", err.to_string());
        }
    });
    app.emit("proxy://status", "running").map_err(|e| e.to_string())
}

/// Stop the running proxy.
#[tauri::command]
fn stop_proxy(app: AppHandle, state: State<'_, Shared>) -> Result<(), String> {
    if let Some(tx) = state.proxy.lock().stop.take() {
        let _ = tx.send(());
    }
    app.emit("proxy://status", "stopped").map_err(|e| e.to_string())
}

#[tauri::command]
fn proxy_status(state: State<'_, Shared>) -> bool {
    state.is_running()
}

/// Return the root CA certificate PEM so the UI can show / export it. The CA is
/// generated on first proxy start.
#[tauri::command]
fn ca_cert_pem(state: State<'_, Shared>) -> Result<Option<String>, String> {
    let cfg = load_proxy_cfg(&state.config_path)?;
    ca::export_ca_cert_pem(&cfg).map_err(|e| e.to_string())
}

/// The OS commands (as displayable strings) that would install the CA + set the
/// system proxy. The shell executes the elevated ones via the privileged helper;
/// here we surface the plan so the UI can ask for consent before escalating.
#[tauri::command]
fn integration_plan(state: State<'_, Shared>, host: String, port: u16) -> Result<Vec<String>, String> {
    let os = TargetOs::current().ok_or("unsupported OS")?;
    let cfg = load_proxy_cfg(&state.config_path)?;
    let cert_path = cfg
        .ca_cert_path
        .clone()
        .unwrap_or_else(|| format!("{}/ctxward-ca.pem", cfg.ca_dir));
    let mut plan = Vec::new();
    for c in platform::install_ca_commands(os, &cert_path) {
        plan.push(render(&c));
    }
    for c in platform::set_proxy_commands(os, &host, port, "Wi-Fi") {
        plan.push(render(&c));
    }
    Ok(plan)
}

fn render(c: &platform::CommandSpec) -> String {
    let prefix = if c.elevated { "[sudo] " } else { "" };
    format!("{prefix}{} {}", c.program, c.args.join(" "))
}

fn load_proxy_cfg(config_path: &PathBuf) -> Result<context_gurd::config::ProxyConfig, String> {
    let cfg = context_gurd::config::AppConfig::load(config_path).map_err(|e| e.to_string())?;
    cfg.proxy.ok_or_else(|| "config has no `proxy` section (set mode: proxy)".into())
}

pub fn run() {
    let config_path = std::env::var("CONTEXT_GURD_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("config/example.yaml"));

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Shared {
            proxy: Mutex::new(ProxyHandle::default()),
            config_path,
        })
        .setup(|app| {
            // Tray-driven control (menu items are reliable across all 3 OSes;
            // tray click events are not on Linux).
            let _ = app.handle();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            proxy_status,
            ca_cert_pem,
            integration_plan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ctxward desktop");

    // Keep a reference so the import is not flagged unused in this scaffold.
    let _ = Arc::<()>::default();
}
