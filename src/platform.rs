//! OS integration for the desktop shell: installing/removing the local root CA
//! in the system trust store, and toggling the system HTTP(S) proxy.
//!
//! Command *construction* is pure and unit-tested here so the exact argv for
//! each OS is locked down. *Execution* needs privilege escalation and live
//! system access, so it is a thin wrapper ([`run`]) the Tauri shell drives —
//! it is intentionally not exercised in CI (headless, unprivileged).

use std::process::Command;

/// The three desktop targets ctxward supports in the first phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetOs {
    MacOs,
    Windows,
    Linux,
}

impl TargetOs {
    /// The OS this binary was built for, if it is one we support.
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

/// A single OS command. `elevated` marks commands that require admin/root
/// (so the shell can route them through one privileged helper invocation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub elevated: bool,
}

impl CommandSpec {
    fn new(program: &str, args: &[&str], elevated: bool) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            elevated,
        }
    }
}

/// Common name of the generated root CA (matches `mitm::ca`).
pub const CA_COMMON_NAME: &str = "ctxward Root CA";

const LINUX_CA_DIR: &str = "/usr/local/share/ca-certificates";
const LINUX_CA_FILENAME: &str = "ctxward-ca.crt";
const MACOS_SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const WIN_INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Commands to install `cert_path` (PEM/DER) as a trusted root CA.
pub fn install_ca_commands(os: TargetOs, cert_path: &str) -> Vec<CommandSpec> {
    match os {
        TargetOs::MacOs => vec![CommandSpec::new(
            "security",
            &[
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                MACOS_SYSTEM_KEYCHAIN,
                cert_path,
            ],
            true,
        )],
        TargetOs::Windows => vec![CommandSpec::new(
            "certutil",
            &["-addstore", "-f", "Root", cert_path],
            true,
        )],
        TargetOs::Linux => {
            let dest = format!("{LINUX_CA_DIR}/{LINUX_CA_FILENAME}");
            vec![
                CommandSpec::new("cp", &[cert_path, &dest], true),
                CommandSpec::new("update-ca-certificates", &[], true),
            ]
        }
    }
}

/// Commands to remove the previously-installed ctxward root CA.
pub fn uninstall_ca_commands(os: TargetOs) -> Vec<CommandSpec> {
    match os {
        TargetOs::MacOs => vec![CommandSpec::new(
            "security",
            &[
                "delete-certificate",
                "-c",
                CA_COMMON_NAME,
                MACOS_SYSTEM_KEYCHAIN,
            ],
            true,
        )],
        TargetOs::Windows => vec![CommandSpec::new(
            "certutil",
            &["-delstore", "Root", CA_COMMON_NAME],
            true,
        )],
        TargetOs::Linux => {
            let dest = format!("{LINUX_CA_DIR}/{LINUX_CA_FILENAME}");
            vec![
                CommandSpec::new("rm", &["-f", &dest], true),
                CommandSpec::new("update-ca-certificates", &["--fresh"], true),
            ]
        }
    }
}

/// Commands to point the system HTTP(S) proxy at `host:port`.
///
/// `macos_service` is the network service name (e.g. "Wi-Fi"); the shell
/// enumerates `networksetup -listallnetworkservices` and applies per service.
pub fn set_proxy_commands(
    os: TargetOs,
    host: &str,
    port: u16,
    macos_service: &str,
) -> Vec<CommandSpec> {
    let port = port.to_string();
    match os {
        TargetOs::MacOs => vec![
            CommandSpec::new(
                "networksetup",
                &["-setsecurewebproxy", macos_service, host, &port],
                true,
            ),
            CommandSpec::new(
                "networksetup",
                &["-setwebproxy", macos_service, host, &port],
                true,
            ),
        ],
        TargetOs::Windows => {
            let endpoint = format!("{host}:{port}");
            vec![
                CommandSpec::new(
                    "reg",
                    &[
                        "add",
                        WIN_INET_KEY,
                        "/v",
                        "ProxyServer",
                        "/t",
                        "REG_SZ",
                        "/d",
                        &endpoint,
                        "/f",
                    ],
                    false,
                ),
                CommandSpec::new(
                    "reg",
                    &[
                        "add",
                        WIN_INET_KEY,
                        "/v",
                        "ProxyEnable",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        "1",
                        "/f",
                    ],
                    false,
                ),
            ]
        }
        TargetOs::Linux => vec![
            CommandSpec::new(
                "gsettings",
                &["set", "org.gnome.system.proxy", "mode", "manual"],
                false,
            ),
            CommandSpec::new(
                "gsettings",
                &["set", "org.gnome.system.proxy.http", "host", host],
                false,
            ),
            CommandSpec::new(
                "gsettings",
                &["set", "org.gnome.system.proxy.http", "port", &port],
                false,
            ),
            CommandSpec::new(
                "gsettings",
                &["set", "org.gnome.system.proxy.https", "host", host],
                false,
            ),
            CommandSpec::new(
                "gsettings",
                &["set", "org.gnome.system.proxy.https", "port", &port],
                false,
            ),
        ],
    }
}

/// Commands to disable the system HTTP(S) proxy ctxward set.
pub fn clear_proxy_commands(os: TargetOs, macos_service: &str) -> Vec<CommandSpec> {
    match os {
        TargetOs::MacOs => vec![
            CommandSpec::new(
                "networksetup",
                &["-setsecurewebproxystate", macos_service, "off"],
                true,
            ),
            CommandSpec::new(
                "networksetup",
                &["-setwebproxystate", macos_service, "off"],
                true,
            ),
        ],
        TargetOs::Windows => vec![CommandSpec::new(
            "reg",
            &[
                "add",
                WIN_INET_KEY,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ],
            false,
        )],
        TargetOs::Linux => vec![CommandSpec::new(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "none"],
            false,
        )],
    }
}

/// Execute a [`CommandSpec`] (non-elevated). Elevated commands must be routed
/// through the privileged helper by the shell; this returns an error for them
/// so a caller cannot silently fail to escalate.
///
/// Not exercised in CI: it touches the live system.
pub fn run(spec: &CommandSpec) -> std::io::Result<std::process::Output> {
    if spec.elevated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "command '{}' requires elevation; route it through the privileged helper",
                spec.program
            ),
        ));
    }
    Command::new(&spec.program).args(&spec.args).output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_ca_install_uninstall() {
        let install = install_ca_commands(TargetOs::MacOs, "/tmp/ctxward-ca.pem");
        assert_eq!(install.len(), 1);
        assert_eq!(install[0].program, "security");
        assert!(install[0].elevated);
        assert_eq!(install[0].args[0], "add-trusted-cert");
        assert!(install[0].args.contains(&MACOS_SYSTEM_KEYCHAIN.to_string()));
        assert!(install[0].args.contains(&"/tmp/ctxward-ca.pem".to_string()));

        let uninstall = uninstall_ca_commands(TargetOs::MacOs);
        assert_eq!(
            uninstall[0].args,
            vec![
                "delete-certificate",
                "-c",
                CA_COMMON_NAME,
                MACOS_SYSTEM_KEYCHAIN
            ]
        );
    }

    #[test]
    fn windows_ca_install_uninstall() {
        let install = install_ca_commands(TargetOs::Windows, "C:\\ctxward-ca.cer");
        assert_eq!(install[0].program, "certutil");
        assert_eq!(
            install[0].args,
            vec!["-addstore", "-f", "Root", "C:\\ctxward-ca.cer"]
        );
        assert!(install[0].elevated);

        let uninstall = uninstall_ca_commands(TargetOs::Windows);
        assert_eq!(uninstall[0].args, vec!["-delstore", "Root", CA_COMMON_NAME]);
    }

    #[test]
    fn linux_ca_install_uninstall() {
        let install = install_ca_commands(TargetOs::Linux, "/tmp/c.pem");
        assert_eq!(install.len(), 2);
        assert_eq!(install[0].program, "cp");
        assert_eq!(
            install[0].args,
            vec![
                "/tmp/c.pem",
                "/usr/local/share/ca-certificates/ctxward-ca.crt"
            ]
        );
        assert_eq!(install[1].program, "update-ca-certificates");
        assert!(install.iter().all(|c| c.elevated));

        let uninstall = uninstall_ca_commands(TargetOs::Linux);
        assert_eq!(uninstall[0].program, "rm");
        assert_eq!(uninstall[1].args, vec!["--fresh"]);
    }

    #[test]
    fn macos_proxy_set_clear() {
        let set = set_proxy_commands(TargetOs::MacOs, "127.0.0.1", 8888, "Wi-Fi");
        assert_eq!(set.len(), 2);
        assert_eq!(
            set[0].args,
            vec!["-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8888"]
        );
        assert_eq!(
            set[1].args,
            vec!["-setwebproxy", "Wi-Fi", "127.0.0.1", "8888"]
        );

        let clear = clear_proxy_commands(TargetOs::MacOs, "Wi-Fi");
        assert_eq!(
            clear[0].args,
            vec!["-setsecurewebproxystate", "Wi-Fi", "off"]
        );
        assert_eq!(clear[1].args, vec!["-setwebproxystate", "Wi-Fi", "off"]);
    }

    #[test]
    fn windows_proxy_set_clear() {
        let set = set_proxy_commands(TargetOs::Windows, "127.0.0.1", 8888, "");
        assert_eq!(set.len(), 2);
        assert!(set[0].args.contains(&"127.0.0.1:8888".to_string()));
        assert!(set[1].args.contains(&"ProxyEnable".to_string()));
        assert!(set[1].args.contains(&"1".to_string()));
        assert!(set.iter().all(|c| !c.elevated)); // WinINET HKCU needs no admin

        let clear = clear_proxy_commands(TargetOs::Windows, "");
        assert!(clear[0].args.contains(&"0".to_string()));
    }

    #[test]
    fn linux_proxy_set_clear() {
        let set = set_proxy_commands(TargetOs::Linux, "127.0.0.1", 8888, "");
        assert_eq!(set.len(), 5);
        assert_eq!(
            set[0].args,
            vec!["set", "org.gnome.system.proxy", "mode", "manual"]
        );
        assert!(
            set.iter()
                .any(|c| c.args == vec!["set", "org.gnome.system.proxy.http", "port", "8888"])
        );
        assert!(set.iter().all(|c| !c.elevated));

        let clear = clear_proxy_commands(TargetOs::Linux, "");
        assert_eq!(
            clear[0].args,
            vec!["set", "org.gnome.system.proxy", "mode", "none"]
        );
    }

    #[test]
    fn run_refuses_to_silently_skip_elevation() {
        let elevated = CommandSpec::new("certutil", &["-addstore"], true);
        let err = run(&elevated).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
