//! Running system commands without flashing console windows on Windows.

use std::process::{Command, Stdio};

pub fn command(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c.stdin(Stdio::null());
    c
}

/// Runs a command and returns stdout, even if the exit code is non-zero
/// (ping exits 1 or 2 on packet loss, and we still want its output).
pub fn output(program: &str, args: &[&str]) -> Result<String, String> {
    let out = command(program)
        .args(args)
        .output()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    if s.trim().is_empty() {
        s = String::from_utf8_lossy(&out.stderr).to_string();
    }
    Ok(s)
}

#[cfg(windows)]
pub fn powershell(script: &str) -> Result<String, String> {
    output("powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

pub fn os_name() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Turns a host name into an IPv4 address string. A bare name such as
/// "Neptune" is tried as given, then as "Neptune.local", which is how a
/// Synology announces itself on the network over Bonjour.
pub fn resolve_ipv4(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host.to_string());
    }
    let mut names = vec![host.to_string()];
    if !host.contains('.') {
        names.push(format!("{host}.local"));
    }
    names.iter().find_map(|n| lookup(n))
}

fn lookup(name: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    (name, 445)
        .to_socket_addrs()
        .ok()?
        .find(|a| a.is_ipv4())
        .map(|a| a.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves() {
        assert_eq!(resolve_ipv4(""), None);
        assert_eq!(resolve_ipv4(" 192.168.10.5 ").as_deref(), Some("192.168.10.5"));
        assert_eq!(resolve_ipv4("localhost").as_deref(), Some("127.0.0.1"));
        assert_eq!(resolve_ipv4("no-such-host-tph-netcheck"), None);
    }
}
