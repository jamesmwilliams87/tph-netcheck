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

/// Turns a host name into an IPv4 address string.
pub fn resolve_ipv4(host: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host.to_string());
    }
    (host, 445)
        .to_socket_addrs()
        .ok()?
        .find(|a| a.is_ipv4())
        .map(|a| a.ip().to_string())
}
