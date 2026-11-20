//! Starts tph-netcheck-server on Neptune through the system OpenSSH client
//! (built into macOS and Windows 10/11).

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netcheck_proto::{ServeReport, StatsLine, READY_LINE};

use crate::report::ServerSnapshot;
use crate::settings::Settings;
use crate::sys;

struct Remote {
    child: Child,
    rx: Receiver<(Instant, String)>,
    stderr: Arc<Mutex<String>>,
}

fn safe_path(p: &str) -> bool {
    !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
}

fn spawn(s: &Settings, args: &str) -> Result<Remote, String> {
    if !s.ssh_ready() {
        return Err("Neptune SSH is not set up in Settings".into());
    }
    if !safe_path(&s.server_path) {
        return Err("The server path on Neptune can only contain letters, numbers, / . _ -".into());
    }
    let program = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    let target = format!("{}@{}", s.ssh_user, s.neptune_host);
    let remote_cmd = format!("{} {}", s.server_path, args);
    let mut child = sys::command(program)
        .args([
            "-i", &s.ssh_key_path,
            "-p", &s.ssh_port.to_string(),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=ERROR",
            "-T",
            &target,
            &remote_cmd,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start the SSH client ({e}). OpenSSH must be installed."))?;

    let (tx, rx) = channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send((Instant::now(), line)).is_err() {
                break;
            }
        }
    });
    let stderr = Arc::new(Mutex::new(String::new()));
    let mut err = child.stderr.take().unwrap();
    let e2 = stderr.clone();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        *e2.lock().unwrap() = s;
    });
    Ok(Remote { child, rx, stderr })
}

impl Remote {
    fn error(&mut self, s: &Settings) -> String {
        let _ = self.child.wait();
        std::thread::sleep(Duration::from_millis(100));
        friendly_error(&self.stderr.lock().unwrap(), s)
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn friendly_error(stderr: &str, s: &Settings) -> String {
    let e = stderr.to_lowercase();
    let msg = if e.contains("permission denied") {
        format!("Neptune refused the SSH key for user '{}'. Check the public key is in that user's authorized_keys.", s.ssh_user)
    } else if e.contains("connection refused") {
        "Neptune refused the SSH connection. Check SSH is enabled in DSM (Control Panel > Terminal & SNMP) and the port is right.".into()
    } else if e.contains("timed out") || e.contains("no route") || e.contains("unreachable") {
        format!("Could not reach Neptune at {} over SSH.", s.neptune_host)
    } else if e.contains("no such file") || e.contains("not found") {
        format!("tph-netcheck-server was not found on Neptune at {}.", s.server_path)
    } else if e.contains("command not allowed") {
        "Neptune's forced command rejected the request. Check the authorized_keys line.".into()
    } else if e.contains("bad permissions") || e.contains("unprotected private key") {
        "The SSH key file permissions are too open. Re-import the key in Settings.".into()
    } else if e.contains("host key verification failed") || e.contains("remote host identification has changed") {
        "Neptune's SSH host key changed. Remove its old entry from known_hosts if this is expected.".into()
    } else if stderr.trim().is_empty() {
        "The SSH session ended without a result.".into()
    } else {
        format!("SSH error: {}", stderr.trim())
    };
    msg
}

/// Samples Neptune's load for a few seconds and waits for the result.
pub fn stats(s: &Settings, seconds: u32) -> Result<ServerSnapshot, String> {
    let mut r = spawn(s, &format!("stats --seconds {seconds} --interval 1"))?;
    let deadline = Instant::now() + Duration::from_secs(seconds as u64 + 15);
    let mut snap = ServerSnapshot::default();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match r.rx.recv_timeout(left) {
            Ok((_, line)) => absorb(&mut snap, &line),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => return Err("Neptune took too long to answer".into()),
        }
    }
    if snap.info.is_none() {
        return Err(r.error(s));
    }
    Ok(snap)
}

fn absorb(snap: &mut ServerSnapshot, line: &str) {
    match serde_json::from_str::<StatsLine>(line) {
        Ok(StatsLine::Info(i)) => snap.info = Some(i),
        Ok(StatsLine::Sample(x)) => snap.samples.push(x),
        Err(_) => {}
    }
}

/// Streams Neptune's load in the background while something else runs.
pub struct StatsStream {
    remote: Remote,
    lines: Vec<(Instant, String)>,
}

impl StatsStream {
    pub fn start(s: &Settings, max_seconds: u32) -> Result<Self, String> {
        let mut remote = spawn(s, &format!("stats --seconds {max_seconds} --interval 1"))?;
        // Wait for the info line so we know the session works.
        match remote.rx.recv_timeout(Duration::from_secs(15)) {
            Ok(first) => Ok(StatsStream { remote, lines: vec![first] }),
            Err(_) => Err(remote.error(s)),
        }
    }

    fn drain(&mut self) {
        while let Ok(l) = self.remote.rx.try_recv() {
            self.lines.push(l);
        }
    }

    /// Splits samples into those that arrived inside [from, to].
    pub fn window(&mut self, from: Instant, to: Instant) -> ServerSnapshot {
        self.drain();
        // A sample covers the second before it arrived. If the copy was shorter
        // than one sample, wait for the next sample and use that.
        let deadline = Instant::now() + Duration::from_millis(1500);
        loop {
            let mut snap = ServerSnapshot::default();
            let mut first_after: Option<netcheck_proto::ServerSample> = None;
            for (at, line) in &self.lines {
                match serde_json::from_str::<StatsLine>(line) {
                    Ok(StatsLine::Info(i)) => snap.info = Some(i),
                    Ok(StatsLine::Sample(x)) if *at > from => {
                        if *at <= to + Duration::from_millis(1200) {
                            snap.samples.push(x);
                        } else if first_after.is_none() {
                            first_after = Some(x);
                        }
                    }
                    _ => {}
                }
            }
            if !snap.samples.is_empty() {
                return snap;
            }
            if let Some(x) = first_after {
                snap.samples.push(x);
                return snap;
            }
            if Instant::now() >= deadline {
                return snap;
            }
            if let Ok(l) = self.remote.rx.recv_timeout(Duration::from_millis(300)) {
                self.lines.push(l);
            }
        }
    }

    pub fn stop(mut self) {
        let _ = self.remote.child.kill();
    }
}

/// A running throughput endpoint on Neptune.
pub struct ServeSession {
    remote: Remote,
}

impl ServeSession {
    pub fn start(s: &Settings, max_seconds: u32) -> Result<Self, String> {
        let mut remote = spawn(s, &format!("serve --port {} --max-seconds {max_seconds}", s.test_port))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match remote.rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok((_, l)) if l.starts_with(READY_LINE) => return Ok(ServeSession { remote }),
                Ok(_) => continue,
                Err(_) => return Err(remote.error(s)),
            }
        }
    }

    pub fn finish(self) -> Option<ServeReport> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last = None;
        loop {
            match self.remote.rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok((_, l)) => {
                    if let Ok(r) = serde_json::from_str::<ServeReport>(&l) {
                        last = Some(r);
                    }
                }
                Err(_) => break,
            }
        }
        last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_validation() {
        assert!(safe_path("/volume1/tools/tph-netcheck/tph-netcheck-server"));
        assert!(!safe_path("/x; rm -rf /"));
        assert!(!safe_path("/x $(id)"));
        assert!(!safe_path(""));
    }

    #[test]
    fn errors_are_plain() {
        let s = Settings { ssh_user: "netcheck".into(), ..Default::default() };
        assert!(friendly_error("netcheck@10.0.0.5: Permission denied (publickey).", &s).contains("refused the SSH key"));
        assert!(friendly_error("ssh: connect to host 10.0.0.5 port 22: Connection refused", &s).contains("SSH is enabled"));
    }
}
