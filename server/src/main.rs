//! tph-netcheck-server
//!
//! Runs on the NAS. It is started on demand over SSH by the desktop app and
//! exits on its own. It never stays resident.
//!
//!   tph-netcheck-server stats [--seconds N] [--interval S]
//!   tph-netcheck-server serve [--port P] [--max-seconds N]
//!   tph-netcheck-server dispatch      (for an authorized_keys forced command)
//!   tph-netcheck-server version

mod procfs;
mod serve;

use std::io::Write;
use std::process::exit;
use std::time::{Duration, Instant};

use netcheck_proto::StatsLine;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("dispatch") {
        dispatch();
    }
    exit(run(&args));
}

/// Used as the forced command on the SSH key. Only the commands this program
/// knows are allowed through, so the key cannot open a shell on the NAS.
fn dispatch() -> ! {
    let original = std::env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
    let mut tokens: Vec<String> = original.split_whitespace().map(str::to_string).collect();
    if tokens
        .first()
        .map(|t| t.ends_with("tph-netcheck-server"))
        .unwrap_or(false)
    {
        tokens.remove(0);
    }
    match tokens.first().map(String::as_str) {
        Some("stats") | Some("serve") | Some("version") => exit(run(&tokens)),
        _ => {
            eprintln!("tph-netcheck-server: command not allowed");
            exit(2);
        }
    }
}

fn run(args: &[String]) -> i32 {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let opts = match parse_opts(&args.get(1..).unwrap_or(&[])) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("tph-netcheck-server: {e}");
            return 2;
        }
    };
    match cmd {
        "version" => {
            println!("tph-netcheck-server {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "stats" => {
            let seconds = opts.get("seconds").unwrap_or(3.0).clamp(0.5, 600.0);
            let interval = opts.get("interval").unwrap_or(1.0).clamp(0.25, 10.0);
            stats(seconds, interval);
            0
        }
        "serve" => {
            let port = opts.get("port").unwrap_or(netcheck_proto::DEFAULT_PORT as f64) as u16;
            let max = opts.get("max-seconds").unwrap_or(60.0).clamp(5.0, 300.0);
            match serve::serve(port, Duration::from_secs_f64(max)) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("tph-netcheck-server: serve failed: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("usage: tph-netcheck-server <stats|serve|version|dispatch> [options]");
            2
        }
    }
}

struct Opts(Vec<(String, f64)>);
impl Opts {
    fn get(&self, k: &str) -> Option<f64> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| *v)
    }
}

/// Only numeric --name value pairs from a fixed list are accepted.
fn parse_opts(args: &[String]) -> Result<Opts, String> {
    const ALLOWED: [&str; 4] = ["seconds", "interval", "port", "max-seconds"];
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let name = args[i]
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {}", args[i]))?;
        if !ALLOWED.contains(&name) {
            return Err(format!("unknown option --{name}"));
        }
        let val: f64 = args
            .get(i + 1)
            .ok_or_else(|| format!("--{name} needs a value"))?
            .parse()
            .map_err(|_| format!("--{name} must be a number"))?;
        if !val.is_finite() || val < 0.0 {
            return Err(format!("--{name} out of range"));
        }
        out.push((name.to_string(), val));
        i += 2;
    }
    Ok(Opts(out))
}

fn stats(seconds: f64, interval: f64) {
    let start = Instant::now();
    let mut out = std::io::stdout().lock();
    let info = procfs::server_info();
    let _ = writeln!(out, "{}", serde_json::to_string(&StatsLine::Info(info)).unwrap());
    let _ = out.flush();

    let mut prev = procfs::Snapshot::take();
    let mut elapsed = 0.0;
    while elapsed + 1e-6 < seconds {
        std::thread::sleep(Duration::from_secs_f64(interval));
        let now = procfs::Snapshot::take();
        let mut sample = procfs::compare(&prev, &now, true);
        sample.t = start.elapsed().as_secs_f64();
        if writeln!(out, "{}", serde_json::to_string(&StatsLine::Sample(sample)).unwrap()).is_err() {
            return; // client hung up
        }
        if out.flush().is_err() {
            return;
        }
        prev = now;
        elapsed += interval;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn opts_accept_known_numeric() {
        let o = parse_opts(&v(&["--seconds", "5", "--interval", "0.5"])).unwrap();
        assert_eq!(o.get("seconds"), Some(5.0));
        assert_eq!(o.get("interval"), Some(0.5));
    }

    #[test]
    fn opts_reject_unknown_and_injection() {
        assert!(parse_opts(&v(&["--seconds", "5;rm"])).is_err());
        assert!(parse_opts(&v(&["--evil", "1"])).is_err());
        assert!(parse_opts(&v(&["bash"])).is_err());
        assert!(parse_opts(&v(&["--port"])).is_err());
    }
}
