//! Runs every check in order and builds the report.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::report::*;
use crate::settings::Settings;
use crate::{link, ping, smb, ssh, sys, throughput, unifi, verdict};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Step { id: String, label: String, state: String, note: String },
}

pub const STEPS: [(&str, &str); 7] = [
    ("link", "Your connection"),
    ("neptune", "Neptune's current load"),
    ("path", "Ping and latency"),
    ("switches", "UniFi switches"),
    ("jumbo", "Jumbo frames"),
    ("speed", "Network speed test"),
    ("files", "File transfer test"),
];

struct Steps<'a> {
    emit: &'a (dyn Fn(Event) + Sync),
    done: Mutex<Vec<StepStatus>>,
}

impl Steps<'_> {
    fn label(id: &str) -> String {
        STEPS.iter().find(|(i, _)| *i == id).map(|(_, l)| l.to_string()).unwrap_or_else(|| id.to_string())
    }
    fn start(&self, id: &str) {
        (self.emit)(Event::Step { id: id.into(), label: Self::label(id), state: "running".into(), note: String::new() });
    }
    fn finish(&self, id: &str, state: StepState, note: impl Into<String>) {
        let note = note.into();
        let st = match state {
            StepState::Ok => "ok",
            StepState::Failed => "failed",
            StepState::Skipped => "skipped",
        };
        (self.emit)(Event::Step { id: id.into(), label: Self::label(id), state: st.into(), note: note.clone() });
        self.done.lock().unwrap().push(StepStatus { id: id.into(), label: Self::label(id), state, note });
    }
    fn result<T>(&self, id: &str, r: Result<T, String>, ok_note: impl Fn(&T) -> String) -> Option<T> {
        match r {
            Ok(v) => {
                self.finish(id, StepState::Ok, ok_note(&v));
                Some(v)
            }
            Err(e) => {
                self.finish(id, StepState::Failed, e);
                None
            }
        }
    }
}

pub fn diagnose(s: &Settings, emit: &(dyn Fn(Event) + Sync)) -> Report {
    let t0 = Instant::now();
    let started_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let steps = Steps { emit, done: Mutex::new(Vec::new()) };

    // 1. This machine's link
    steps.start("link");
    let neptune_ip = sys::resolve_ipv4(&s.neptune_host);
    let link = match &neptune_ip {
        None if s.neptune_host.is_empty() => {
            steps.finish("link", StepState::Failed, "Neptune's address is not set in Settings");
            None
        }
        None => {
            steps.finish("link", StepState::Failed, format!("Could not find Neptune on the network as '{}'. Try its IP address in Settings.", s.neptune_host));
            None
        }
        Some(ip) => steps.result("link", link::detect(ip), |l| {
            format!("{} at {}", l.iface, l.speed_mbps.map(verdict::speed_label).unwrap_or("unknown speed".into()))
        }),
    };

    // 2. In parallel: Neptune's load, pings, first switch snapshot
    let (server_before, pings, uni) = std::thread::scope(|sc| {
        let h_server = sc.spawn(|| {
            steps.start("neptune");
            if !s.ssh_ready() {
                steps.finish("neptune", StepState::Skipped, "SSH to Neptune is not set up");
                return None;
            }
            steps.result("neptune", ssh::stats(s, 3), |x: &ServerSnapshot| {
                format!("CPU {:.0}%, disks {:.0}% busy", x.avg(|v| v.cpu_pct).unwrap_or(0.0), x.avg(|v| v.disk_util_max_pct).unwrap_or(0.0))
            })
        });
        let h_ping = sc.spawn(|| {
            steps.start("path");
            let mut targets: Vec<(String, String)> = Vec::new();
            if let Some(ip) = &neptune_ip {
                targets.push(("Neptune".into(), ip.clone()));
            }
            if let Some(gw) = link.as_ref().and_then(|l| l.gateway.clone()) {
                targets.push(("Building router".into(), gw));
            }
            if !s.internet_target.is_empty() {
                targets.push(("Internet".into(), s.internet_target.clone()));
            }
            let res: Vec<PingResult> = std::thread::scope(|sc2| {
                let hs: Vec<_> = targets.iter().map(|(l, t)| sc2.spawn(move || ping::ping(l, t, 10))).collect();
                hs.into_iter().filter_map(|h| h.join().ok()).collect()
            });
            let note = res.iter().map(|p| format!("{} {}", p.label, p.avg_ms.map(|a| format!("{a:.2} ms")).unwrap_or("no reply".into()))).collect::<Vec<_>>().join(", ");
            steps.finish("path", if res.is_empty() { StepState::Failed } else { StepState::Ok }, note);
            res
        });
        let h_uni = sc.spawn(|| {
            steps.start("switches");
            if !s.unifi_ready() {
                steps.finish("switches", StepState::Skipped, "UniFi controller is not set up");
                return None;
            }
            let r = unifi::Unifi::login(s).and_then(|c| c.snapshot().map(|snap| (c, snap)));
            steps.result("switches", r, |(_, snap)| {
                let ports: usize = snap.switches.iter().map(|x| x.ports.len()).sum();
                format!("{} switch(es), {} ports read", snap.switches.len(), ports)
            })
        });
        (h_server.join().unwrap_or(None), h_ping.join().unwrap_or_default(), h_uni.join().unwrap_or(None))
    });

    // 3. Jumbo frames
    steps.start("jumbo");
    let jumbo = match (&link, &neptune_ip) {
        (Some(l), Some(ip)) => match l.mtu {
            Some(m) if m > 1500 => {
                // Jumbo frames top out at 9000 on this kit; larger MTUs are loopback or virtual.
                let payload = m.min(9000) - 28;
                let passed = ping::dont_fragment(ip, payload);
                steps.finish("jumbo", if passed { StepState::Ok } else { StepState::Failed }, if passed { format!("{}-byte frames reach Neptune", payload + 28) } else { format!("{}-byte frames do not reach Neptune", payload + 28) });
                Some(JumboResult { local_mtu: m, payload, passed })
            }
            _ => {
                steps.finish("jumbo", StepState::Ok, "Standard 1500 MTU, nothing to check");
                None
            }
        },
        _ => {
            steps.finish("jumbo", StepState::Skipped, "Needs the connection details");
            None
        }
    };

    // 4. Raw network speed
    steps.start("speed");
    let tput = match (&neptune_ip, s.ssh_ready()) {
        (Some(ip), true) => {
            let secs = s.throughput_seconds.clamp(3, 30);
            let streams = s.throughput_streams.clamp(1, 16);
            let r = ssh::ServeSession::start(s, secs * 2 + 25).and_then(|session| {
                let addr: SocketAddr = format!("{ip}:{}", s.test_port).parse().map_err(|_| "bad address".to_string())?;
                let down = throughput::download(addr, secs, streams);
                let up = throughput::upload(addr, secs, streams);
                throughput::quit(addr);
                let server = session.finish();
                if down.is_err() && up.is_err() {
                    return Err(down.err().unwrap());
                }
                // The server's own count of received bytes is the most accurate upload figure.
                let up_server = server.as_ref().and_then(|x| x.upload.as_ref()).filter(|p| p.bytes > 0).map(|p| p.bytes as f64 * 8.0 / p.seconds / 1e6);
                Ok(ThroughputResult { download_mbps: down.ok(), upload_mbps: up_server.or(up.ok()), streams, server })
            });
            steps.result("speed", r, |t| {
                format!(
                    "{} from Neptune, {} to Neptune",
                    t.download_mbps.map(|x| format!("{:.2} Gb/s", x / 1000.0)).unwrap_or("n/a".into()),
                    t.upload_mbps.map(|x| format!("{:.2} Gb/s", x / 1000.0)).unwrap_or("n/a".into())
                )
            })
        }
        _ => {
            steps.finish("speed", StepState::Skipped, "SSH to Neptune is not set up");
            None
        }
    };

    // 5. File transfer
    steps.start("files");
    let smb_res = smb::check_dir(&s.smb_test_dir).and_then(|dir| {
        let plan = smb::plan(&dir, &sys::hostname());
        let mut stream = if s.ssh_ready() { ssh::StatsStream::start(s, 300).ok() } else { None };
        let w = smb::write_test(&plan.write_path, s.smb_test_size_mb.clamp(256, 16384));
        let rd = w.as_ref().ok().and_then(|_| smb::read_test(&plan.read_path).ok());
        let w = w?;
        let (during_w, during_r) = match stream.as_mut() {
            Some(st) => (st.window(w.start, w.end), rd.as_ref().map(|r| st.window(r.start, r.end)).unwrap_or_default()),
            None => Default::default(),
        };
        if let Some(st) = stream {
            st.stop();
        }
        Ok(SmbResult {
            path: dir.display().to_string(),
            write_mb_s: Some(w.mb_s),
            read_mb_s: rd.as_ref().map(|r| r.mb_s),
            write_mb: w.mb,
            read_mb: rd.as_ref().map(|r| r.mb).unwrap_or(0),
            read_maybe_cached: plan.read_maybe_cached,
            server_during_write: during_w,
            server_during_read: during_r,
        })
    });
    let smb_res = steps.result("files", smb_res, |x| format!("write {:.0} MB/s, read {}", x.write_mb_s.unwrap_or(0.0), x.read_mb_s.map(|r| format!("{r:.0} MB/s")).unwrap_or("failed".into())));

    // 6. Second switch snapshot for error and broadcast counters
    let unifi_res = uni.and_then(|(client, first)| {
        let second = client.snapshot().ok()?;
        let events = client.loop_events();
        Some(unifi::compare(&first, &second, link.as_ref().and_then(|l| l.local_ip.as_deref()), neptune_ip.as_deref(), events))
    });

    let steps_done = steps.done.into_inner().unwrap();
    let mut report = Report {
        id: started_at_ms.to_string(),
        started_at_ms,
        duration_s: 0.0,
        machine: sys::hostname(),
        os: sys::os_name(),
        app_version: env!("CARGO_PKG_VERSION").into(),
        steps: steps_done,
        link,
        neptune_ip,
        pings,
        jumbo,
        server_before,
        throughput: tput,
        smb: smb_res,
        unifi: unifi_res,
        findings: vec![],
        headline: Finding::new(Severity::Info, "", "", ""),
    };
    report.findings = verdict::analyse(&report, s);
    report.headline = verdict::headline(&report.findings, &report.steps);
    report.duration_s = t0.elapsed().as_secs_f64();
    report
}
