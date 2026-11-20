//! Reads switch ports, connected clients and loop events from the UniFi
//! Network controller. Read-only: this module never sends a change.
//!
//! Supports the self-hosted UniFi Network application (login at /api/login)
//! and UniFi OS consoles (login at /api/auth/login, API under /proxy/network).

use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::{json, Value};

use crate::report::{ClientInfo, PortDelta, PortInfo, PortRef, SwitchInfo, UnifiResult};
use crate::settings::Settings;

pub struct Unifi {
    http: Client,
    base: String,
    prefix: &'static str,
    site: String,
}

pub struct Snapshot {
    pub at: Instant,
    pub switches: Vec<SwitchInfo>,
    pub clients: Vec<ClientInfo>,
}

impl Unifi {
    pub fn login(s: &Settings) -> Result<Self, String> {
        let http = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(s.unifi_insecure_tls)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        let base = s.unifi_url.trim_end_matches('/').to_string();
        let body = json!({ "username": s.unifi_user, "password": s.unifi_password, "remember": false });

        let classic = http.post(format!("{base}/api/login")).json(&body).send();
        match classic {
            Ok(r) if r.status().is_success() => {
                return Ok(Unifi { http, base, prefix: "", site: s.unifi_site.clone() });
            }
            Ok(r) if r.status().as_u16() == 400 || r.status().as_u16() == 401 => {
                return Err("The UniFi controller rejected the username or password".into());
            }
            Err(e) if e.is_connect() || e.is_timeout() => {
                return Err(format!("Could not reach the UniFi controller at {base}. Is the laptop on?"));
            }
            _ => {}
        }
        let os = http
            .post(format!("{base}/api/auth/login"))
            .json(&body)
            .send()
            .map_err(|e| format!("UniFi login failed: {e}"))?;
        if os.status().is_success() {
            Ok(Unifi { http, base, prefix: "/proxy/network", site: s.unifi_site.clone() })
        } else {
            Err(format!("UniFi login failed ({})", os.status()))
        }
    }

    fn get(&self, path: &str) -> Result<Vec<Value>, String> {
        let url = format!("{}{}/api/s/{}/{}", self.base, self.prefix, self.site, path);
        let v: Value = self
            .http
            .get(url)
            .send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("UniFi request failed: {e}"))?
            .json()
            .map_err(|e| format!("UniFi sent something unexpected: {e}"))?;
        Ok(v.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default())
    }

    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let devices = self.get("stat/device")?;
        let clients = self.get("stat/sta").unwrap_or_default();
        Ok(Snapshot { at: Instant::now(), switches: parse_switches(&devices), clients: parse_clients(&clients) })
    }

    /// Loop and STP related events from the last day.
    pub fn loop_events(&self) -> Vec<String> {
        let mut out = Vec::new();
        for path in ["stat/event?within=24&_limit=300", "list/alarm"] {
            if let Ok(items) = self.get(path) {
                out.extend(loop_messages(&items));
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64().or_else(|| x.as_f64().map(|f| f as u64))).unwrap_or(0)
}
fn st(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

pub fn parse_switches(devices: &[Value]) -> Vec<SwitchInfo> {
    devices
        .iter()
        .filter(|d| st(d, "type") == "usw" || d.get("port_table").is_some())
        .map(|d| {
            let ports = d
                .get("port_table")
                .and_then(|p| p.as_array())
                .map(|arr| arr.iter().map(parse_port).collect())
                .unwrap_or_default();
            let name = Some(st(d, "name")).filter(|n| !n.is_empty()).unwrap_or_else(|| st(d, "model"));
            SwitchInfo { name, model: st(d, "model"), mac: st(d, "mac").to_lowercase(), ip: st(d, "ip"), ports }
        })
        .collect()
}

fn parse_port(p: &Value) -> PortInfo {
    let rate = |k: &str| p.get(k).and_then(|x| x.as_f64());
    PortInfo {
        idx: u(p, "port_idx") as u32,
        name: st(p, "name"),
        up: p.get("up").and_then(|x| x.as_bool()).unwrap_or(false),
        speed_mbps: p.get("speed").and_then(|x| x.as_u64()).filter(|x| *x > 0),
        full_duplex: p.get("full_duplex").and_then(|x| x.as_bool()),
        rx_errors: u(p, "rx_errors"),
        tx_errors: u(p, "tx_errors"),
        rx_dropped: u(p, "rx_dropped"),
        tx_dropped: u(p, "tx_dropped"),
        rx_broadcast: u(p, "rx_broadcast"),
        tx_broadcast: u(p, "tx_broadcast"),
        rx_bytes: u(p, "rx_bytes"),
        tx_bytes: u(p, "tx_bytes"),
        rx_rate_bps: rate("rx_bytes-r").map(|b| b * 8.0),
        tx_rate_bps: rate("tx_bytes-r").map(|b| b * 8.0),
        stp_state: p.get("stp_state").and_then(|x| x.as_str()).map(str::to_string),
        is_uplink: p.get("is_uplink").and_then(|x| x.as_bool()).unwrap_or(false),
    }
}

pub fn parse_clients(items: &[Value]) -> Vec<ClientInfo> {
    items
        .iter()
        .map(|c| {
            let name = [st(c, "name"), st(c, "hostname")].into_iter().find(|n| !n.is_empty()).unwrap_or_default();
            ClientInfo {
                mac: st(c, "mac").to_lowercase(),
                ip: st(c, "ip"),
                name,
                sw_mac: c.get("sw_mac").and_then(|x| x.as_str()).map(|s| s.to_lowercase()),
                sw_port: c.get("sw_port").and_then(|x| x.as_u64()).map(|x| x as u32),
            }
        })
        .collect()
}

pub fn loop_messages(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|e| {
            let key = st(e, "key").to_lowercase();
            let msg = st(e, "msg");
            let lower = msg.to_lowercase();
            (key.contains("loop") || lower.contains("loop") || lower.contains("stp") || lower.contains("spanning tree"))
                .then(|| if msg.is_empty() { key } else { msg })
        })
        .collect()
}

/// Compares two snapshots and locates this machine and Neptune on the switches.
pub fn compare(a: &Snapshot, b: &Snapshot, my_ip: Option<&str>, neptune_ip: Option<&str>, loop_events: Vec<String>) -> UnifiResult {
    let secs = b.at.duration_since(a.at).as_secs_f64().max(0.001);
    let mut deltas = Vec::new();
    for sw in &b.switches {
        let Some(prev) = a.switches.iter().find(|x| x.mac == sw.mac) else { continue };
        for p in &sw.ports {
            let Some(q) = prev.ports.iter().find(|x| x.idx == p.idx) else { continue };
            let errors = (p.rx_errors + p.tx_errors).saturating_sub(q.rx_errors + q.tx_errors);
            let drops = (p.rx_dropped + p.tx_dropped).saturating_sub(q.rx_dropped + q.tx_dropped);
            let bcast = (p.rx_broadcast).saturating_sub(q.rx_broadcast) as f64 / secs;
            deltas.push(PortDelta { switch: sw.name.clone(), port: p.idx, port_name: p.name.clone(), errors, drops, broadcast_pps: bcast });
        }
    }
    let locate = |ip: Option<&str>| -> Option<PortRef> {
        let ip = ip?;
        let c = b.clients.iter().find(|c| c.ip == ip)?;
        let sw = b.switches.iter().find(|s| Some(&s.mac) == c.sw_mac.as_ref())?;
        let port = sw.ports.iter().find(|p| Some(p.idx) == c.sw_port)?;
        Some(PortRef { switch: sw.name.clone(), port: port.idx, port_name: port.name.clone(), speed_mbps: port.speed_mbps })
    };
    let mut busy_before = Vec::new();
    for sw in &a.switches {
        for p in &sw.ports {
            let (Some(speed), Some(rx), Some(tx)) = (p.speed_mbps, p.rx_rate_bps, p.tx_rate_bps) else { continue };
            let peak = rx.max(tx) / 1e6;
            if p.up && peak > 0.7 * speed as f64 {
                let label = if p.name.is_empty() { format!("port {}", p.idx) } else { format!("port {} ({})", p.idx, p.name) };
                busy_before.push(format!("{} {} at {:.1} Gb/s", sw.name, label, peak / 1000.0));
            }
        }
    }
    UnifiResult {
        busy_before,
        switches: b.switches.clone(),
        clients: b.clients.clone(),
        interval_s: secs,
        deltas,
        this_machine_port: locate(my_ip),
        neptune_port: locate(neptune_ip),
        loop_events,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(errors: u64, bcast: u64) -> Vec<Value> {
        vec![json!({
            "type": "usw", "name": "Flex B", "model": "USWFLEXXG", "mac": "AA:BB:CC:00:00:02", "ip": "192.168.10.3",
            "port_table": [
                {"port_idx": 1, "name": "Port 1", "up": true, "speed": 10000, "full_duplex": true,
                 "rx_errors": errors, "tx_errors": 0, "rx_broadcast": bcast, "rx_bytes-r": 1250000.0, "stp_state": "forwarding"},
                {"port_idx": 2, "name": "Neptune", "up": true, "speed": 1000, "rx_errors": 0, "tx_errors": 0}
            ]
        }), json!({"type": "uap", "name": "AP"})]
    }

    #[test]
    fn parses_and_compares() {
        let clients = parse_clients(&[json!({"mac": "11:22:33:44:55:66", "ip": "192.168.10.5", "hostname": "Neptune", "sw_mac": "aa:bb:cc:00:00:02", "sw_port": 2})]);
        let a = Snapshot { at: Instant::now(), switches: parse_switches(&sample(10, 1000)), clients: clients.clone() };
        let b = Snapshot { at: a.at + Duration::from_secs(10), switches: parse_switches(&sample(15, 31000)), clients };
        assert_eq!(a.switches.len(), 1);
        assert_eq!(a.switches[0].ports[0].rx_rate_bps, Some(10_000_000.0));
        let r = compare(&a, &b, None, Some("192.168.10.5"), vec![]);
        let d = &r.deltas[0];
        assert_eq!(d.errors, 5);
        assert!((d.broadcast_pps - 3000.0).abs() < 1.0);
        let np = r.neptune_port.unwrap();
        assert_eq!(np.port, 2);
        assert_eq!(np.speed_mbps, Some(1000));
    }

    #[test]
    fn finds_loop_events() {
        let ev = vec![json!({"key": "EVT_SW_Loop", "msg": "Switch Flex B detected a loop on port 4"}), json!({"key": "EVT_LU_Connected", "msg": "User connected"})];
        assert_eq!(loop_messages(&ev).len(), 1);
    }
}
