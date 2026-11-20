use netcheck_proto::{ServeReport, ServerInfo, ServerSample};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Good,
    Info,
    Warn,
    Bad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// Short label for where the problem sits: "Your link", "Neptune", ...
    pub area: String,
    pub title: String,
    pub detail: String,
}

impl Finding {
    pub fn new(severity: Severity, area: &str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Finding { severity, area: area.into(), title: title.into(), detail: detail.into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Ok,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepStatus {
    pub id: String,
    pub label: String,
    pub state: StepState,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Wired,
    Wifi,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    pub iface: String,
    pub description: String,
    pub kind: LinkKind,
    pub speed_mbps: Option<u64>,
    pub mtu: Option<u32>,
    pub local_ip: Option<String>,
    pub prefix_len: Option<u8>,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PingResult {
    pub label: String,
    pub target: String,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumboResult {
    pub local_mtu: u32,
    pub payload: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub info: Option<ServerInfo>,
    pub samples: Vec<ServerSample>,
}

impl ServerSnapshot {
    pub fn avg(&self, f: impl Fn(&ServerSample) -> f64) -> Option<f64> {
        if self.samples.is_empty() {
            None
        } else {
            Some(self.samples.iter().map(&f).sum::<f64>() / self.samples.len() as f64)
        }
    }
    pub fn peak(&self, f: impl Fn(&ServerSample) -> f64) -> Option<f64> {
        self.samples.iter().map(f).reduce(f64::max)
    }
    /// Combined top processes across samples, averaged.
    pub fn top_processes(&self) -> Vec<(String, f64)> {
        let mut acc: std::collections::BTreeMap<String, f64> = Default::default();
        for s in &self.samples {
            for p in &s.top_processes {
                *acc.entry(p.name.clone()).or_default() += p.cpu_pct;
            }
        }
        let n = self.samples.len().max(1) as f64;
        let mut v: Vec<(String, f64)> = acc.into_iter().map(|(k, x)| (k, x / n)).collect();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        v
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThroughputResult {
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub streams: u32,
    pub server: Option<ServeReport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmbResult {
    pub path: String,
    pub write_mb_s: Option<f64>,
    pub read_mb_s: Option<f64>,
    pub write_mb: u64,
    pub read_mb: u64,
    /// True if Neptune may have served the read from its own memory,
    /// which makes the read figure look better than the disks can do.
    pub read_maybe_cached: bool,
    pub server_during_write: ServerSnapshot,
    pub server_during_read: ServerSnapshot,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortInfo {
    pub idx: u32,
    pub name: String,
    pub up: bool,
    pub speed_mbps: Option<u64>,
    pub full_duplex: Option<bool>,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_broadcast: u64,
    pub tx_broadcast: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate_bps: Option<f64>,
    pub tx_rate_bps: Option<f64>,
    pub stp_state: Option<String>,
    pub is_uplink: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwitchInfo {
    pub name: String,
    pub model: String,
    pub mac: String,
    pub ip: String,
    pub ports: Vec<PortInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientInfo {
    pub mac: String,
    pub ip: String,
    pub name: String,
    pub sw_mac: Option<String>,
    pub sw_port: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortDelta {
    pub switch: String,
    pub port: u32,
    pub port_name: String,
    pub errors: u64,
    pub drops: u64,
    pub broadcast_pps: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortRef {
    pub switch: String,
    pub port: u32,
    pub port_name: String,
    pub speed_mbps: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnifiResult {
    pub switches: Vec<SwitchInfo>,
    pub clients: Vec<ClientInfo>,
    pub interval_s: f64,
    pub deltas: Vec<PortDelta>,
    pub this_machine_port: Option<PortRef>,
    pub neptune_port: Option<PortRef>,
    pub loop_events: Vec<String>,
    /// Ports already running above 70% of their speed before testing began.
    pub busy_before: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub started_at_ms: u64,
    pub duration_s: f64,
    pub machine: String,
    pub os: String,
    pub app_version: String,
    pub steps: Vec<StepStatus>,
    pub link: Option<LinkInfo>,
    pub neptune_ip: Option<String>,
    pub pings: Vec<PingResult>,
    pub jumbo: Option<JumboResult>,
    pub server_before: Option<ServerSnapshot>,
    pub throughput: Option<ThroughputResult>,
    pub smb: Option<SmbResult>,
    pub unifi: Option<UnifiResult>,
    pub findings: Vec<Finding>,
    pub headline: Finding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDevice {
    pub ip: String,
    pub mac: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub subnet: String,
    pub scanned: u32,
    pub devices: Vec<ScanDevice>,
    pub findings: Vec<Finding>,
}
