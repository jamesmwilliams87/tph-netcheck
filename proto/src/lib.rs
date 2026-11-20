//! Types shared between the desktop app and the test server that runs on Neptune.

use serde::{Deserialize, Serialize};

/// Port the throughput server listens on by default.
pub const DEFAULT_PORT: u16 = 5201;

/// First byte sent on every throughput connection.
pub const MODE_DOWNLOAD: u8 = b'D'; // server sends, client receives
pub const MODE_UPLOAD: u8 = b'U'; // client sends, server receives
pub const MODE_QUIT: u8 = b'Q'; // ends the session

/// Line the server prints on stdout once it is listening.
pub const READY_LINE: &str = "TPH-NETCHECK-READY";

/// One snapshot of what the NAS is doing over a sample window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerSample {
    /// Seconds since the sampler started.
    pub t: f64,
    /// Whole-system CPU busy, 0 to 100.
    pub cpu_pct: f64,
    /// Busiest single core, 0 to 100. A single-threaded task can max one core
    /// while the total still looks low.
    pub busiest_core_pct: f64,
    /// Highest utilisation of any physical disk, 0 to 100.
    pub disk_util_max_pct: f64,
    /// Average utilisation across physical disks, 0 to 100.
    pub disk_util_avg_pct: f64,
    /// Bytes per second read from and written to disks in total.
    pub disk_read_bps: f64,
    pub disk_write_bps: f64,
    /// Bytes per second across network interfaces in total.
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    /// Heaviest processes during the window.
    pub top_processes: Vec<ProcessUse>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessUse {
    pub name: String,
    /// Percent of one core (can exceed 100 for multithreaded processes).
    pub cpu_pct: f64,
}

/// Static facts plus current state, sent once per stats run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerInfo {
    pub hostname: String,
    pub cores: usize,
    pub mem_total_mb: u64,
    pub mem_available_mb: u64,
    pub load_avg: [f64; 3],
    pub uptime_s: u64,
    pub interfaces: Vec<ServerInterface>,
    /// RAID activity read from /proc/mdstat (scrub, resync, rebuild).
    pub raid_activity: Vec<RaidActivity>,
    /// IP the client connected to, from SSH_CONNECTION, if known.
    pub connected_ip: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerInterface {
    pub name: String,
    pub ipv4: Vec<String>,
    /// Negotiated speed in Mb/s, None if down or unknown.
    pub speed_mbps: Option<u64>,
    pub mtu: Option<u32>,
    pub up: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RaidActivity {
    pub device: String,
    /// check, resync, recovery or reshape. On Synology, "check" is a data scrub.
    pub action: String,
    pub progress_pct: Option<f64>,
    pub finish: Option<String>,
}

/// A line of output from `stats`. The first line is Info, the rest are Samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatsLine {
    Info(ServerInfo),
    Sample(ServerSample),
}

/// Printed by `serve` when the session ends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServeReport {
    pub download: Option<PhaseReport>,
    pub upload: Option<PhaseReport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseReport {
    pub bytes: u64,
    pub seconds: f64,
    pub streams: u32,
    /// Average whole-system CPU during the phase.
    pub cpu_avg_pct: f64,
    /// Peak of the busiest core during the phase.
    pub busiest_core_peak_pct: f64,
}
