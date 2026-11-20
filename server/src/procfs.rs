//! Reads load figures from /proc and /sys. Parsing is kept in pure functions
//! so it can be tested against sample text.

use std::collections::HashMap;
use std::fs;
use std::time::Instant;

use netcheck_proto::{ProcessUse, RaidActivity, ServerInfo, ServerInterface, ServerSample};

#[derive(Clone, Default)]
pub struct CpuTimes {
    pub busy: u64,
    pub total: u64,
}

#[derive(Clone)]
pub struct Snapshot {
    pub at: Instant,
    pub cpu_all: CpuTimes,
    pub cpu_cores: Vec<CpuTimes>,
    /// name -> (sectors read, sectors written, io ticks ms)
    pub disks: HashMap<String, (u64, u64, u64)>,
    /// name -> (rx bytes, tx bytes)
    pub nets: HashMap<String, (u64, u64)>,
    /// pid -> (name, cpu ticks)
    pub procs: HashMap<u32, (String, u64)>,
}

impl Snapshot {
    pub fn take() -> Self {
        Self::take_with(true)
    }

    pub fn take_cpu_only() -> Self {
        Self::take_with(false)
    }

    fn take_with(full: bool) -> Self {
        let (cpu_all, cpu_cores) = parse_stat(&read("/proc/stat"));
        let (disks, nets, procs) = if full {
            (
                parse_diskstats(&read("/proc/diskstats")),
                parse_netdev(&read("/proc/net/dev")),
                read_procs(),
            )
        } else {
            Default::default()
        };
        Snapshot { at: Instant::now(), cpu_all, cpu_cores, disks, nets, procs }
    }
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn pct(busy: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (busy as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    }
}

fn delta(a: &CpuTimes, b: &CpuTimes) -> f64 {
    pct(b.busy.saturating_sub(a.busy), b.total.saturating_sub(a.total))
}

/// Builds a sample from two snapshots.
pub fn compare(a: &Snapshot, b: &Snapshot, full: bool) -> ServerSample {
    let secs = b.at.duration_since(a.at).as_secs_f64().max(0.001);
    let cpu_pct = delta(&a.cpu_all, &b.cpu_all);
    let busiest_core_pct = a
        .cpu_cores
        .iter()
        .zip(&b.cpu_cores)
        .map(|(x, y)| delta(x, y))
        .fold(0.0, f64::max);
    let mut s = ServerSample { cpu_pct, busiest_core_pct, ..Default::default() };
    if !full {
        return s;
    }

    let mut utils = Vec::new();
    let (mut rd, mut wr) = (0u64, 0u64);
    for (name, (r1, w1, t1)) in &b.disks {
        if let Some((r0, w0, t0)) = a.disks.get(name) {
            rd += r1.saturating_sub(*r0);
            wr += w1.saturating_sub(*w0);
            let busy_ms = t1.saturating_sub(*t0) as f64;
            utils.push((busy_ms / (secs * 1000.0) * 100.0).clamp(0.0, 100.0));
        }
    }
    s.disk_util_max_pct = utils.iter().cloned().fold(0.0, f64::max);
    s.disk_util_avg_pct = if utils.is_empty() { 0.0 } else { utils.iter().sum::<f64>() / utils.len() as f64 };
    s.disk_read_bps = rd as f64 * 512.0 / secs;
    s.disk_write_bps = wr as f64 * 512.0 / secs;

    let (mut rx, mut tx) = (0u64, 0u64);
    for (name, (r1, t1)) in &b.nets {
        if let Some((r0, t0)) = a.nets.get(name) {
            rx += r1.saturating_sub(*r0);
            tx += t1.saturating_sub(*t0);
        }
    }
    s.net_rx_bps = rx as f64 / secs;
    s.net_tx_bps = tx as f64 / secs;

    let hz = clock_ticks() as f64;
    let mut by_name: HashMap<String, f64> = HashMap::new();
    for (pid, (name, t1)) in &b.procs {
        if let Some((_, t0)) = a.procs.get(pid) {
            let used = t1.saturating_sub(*t0) as f64 / hz / secs * 100.0;
            if used > 0.0 {
                *by_name.entry(name.clone()).or_default() += used;
            }
        }
    }
    let mut top: Vec<ProcessUse> = by_name
        .into_iter()
        .filter(|(n, _)| n != "tph-netcheck-se") // ourselves (comm is truncated to 15 chars)
        .map(|(name, cpu_pct)| ProcessUse { name, cpu_pct })
        .collect();
    top.sort_by(|x, y| y.cpu_pct.partial_cmp(&x.cpu_pct).unwrap());
    top.truncate(6);
    s.top_processes = top;
    s
}

fn clock_ticks() -> i64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as i64;
    if v > 0 { v } else { 100 }
}

pub fn parse_stat(text: &str) -> (CpuTimes, Vec<CpuTimes>) {
    let mut all = CpuTimes::default();
    let mut cores = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(label) = it.next() else { continue };
        if !label.starts_with("cpu") {
            continue;
        }
        let nums: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
        if nums.len() < 4 {
            continue;
        }
        // user nice system idle iowait irq softirq steal (guest fields are inside user)
        let total: u64 = nums.iter().take(8).sum();
        let idle = nums[3] + nums.get(4).copied().unwrap_or(0);
        let t = CpuTimes { busy: total.saturating_sub(idle), total };
        if label == "cpu" {
            all = t;
        } else {
            cores.push(t);
        }
    }
    (all, cores)
}

pub fn is_physical_disk(name: &str) -> bool {
    let sd = name.strip_prefix("sd").map(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_lowercase()));
    let sata = name.strip_prefix("sata").map(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()));
    let nvme = name.starts_with("nvme") && name.contains('n') && !name.contains('p');
    sd == Some(true) || sata == Some(true) || nvme
}

pub fn parse_diskstats(text: &str) -> HashMap<String, (u64, u64, u64)> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 13 || !is_physical_disk(f[2]) {
            continue;
        }
        let n = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        out.insert(f[2].to_string(), (n(5), n(9), n(12)));
    }
    out
}

pub fn parse_netdev(text: &str) -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let name = name.trim();
        if name == "lo" {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() >= 9 {
            out.insert(name.to_string(), (f[0], f[8]));
        }
    }
    out
}

/// Returns (name, utime + stime) from the text of /proc/<pid>/stat.
pub fn parse_pid_stat(text: &str) -> Option<(String, u64)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let name = text[open + 1..close].to_string();
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    let utime: u64 = rest.get(11)?.parse().ok()?;
    let stime: u64 = rest.get(12)?.parse().ok()?;
    Some((name, utime + stime))
}

fn read_procs() -> HashMap<u32, (String, u64)> {
    let mut out = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else { return out };
    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        if let Ok(text) = fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(v) = parse_pid_stat(&text) {
                out.insert(pid, v);
            }
        }
    }
    out
}

pub fn parse_mdstat(text: &str) -> Vec<RaidActivity> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some((dev, _)) = line.split_once(" : ") {
            if dev.starts_with("md") {
                current = dev.trim().to_string();
            }
            continue;
        }
        for action in ["check", "resync", "recovery", "reshape"] {
            let key = format!("{action} =");
            if let Some(pos) = line.find(&key) {
                let after = &line[pos + key.len()..];
                let progress = after
                    .split('%')
                    .next()
                    .and_then(|x| x.trim().parse::<f64>().ok());
                let finish = line
                    .split_whitespace()
                    .find_map(|w| w.strip_prefix("finish="))
                    .map(str::to_string);
                out.push(RaidActivity {
                    device: current.clone(),
                    action: action.to_string(),
                    progress_pct: progress,
                    finish,
                });
            }
        }
    }
    out
}

pub fn parse_meminfo(text: &str) -> (u64, u64) {
    let get = |k: &str| {
        text.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let total = get("MemTotal:");
    let mut avail = get("MemAvailable:");
    if avail == 0 {
        avail = get("MemFree:") + get("Buffers:") + get("Cached:");
    }
    (total / 1024, avail / 1024)
}

pub fn server_info() -> ServerInfo {
    let (_, cores) = parse_stat(&read("/proc/stat"));
    let (mem_total_mb, mem_available_mb) = parse_meminfo(&read("/proc/meminfo"));
    let la: Vec<f64> = read("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect();
    let uptime_s = read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;
    let connected_ip = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|s| s.split_whitespace().nth(2).map(str::to_string));
    ServerInfo {
        hostname: read("/proc/sys/kernel/hostname").trim().to_string(),
        cores: cores.len(),
        mem_total_mb,
        mem_available_mb,
        load_avg: [la.first().copied().unwrap_or(0.0), la.get(1).copied().unwrap_or(0.0), la.get(2).copied().unwrap_or(0.0)],
        uptime_s,
        interfaces: interfaces(),
        raid_activity: parse_mdstat(&read("/proc/mdstat")),
        connected_ip,
    }
}

fn interfaces() -> Vec<ServerInterface> {
    let addrs = ipv4_addrs();
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/sys/class/net") else { return out };
    for e in dir.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == "lo" || name.starts_with("docker") || name.starts_with("veth") {
            continue;
        }
        let base = format!("/sys/class/net/{name}");
        let up = read(&format!("{base}/operstate")).trim() == "up";
        let speed_mbps = read(&format!("{base}/speed"))
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|v| *v > 0)
            .map(|v| v as u64);
        let mtu = read(&format!("{base}/mtu")).trim().parse().ok();
        out.push(ServerInterface {
            ipv4: addrs.get(&name).cloned().unwrap_or_default(),
            name,
            speed_mbps,
            mtu,
            up,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn ipv4_addrs() -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    // SAFETY: standard getifaddrs/freeifaddrs pattern; pointers are only read
    // while the list is alive and null checks guard every dereference.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
                out.entry(name).or_default().push(ip.to_string());
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parses_total_and_cores() {
        let t = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0 0 0\ncpu1 50 0 50 350 50 0 0 0 0 0\nintr 1\n";
        let (all, cores) = parse_stat(t);
        assert_eq!(all.total, 1000);
        assert_eq!(all.busy, 200);
        assert_eq!(cores.len(), 2);
    }

    #[test]
    fn disk_filter() {
        assert!(is_physical_disk("sda"));
        assert!(is_physical_disk("sdab"));
        assert!(is_physical_disk("sata1"));
        assert!(!is_physical_disk("sda1"));
        assert!(!is_physical_disk("md2"));
        assert!(!is_physical_disk("sata1p3"));
        assert!(!is_physical_disk("loop0"));
    }

    #[test]
    fn diskstats_fields() {
        let t = "   8       0 sda 1000 0 2000 10 500 0 4000 20 0 300 30\n   8       1 sda1 1 0 2 0 0 0 0 0 0 0 0\n";
        let d = parse_diskstats(t);
        assert_eq!(d.len(), 1);
        assert_eq!(d["sda"], (2000, 4000, 300));
    }

    #[test]
    fn netdev_fields() {
        let t = "Inter-|   Receive\n face |bytes\n    lo: 5 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        let n = parse_netdev(t);
        assert_eq!(n.len(), 1);
        assert_eq!(n["eth0"], (1000, 2000));
    }

    #[test]
    fn pid_stat_with_spaces_in_name() {
        let t = "1234 (smb d) S 1 1 1 0 -1 4194560 100 0 0 0 70 30 0 0 20 0 1 0 100 0 0";
        assert_eq!(parse_pid_stat(t), Some(("smb d".to_string(), 100)));
    }

    #[test]
    fn mdstat_scrub() {
        let t = "Personalities : [raid10]\nmd2 : active raid10 sda5[0] sdb5[1]\n      23 blocks super 1.2\n      [==>..................]  check = 12.5% (1/8) finish=320.4min speed=150000K/sec\n\nmd0 : active raid1 sda1[0]\n";
        let a = parse_mdstat(t);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].device, "md2");
        assert_eq!(a[0].action, "check");
        assert_eq!(a[0].progress_pct, Some(12.5));
        assert_eq!(a[0].finish.as_deref(), Some("320.4min"));
    }

    #[test]
    fn meminfo() {
        let t = "MemTotal:        4096000 kB\nMemFree:          100000 kB\nMemAvailable:    2048000 kB\n";
        assert_eq!(parse_meminfo(t), (4000, 2000));
    }
}
