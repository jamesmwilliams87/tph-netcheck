//! Turns test results into plain findings and a headline.
//!
//! The order of reasoning matches how a person would check by hand: is this
//! machine connected properly, is Neptune connected properly, is anything
//! wrong on the switches, does the network carry full speed, and finally does
//! file sharing get close to what the network can carry. When something is
//! slow, the evidence collected on Neptune at the same moment says whether
//! the network, Neptune's processor or Neptune's disks are to blame.

use crate::report::*;
use crate::settings::Settings;

pub fn speed_label(mbps: u64) -> String {
    if mbps >= 1000 {
        let g = mbps as f64 / 1000.0;
        if (g - g.round()).abs() < 0.05 { format!("{:.0} Gb/s", g) } else { format!("{:.1} Gb/s", g) }
    } else {
        format!("{mbps} Mb/s")
    }
}

fn rate_label(mbps: f64) -> String {
    if mbps >= 1000.0 { format!("{:.2} Gb/s", mbps / 1000.0) } else { format!("{:.0} Mb/s", mbps) }
}

/// Adds a plain description to process names we can identify with confidence.
pub fn describe_process(name: &str) -> String {
    let n = name.to_lowercase();
    let what = if n == "smbd" {
        Some("file sharing")
    } else if n == "afpd" {
        Some("Mac file sharing (AFP)")
    } else if n.contains("synoindex") {
        Some("media indexing")
    } else if n.contains("thumb") {
        Some("thumbnail generation")
    } else if n.contains("cloudsync") || n.contains("cloud-sync") || n.contains("cloud_sync") {
        Some("Cloud Sync")
    } else if n.contains("backup") {
        Some("a backup task")
    } else if n == "rsync" {
        Some("a copy or backup over rsync")
    } else if n.starts_with("btrfs") {
        Some("Btrfs maintenance")
    } else if n.starts_with("md") && (n.contains("raid") || n.contains("resync")) {
        Some("RAID")
    } else if n.starts_with("kworker") {
        Some("kernel disk work")
    } else if n == "synoscgi" {
        Some("the DSM web interface")
    } else if n.starts_with("postgres") {
        Some("DSM's database")
    } else {
        None
    };
    match what {
        Some(w) => format!("{name} ({w})"),
        None => name.to_string(),
    }
}

fn top_list(snap: &ServerSnapshot, n: usize) -> String {
    let v: Vec<String> = snap
        .top_processes()
        .into_iter()
        .filter(|(_, c)| *c >= 5.0)
        .take(n)
        .map(|(name, c)| format!("{} {:.0}%", describe_process(&name), c))
        .collect();
    if v.is_empty() { String::new() } else { format!(" Busiest processes: {}.", v.join(", ")) }
}

fn neptune_iface<'a>(r: &'a Report) -> Option<&'a netcheck_proto::ServerInterface> {
    let info = r.server_before.as_ref()?.info.as_ref()?;
    let ip = r.neptune_ip.as_deref().or(info.connected_ip.as_deref())?;
    info.interfaces.iter().find(|i| i.ipv4.iter().any(|a| a == ip))
}

fn port_label(p: &PortRef) -> String {
    if p.port_name.is_empty() || p.port_name.starts_with("Port ") {
        format!("{} port {}", p.switch, p.port)
    } else {
        format!("{} port {} ({})", p.switch, p.port, p.port_name)
    }
}

pub fn analyse(r: &Report, s: &Settings) -> Vec<Finding> {
    let mut f: Vec<Finding> = Vec::new();
    let expected = s.expected_link_mbps.max(100);

    // ---------- This machine's link ----------
    let mut my_link_slow = false;
    match &r.link {
        None => f.push(Finding::new(Severity::Warn, "Your connection", "Could not read this machine's connection", "The adapter details were not available, so link speed was not checked.")),
        Some(l) if l.kind == LinkKind::Wifi => {
            my_link_slow = true;
            f.push(Finding::new(
                Severity::Bad,
                "Your connection",
                "You are reaching Neptune over Wi-Fi",
                format!("Traffic to Neptune is going out through {} ({}). Wi-Fi tops out far below the 10 Gb wired network. Plug into the wired network, or turn Wi-Fi off while working from Neptune.", l.iface, l.description),
            ));
        }
        Some(l) => match l.speed_mbps {
            Some(sp) if sp < expected => {
                my_link_slow = true;
                let switch_note = r
                    .unifi
                    .as_ref()
                    .and_then(|u| u.this_machine_port.as_ref())
                    .map(|p| format!(" The switch agrees: {} shows {}.", port_label(p), p.speed_mbps.map(speed_label).unwrap_or("no speed".into())))
                    .unwrap_or_default();
                f.push(Finding::new(
                    Severity::Bad,
                    "Your connection",
                    format!("This machine is linked at {}, not {}", speed_label(sp), speed_label(expected)),
                    format!(
                        "{} ({}) negotiated a slower speed. The usual causes are a damaged or low-grade cable, a loose plug, or the switch port. Reseat both ends, then try a known good Cat6a cable.{}",
                        l.iface, l.description, switch_note
                    ),
                ));
            }
            Some(sp) => f.push(Finding::new(Severity::Good, "Your connection", format!("Linked at {}", speed_label(sp)), format!("{} ({}), MTU {}.", l.iface, l.description, l.mtu.map(|m| m.to_string()).unwrap_or("unknown".into())))),
            None => f.push(Finding::new(Severity::Info, "Your connection", "Link speed not reported", format!("{} did not report a negotiated speed.", l.iface))),
        },
    }

    // ---------- Neptune's link ----------
    let nif = neptune_iface(r);
    let mut neptune_link_slow = false;
    if let Some(i) = nif {
        if let Some(sp) = i.speed_mbps {
            if sp < expected {
                neptune_link_slow = true;
                f.push(Finding::new(
                    Severity::Bad,
                    "Neptune",
                    format!("Neptune is linked at {}, not {}", speed_label(sp), speed_label(expected)),
                    format!("Neptune's {} negotiated a slower speed, which caps everyone. Check the cable and the port on Flex B.", i.name),
                ));
            }
        }
    }

    // ---------- Switches ----------
    if let Some(u) = &r.unifi {
        if !u.loop_events.is_empty() {
            let list = u.loop_events.iter().take(3).cloned().collect::<Vec<_>>().join(" | ");
            f.push(Finding::new(
                Severity::Bad,
                "Switches",
                "The UniFi controller logged a loop or spanning tree event in the last 24 hours",
                format!("{list}. A loop means two cables connect the same parts of the network. Trace any recently added cables, especially around the Netgear."),
            ));
        }
        for d in &u.deltas {
            let where_ = if d.port_name.is_empty() { format!("{} port {}", d.switch, d.port) } else { format!("{} port {} ({})", d.switch, d.port, d.port_name) };
            if d.broadcast_pps > 500.0 {
                f.push(Finding::new(
                    Severity::Bad,
                    "Switches",
                    format!("Broadcast storm on {where_}"),
                    format!("{:.0} broadcast packets per second are arriving. Normal is a few dozen. This is the signature of a loop. If that port leads to the Netgear, the storm is coming from the building network and the building's IT company needs to look at it.", d.broadcast_pps),
                ));
            } else if d.broadcast_pps > 150.0 {
                f.push(Finding::new(Severity::Warn, "Switches", format!("High broadcast traffic on {where_}"), format!("{:.0} broadcast packets per second. Not a storm yet, but higher than a small office should see.", d.broadcast_pps)));
            }
            if d.errors > 0 {
                f.push(Finding::new(
                    Severity::Warn,
                    "Switches",
                    format!("{} errors on {where_} during the test", d.errors),
                    "Errors on a port almost always mean a bad cable, a bad plug or interference. Replace that cable first.",
                ));
            }
        }
        let important = |sw: &str, idx: u32| {
            let m = |p: &Option<PortRef>| p.as_ref().map(|x| x.switch == sw && x.port == idx).unwrap_or(false);
            m(&u.this_machine_port) || m(&u.neptune_port)
        };
        let mut slow_ports = Vec::new();
        for sw in &u.switches {
            for p in &sw.ports {
                if let Some(state) = &p.stp_state {
                    let st = state.to_lowercase();
                    if st.contains("block") || st.contains("discard") {
                        f.push(Finding::new(
                            Severity::Warn,
                            "Switches",
                            format!("Spanning tree is blocking {} port {}", sw.name, p.idx),
                            "The switch found a second path between the same points and shut one off to stop a loop. The network still works, but there is an extra cable somewhere that should not be there.",
                        ));
                    }
                }
                if !p.up {
                    continue;
                }
                if let Some(sp) = p.speed_mbps {
                    if sp < expected && !important(&sw.name, p.idx) {
                        let uplink = if p.is_uplink { ", the uplink" } else { "" };
                        slow_ports.push(format!("{} port {}{} at {}", sw.name, p.idx, uplink, speed_label(sp)));
                        if p.is_uplink {
                            f.push(Finding::new(
                                Severity::Bad,
                                "Switches",
                                format!("The uplink on {} runs at {}", sw.name, speed_label(sp)),
                                "Everyone's traffic to Neptune crosses this link. Check the cable between the two Flex switches.",
                            ));
                        }
                    }
                }
            }
        }
        if !slow_ports.is_empty() {
            f.push(Finding::new(Severity::Info, "Switches", "Some switch ports run below 10 Gb", format!("{}. That is fine for devices that only need internet, such as the Netgear link, but not for anything working from Neptune.", slow_ports.join("; "))));
        }
        if !u.busy_before.is_empty() {
            f.push(Finding::new(
                Severity::Warn,
                "Switches",
                "Someone else was already moving a lot of data",
                format!("Before the test started: {}. Big copies by other people share the same links and Neptune, so everyone slows down.", u.busy_before.join("; ")),
            ));
        }
    }

    // ---------- Path ----------
    for p in &r.pings {
        let is_neptune = p.label == "Neptune";
        if p.received == 0 {
            // If data still flowed to Neptune, it is only ignoring ping.
            let reachable = r.throughput.is_some() || r.smb.is_some();
            let sev = if is_neptune && !reachable { Severity::Bad } else { Severity::Info };
            f.push(Finding::new(sev, if is_neptune { "Network path" } else { "Internet" }, format!("{} did not answer pings", p.label), format!("No replies from {} ({}). Some devices ignore ping, so on its own this is not proof of a fault.", p.label, p.target)));
            continue;
        }
        if is_neptune {
            if p.loss_pct >= 5.0 {
                f.push(Finding::new(Severity::Bad, "Network path", format!("{:.0}% of pings to Neptune were lost", p.loss_pct), "A healthy wired network loses none. Loss points to a cable, a port or a loop."));
            } else if p.loss_pct > 0.0 {
                f.push(Finding::new(Severity::Warn, "Network path", format!("{:.0}% ping loss to Neptune", p.loss_pct), "Small but not zero. Worth watching if it repeats."));
            }
            if let Some(avg) = p.avg_ms {
                if avg > 3.0 {
                    f.push(Finding::new(Severity::Warn, "Network path", format!("Neptune is slow to answer ({avg:.1} ms average)"), "On a wired network this should be well under 1 ms. Neptune may be overloaded, or the path is congested."));
                } else if p.loss_pct == 0.0 {
                    f.push(Finding::new(Severity::Good, "Network path", format!("Neptune answers in {avg:.2} ms with no loss"), format!("Jitter {:.2} ms.", p.jitter_ms.unwrap_or(0.0))));
                }
            }
        } else if p.loss_pct > 10.0 || p.avg_ms.unwrap_or(0.0) > 60.0 {
            f.push(Finding::new(
                Severity::Info,
                "Internet",
                format!("{} is struggling ({:.0}% loss, {:.0} ms)", p.label, p.loss_pct, p.avg_ms.unwrap_or(0.0)),
                "This sits beyond your switches. It does not slow Neptune down, but it does affect Dropbox and remote access. If it persists, report it to the building's IT company.",
            ));
        }
    }

    // ---------- Jumbo frames ----------
    if let Some(j) = &r.jumbo {
        if !j.passed {
            f.push(Finding::new(
                Severity::Bad,
                "Network path",
                "Jumbo frames are on here but do not reach Neptune",
                format!("This machine uses MTU {} but a {}-byte unfragmented ping failed. Something in between is set to 1500. Mismatched MTU causes stalls and slow copies. Set the same MTU on this machine, both Flex switches and Neptune, or set everything back to 1500.", j.local_mtu, j.payload),
            ));
        }
    }
    if let (Some(l), Some(i)) = (&r.link, nif) {
        if let (Some(a), Some(b)) = (l.mtu, i.mtu) {
            if a != b {
                f.push(Finding::new(Severity::Info, "Network path", format!("MTU differs: this machine {a}, Neptune {b}"), "It works because connections agree a common size, but matching settings everywhere avoids odd edge cases."));
            }
        }
    }

    // ---------- Neptune before testing ----------
    if let Some(sb) = &r.server_before {
        if let Some(info) = &sb.info {
            for a in &info.raid_activity {
                let (title, what) = match a.action.as_str() {
                    "check" => ("Neptune is running a data scrub", "A scrub reads every disk end to end and slows everything until it finishes. Schedule scrubs for weekends or overnight in Storage Manager."),
                    "resync" => ("Neptune is resyncing its RAID", "Every disk is busy. Expect slow performance until it completes."),
                    "recovery" => ("Neptune is rebuilding its RAID", "A disk is being rebuilt. Performance will be poor and the array is at risk until it finishes. Do not remove any drives."),
                    _ => ("Neptune is reshaping its RAID", "Every disk is busy until it completes."),
                };
                let progress = a.progress_pct.map(|p| format!(" {p:.1}% done.")).unwrap_or_default();
                let finish = a.finish.as_ref().map(|x| format!(" Estimated time left: {}.", humanise_finish(x))).unwrap_or_default();
                f.push(Finding::new(Severity::Bad, "Neptune", title, format!("{what}{progress}{finish}")));
            }
            let total = info.mem_total_mb.max(1) as f64;
            if (info.mem_available_mb as f64) < total * 0.1 {
                f.push(Finding::new(Severity::Info, "Neptune", "Neptune is low on free memory", format!("{} MB of {} MB available.", info.mem_available_mb, info.mem_total_mb)));
            }
        }
        let cpu = sb.avg(|x| x.cpu_pct).unwrap_or(0.0);
        let disk = sb.avg(|x| x.disk_util_max_pct).unwrap_or(0.0);
        if cpu > 75.0 {
            f.push(Finding::new(Severity::Warn, "Neptune", format!("Neptune's processor was {cpu:.0}% busy before testing started"), format!("Something on Neptune is already using most of its CPU.{}", top_list(sb, 3))));
        }
        if disk > 70.0 {
            f.push(Finding::new(Severity::Warn, "Neptune", format!("Neptune's disks were {disk:.0}% busy before testing started"), format!("Something is already working the disks hard.{}", top_list(sb, 3))));
        }
    }

    // ---------- Raw network speed ----------
    let nep_speed = nif.and_then(|i| i.speed_mbps).unwrap_or(expected);
    let my_speed = r.link.as_ref().and_then(|l| l.speed_mbps).unwrap_or(expected);
    let cap = expected.min(nep_speed).min(my_speed) as f64;
    let mut raw_ok_mbps: Option<f64> = None;
    if let Some(t) = &r.throughput {
        let server = t.server.as_ref();
        let dirs = [
            ("from Neptune", t.download_mbps, server.and_then(|x| x.download.as_ref())),
            ("to Neptune", t.upload_mbps, server.and_then(|x| x.upload.as_ref())),
        ];
        let mut slow_any = false;
        for (dir, rate, phase) in dirs {
            let Some(rate) = rate else { continue };
            if rate >= 0.5 * cap {
                continue;
            }
            slow_any = true;
            let core = phase.map(|p| p.busiest_core_peak_pct).unwrap_or(0.0);
            let cpu = phase.map(|p| p.cpu_avg_pct).unwrap_or(0.0);
            if core > 90.0 || cpu > 85.0 {
                f.push(Finding::new(
                    Severity::Warn,
                    "Neptune",
                    format!("Neptune's processor limits network speed {dir} to about {}", rate_label(rate)),
                    format!("During the test Neptune's busiest core hit {core:.0}% (average {cpu:.0}%) while the link was not full. The network is not the problem: Neptune's processor cannot push data any faster. This is a hardware limit of the DS1817's ARM processor, not a fault."),
                ));
            } else if my_link_slow || neptune_link_slow {
                // Already explained by a slow link.
            } else {
                f.push(Finding::new(
                    Severity::Bad,
                    "Network path",
                    format!("Network speed {dir} is only {} on a {} path", rate_label(rate), speed_label(cap as u64)),
                    "Both ends are linked at full speed and Neptune's processor had headroom, so the loss is between them: a cable run, Flex A, the uplink between the switches, or Flex B. Check any switch findings, then swap cables one at a time.",
                ));
            }
        }
        if !slow_any {
            if let (Some(d), Some(u)) = (t.download_mbps, t.upload_mbps) {
                f.push(Finding::new(Severity::Good, "Network path", format!("Network speed is healthy: {} from Neptune, {} to Neptune", rate_label(d), rate_label(u)), format!("{} parallel streams, disks not involved.", t.streams)));
            }
        }
        raw_ok_mbps = match (t.download_mbps, t.upload_mbps) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }

    // ---------- File sharing ----------
    if let Some(smb) = &r.smb {
        let ceiling_mb_s = raw_ok_mbps.unwrap_or(cap) / 8.0;
        let cases = [("Writing to", smb.write_mb_s, &smb.server_during_write, r.throughput.as_ref().and_then(|t| t.upload_mbps)), ("Reading from", smb.read_mb_s, &smb.server_during_read, r.throughput.as_ref().and_then(|t| t.download_mbps))];
        let mut slow_any = false;
        for (verb, rate, snap, dir_raw) in cases {
            let Some(rate) = rate else { continue };
            let ceiling = dir_raw.map(|x| x / 8.0).unwrap_or(ceiling_mb_s);
            if rate >= 0.6 * ceiling {
                continue;
            }
            slow_any = true;
            let disk = snap.peak(|x| x.disk_util_avg_pct).unwrap_or(0.0);
            let core = snap.peak(|x| x.busiest_core_pct).unwrap_or(0.0);
            let cpu = snap.avg(|x| x.cpu_pct).unwrap_or(0.0);
            let others_busy = r.server_before.as_ref().map(|b| b.avg(|x| x.disk_util_max_pct).unwrap_or(0.0) > 70.0 || b.avg(|x| x.cpu_pct).unwrap_or(0.0) > 75.0).unwrap_or(false);
            let procs = top_list(snap, 3);
            if snap.samples.is_empty() {
                f.push(Finding::new(Severity::Warn, "File sharing", format!("{verb} Neptune ran at {rate:.0} MB/s"), format!("That is well below the {ceiling:.0} MB/s the network carried. Neptune's load could not be read during the copy, so the cause is not certain.")));
            } else if disk > 85.0 {
                let detail = if others_busy {
                    format!("Neptune's disks were {disk:.0}% busy, and they were already busy before the test. Something else on Neptune is competing for them.{procs}")
                } else {
                    format!("Neptune's disks were {disk:.0}% busy while the network had room to spare. For eight spinning drives this is close to their real limit, so this figure is what Neptune can deliver.{procs}")
                };
                f.push(Finding::new(if others_busy { Severity::Bad } else { Severity::Warn }, "Neptune", format!("{verb} Neptune is limited by its disks ({rate:.0} MB/s)"), detail));
            } else if core > 90.0 || cpu > 85.0 {
                f.push(Finding::new(
                    Severity::Warn,
                    "Neptune",
                    format!("{verb} Neptune is limited by its processor ({rate:.0} MB/s)"),
                    format!("Neptune's busiest core hit {core:.0}% during the copy. File sharing (smbd) on the DS1817's ARM processor runs out of CPU before the disks or the network.{procs}"),
                ));
            } else {
                let hint = if r.os.starts_with("macos") {
                    " On a Mac, SMB packet signing is a common cause. It can be turned off for this Mac in /etc/nsmb.conf (signing_required=no). Also check the share is mounted with smb:// and not afp://."
                } else if r.os.starts_with("windows") {
                    " On Windows, check antivirus is not scanning files on the network drive, and that the drive is mapped straight to Neptune."
                } else {
                    ""
                };
                f.push(Finding::new(
                    Severity::Warn,
                    "File sharing",
                    format!("{verb} Neptune is slower than the network and Neptune allow ({rate:.0} MB/s)"),
                    format!("The network carried {ceiling:.0} MB/s and Neptune's disks and processor had headroom, so the bottleneck is the file sharing layer or this machine.{hint}"),
                ));
            }
        }
        if smb.read_maybe_cached {
            f.push(Finding::new(Severity::Info, "File sharing", "The read figure may be flattered", "The file read back was written recently, so Neptune may have served it from memory instead of its disks. Run the check again later for a truer read figure."));
        }
        if !slow_any {
            if let (Some(w), Some(rd)) = (smb.write_mb_s, smb.read_mb_s) {
                f.push(Finding::new(Severity::Good, "File sharing", format!("File transfer is healthy: write {w:.0} MB/s, read {rd:.0} MB/s"), format!("Measured with a {} MB file, this machine's cache bypassed.", smb.write_mb)));
            }
        }
    }

    f.sort_by(|a, b| b.severity.cmp(&a.severity));
    f
}

fn humanise_finish(s: &str) -> String {
    match s.strip_suffix("min").and_then(|m| m.parse::<f64>().ok()) {
        Some(m) if m >= 90.0 => format!("about {:.0} hours", m / 60.0),
        Some(m) => format!("about {m:.0} minutes"),
        None => s.to_string(),
    }
}

pub fn headline(findings: &[Finding], steps: &[StepStatus]) -> Finding {
    let skipped: Vec<&str> = steps.iter().filter(|s| s.state != StepState::Ok).map(|s| s.label.as_str()).collect();
    if let Some(worst) = findings.iter().find(|x| x.severity >= Severity::Warn) {
        return worst.clone();
    }
    if !skipped.is_empty() {
        return Finding::new(
            Severity::Info,
            "Overall",
            "No fault found in what could be tested",
            format!("Not tested: {}. See Settings to set these up.", skipped.join(", ")),
        );
    }
    Finding::new(Severity::Good, "Overall", "Everything checks out", "Your link, the switches, the network path, Neptune and file sharing are all performing as expected. If it still feels slow, run the check again while it is happening.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcheck_proto::{PhaseReport, ServeReport, ServerInfo, ServerInterface, ServerSample};

    fn base() -> Report {
        Report {
            id: "x".into(),
            started_at_ms: 0,
            duration_s: 0.0,
            machine: "test".into(),
            os: "macos aarch64".into(),
            app_version: "0".into(),
            steps: vec![],
            link: Some(LinkInfo { iface: "en8".into(), description: "10G".into(), kind: LinkKind::Wired, speed_mbps: Some(10_000), mtu: Some(1500), local_ip: Some("192.168.10.20".into()), prefix_len: Some(24), gateway: None }),
            neptune_ip: Some("192.168.10.5".into()),
            pings: vec![],
            jumbo: None,
            server_before: Some(ServerSnapshot {
                info: Some(ServerInfo {
                    interfaces: vec![ServerInterface { name: "eth4".into(), ipv4: vec!["192.168.10.5".into()], speed_mbps: Some(10_000), mtu: Some(1500), up: true }],
                    mem_total_mb: 4096,
                    mem_available_mb: 2000,
                    ..Default::default()
                }),
                samples: vec![ServerSample { cpu_pct: 5.0, ..Default::default() }],
            }),
            throughput: None,
            smb: None,
            unifi: None,
            findings: vec![],
            headline: Finding::new(Severity::Good, "", "", ""),
        }
    }

    fn sample(cpu: f64, core: f64, disk: f64) -> ServerSample {
        ServerSample { cpu_pct: cpu, busiest_core_pct: core, disk_util_max_pct: disk, disk_util_avg_pct: disk, ..Default::default() }
    }

    fn worst(r: &Report) -> Finding {
        let s = Settings::default();
        headline(&analyse(r, &s), &[])
    }

    #[test]
    fn slow_link_is_named() {
        let mut r = base();
        r.link.as_mut().unwrap().speed_mbps = Some(1000);
        let h = worst(&r);
        assert_eq!(h.severity, Severity::Bad);
        assert!(h.title.contains("linked at 1 Gb/s"), "{}", h.title);
    }

    #[test]
    fn wifi_is_named() {
        let mut r = base();
        r.link.as_mut().unwrap().kind = LinkKind::Wifi;
        assert!(worst(&r).title.contains("Wi-Fi"));
    }

    #[test]
    fn neptune_link_slow() {
        let mut r = base();
        r.server_before.as_mut().unwrap().info.as_mut().unwrap().interfaces[0].speed_mbps = Some(1000);
        assert!(worst(&r).title.starts_with("Neptune is linked at 1 Gb/s"));
    }

    #[test]
    fn cpu_limited_network_is_not_blamed_on_network() {
        let mut r = base();
        r.throughput = Some(ThroughputResult {
            download_mbps: Some(3200.0),
            upload_mbps: Some(9300.0),
            streams: 4,
            server: Some(ServeReport { download: Some(PhaseReport { busiest_core_peak_pct: 99.0, cpu_avg_pct: 70.0, ..Default::default() }), upload: None }),
        });
        let h = worst(&r);
        assert_eq!(h.area, "Neptune");
        assert!(h.title.contains("processor limits network speed from Neptune"));
    }

    #[test]
    fn network_path_blamed_when_neptune_idle() {
        let mut r = base();
        r.throughput = Some(ThroughputResult {
            download_mbps: Some(900.0),
            upload_mbps: Some(940.0),
            streams: 4,
            server: Some(ServeReport { download: Some(PhaseReport { busiest_core_peak_pct: 30.0, cpu_avg_pct: 10.0, ..Default::default() }), upload: Some(PhaseReport { busiest_core_peak_pct: 30.0, cpu_avg_pct: 10.0, ..Default::default() }) }),
        });
        let h = worst(&r);
        assert_eq!(h.area, "Network path");
        assert_eq!(h.severity, Severity::Bad);
    }

    #[test]
    fn disk_limited_smb() {
        let mut r = base();
        r.throughput = Some(ThroughputResult { download_mbps: Some(9000.0), upload_mbps: Some(9000.0), streams: 4, server: None });
        r.smb = Some(SmbResult {
            write_mb_s: Some(1000.0),
            read_mb_s: Some(300.0),
            write_mb: 2048,
            read_mb: 2048,
            server_during_read: ServerSnapshot { info: None, samples: vec![sample(30.0, 50.0, 98.0)] },
            ..Default::default()
        });
        let h = worst(&r);
        assert!(h.title.contains("limited by its disks"), "{}", h.title);
        assert_eq!(h.severity, Severity::Warn);
    }

    #[test]
    fn disk_limited_with_competition_is_bad() {
        let mut r = base();
        r.server_before.as_mut().unwrap().samples = vec![sample(40.0, 60.0, 95.0)];
        r.throughput = Some(ThroughputResult { download_mbps: Some(9000.0), upload_mbps: Some(9000.0), streams: 4, server: None });
        r.smb = Some(SmbResult { write_mb_s: Some(200.0), read_mb_s: Some(1000.0), write_mb: 2048, read_mb: 2048, server_during_write: ServerSnapshot { info: None, samples: vec![sample(40.0, 60.0, 99.0)] }, ..Default::default() });
        let f = analyse(&r, &Settings::default());
        assert_eq!(f[0].severity, Severity::Bad);
        assert!(f[0].title.contains("disks"));
    }

    #[test]
    fn smb_layer_blamed_when_everything_else_fine() {
        let mut r = base();
        r.throughput = Some(ThroughputResult { download_mbps: Some(9000.0), upload_mbps: Some(9000.0), streams: 4, server: None });
        r.smb = Some(SmbResult { write_mb_s: Some(120.0), read_mb_s: Some(1050.0), write_mb: 2048, read_mb: 2048, server_during_write: ServerSnapshot { info: None, samples: vec![sample(20.0, 30.0, 20.0)] }, ..Default::default() });
        let h = worst(&r);
        assert_eq!(h.area, "File sharing");
        assert!(h.detail.contains("signing"));
    }

    #[test]
    fn scrub_is_reported() {
        let mut r = base();
        r.server_before.as_mut().unwrap().info.as_mut().unwrap().raid_activity = vec![netcheck_proto::RaidActivity { device: "md2".into(), action: "check".into(), progress_pct: Some(40.0), finish: Some("300.0min".into()) }];
        let h = worst(&r);
        assert!(h.title.contains("data scrub"));
        assert!(h.detail.contains("about 5 hours"));
    }

    #[test]
    fn broadcast_storm() {
        let mut r = base();
        r.unifi = Some(UnifiResult { deltas: vec![PortDelta { switch: "Flex B".into(), port: 4, port_name: "Netgear".into(), errors: 0, drops: 0, broadcast_pps: 4000.0 }], ..Default::default() });
        let h = worst(&r);
        assert!(h.title.contains("Broadcast storm on Flex B port 4"));
    }

    #[test]
    fn all_good() {
        let mut r = base();
        r.throughput = Some(ThroughputResult { download_mbps: Some(9200.0), upload_mbps: Some(9100.0), streams: 4, server: None });
        r.smb = Some(SmbResult { write_mb_s: Some(900.0), read_mb_s: Some(1000.0), write_mb: 2048, read_mb: 2048, server_during_write: ServerSnapshot { info: None, samples: vec![sample(20.0, 30.0, 40.0)] }, server_during_read: ServerSnapshot { info: None, samples: vec![sample(20.0, 30.0, 40.0)] }, ..Default::default() });
        let h = worst(&r);
        assert_eq!(h.severity, Severity::Good);
    }

    #[test]
    fn no_dashes_in_copy() {
        // House style: no en or em dashes anywhere in user-facing text.
        let src = include_str!("verdict.rs");
        assert!(!src.contains('\u{2013}') && !src.contains('\u{2014}'));
    }

    #[test]
    fn labels() {
        assert_eq!(speed_label(10_000), "10 Gb/s");
        assert_eq!(speed_label(2500), "2.5 Gb/s");
        assert_eq!(speed_label(100), "100 Mb/s");
        assert_eq!(describe_process("smbd"), "smbd (file sharing)");
        assert_eq!(describe_process("foo"), "foo");
    }
}
