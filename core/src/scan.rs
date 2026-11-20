//! Isolation check: lists every device this machine can reach on its subnet.
//! A packet is sent to each address so the system learns who answers, then
//! the ARP table is read back. Needs no special permissions.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use crate::report::{Finding, LinkInfo, ScanDevice, ScanReport, Severity, UnifiResult};
use crate::settings::Settings;
use crate::sys;

pub fn hosts(ip: Ipv4Addr, prefix: u8) -> (String, Vec<Ipv4Addr>) {
    // Never sweep more than a /22 (1022 hosts). Larger subnets fall back to the local /24.
    let prefix = if prefix < 22 { 24 } else { prefix.min(30) };
    let mask = u32::MAX << (32 - prefix);
    let net = u32::from(ip) & mask;
    let bcast = net | !mask;
    let list = ((net + 1)..bcast).map(Ipv4Addr::from).filter(|h| *h != ip).collect();
    (format!("{}/{}", Ipv4Addr::from(net), prefix), list)
}

pub fn parse_arp(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let t = tok.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none() && t.parse::<Ipv4Addr>().is_ok() {
                ip = Some(t.to_string());
                continue;
            }
            let norm = t.replace('-', ":").to_lowercase();
            let parts: Vec<&str> = norm.split(':').collect();
            if parts.len() == 6 && parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && p.chars().all(|c| c.is_ascii_hexdigit())) {
                let full = parts.iter().map(|p| format!("{p:0>2}")).collect::<Vec<_>>().join(":");
                mac = Some(full);
            }
        }
        if let (Some(i), Some(m)) = (ip, mac) {
            let broadcast = m == "ff:ff:ff:ff:ff:ff";
            let multicast = m.starts_with("01:00:5e") || m.starts_with("33:33");
            if !broadcast && !multicast && m != "00:00:00:00:00:00" {
                out.push((i, m));
            }
        }
    }
    out
}

pub fn scan(link: &LinkInfo, settings: &Settings, neptune_ip: Option<&str>, unifi: Option<&UnifiResult>) -> Result<ScanReport, String> {
    let ip: Ipv4Addr = link.local_ip.as_deref().and_then(|s| s.parse().ok()).ok_or("This machine's address is unknown")?;
    let prefix = link.prefix_len.unwrap_or(24);
    let (subnet, targets) = hosts(ip, prefix);

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    for round in 0..2 {
        for t in &targets {
            let _ = sock.send_to(b"tph-netcheck", (*t, 9));
        }
        std::thread::sleep(Duration::from_millis(if round == 0 { 1500 } else { 2000 }));
    }

    #[cfg(windows)]
    let arp = sys::output("arp", &["-a"])?;
    #[cfg(target_os = "macos")]
    let arp = sys::output("/usr/sbin/arp", &["-an"])?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let arp = sys::output("ip", &["neigh"])?;

    let in_subnet: std::collections::HashSet<String> = targets.iter().map(|t| t.to_string()).collect();
    let mut found: BTreeMap<u32, ScanDevice> = BTreeMap::new();
    for (i, m) in parse_arp(&arp) {
        if !in_subnet.contains(&i) {
            continue;
        }
        let key = u32::from(i.parse::<Ipv4Addr>().unwrap());
        found.insert(key, ScanDevice { ip: i, mac: m, label: None });
    }

    for d in found.values_mut() {
        d.label = label_for(d, settings, neptune_ip, link, unifi);
    }
    let devices: Vec<ScanDevice> = found.into_values().collect();
    let unknown: Vec<&ScanDevice> = devices.iter().filter(|d| d.label.is_none()).collect();

    let mut findings = Vec::new();
    if unknown.is_empty() {
        findings.push(Finding::new(
            Severity::Good,
            "Isolation",
            "Only your own devices are visible",
            format!("{} device(s) answered on {subnet}, and every one is known. Your VLAN looks isolated from other tenants.", devices.len()),
        ));
    } else {
        let list = unknown.iter().take(12).map(|d| format!("{} ({})", d.ip, d.mac)).collect::<Vec<_>>().join(", ");
        let sev = if unknown.len() > 5 { Severity::Warn } else { Severity::Info };
        findings.push(Finding::new(
            sev,
            "Isolation",
            format!("{} device(s) not recognised", unknown.len()),
            format!(
                "These answered on {subnet} but are not in your known list: {list}. If they are yours, add them in Settings. \
                 If they are not, other tenants may be able to reach your network. Raise it with the building's IT company."
            ),
        ));
    }
    Ok(ScanReport { subnet, scanned: targets.len() as u32, devices, findings })
}

fn label_for(d: &ScanDevice, s: &Settings, neptune_ip: Option<&str>, link: &LinkInfo, unifi: Option<&UnifiResult>) -> Option<String> {
    for k in &s.known_devices {
        let mac_match = !k.mac.is_empty() && k.mac.replace('-', ":").to_lowercase() == d.mac;
        let ip_match = !k.ip.is_empty() && k.ip == d.ip;
        if mac_match || ip_match {
            return Some(k.name.clone());
        }
    }
    if Some(d.ip.as_str()) == neptune_ip {
        return Some("Neptune".into());
    }
    if link.gateway.as_deref() == Some(d.ip.as_str()) {
        return Some("Gateway (building router)".into());
    }
    if let Some(u) = unifi {
        if let Some(sw) = u.switches.iter().find(|x| x.mac == d.mac || x.ip == d.ip) {
            return Some(format!("UniFi switch: {}", sw.name));
        }
        if let Some(c) = u.clients.iter().find(|c| c.mac == d.mac) {
            if !c.name.is_empty() {
                return Some(c.name.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_math() {
        let (s, h) = hosts("192.168.10.23".parse().unwrap(), 24);
        assert_eq!(s, "192.168.10.0/24");
        assert_eq!(h.len(), 253);
        let (s, _) = hosts("10.1.2.3".parse().unwrap(), 16);
        assert_eq!(s, "10.1.2.0/24");
        let (_, h) = hosts("10.1.2.3".parse().unwrap(), 22);
        assert_eq!(h.len(), 1021);
    }

    #[test]
    fn arp_formats() {
        let mac = "? (192.168.10.5) at 0:11:32:a:bb:cc on en8 ifscope [ethernet]\n? (192.168.10.9) at (incomplete) on en8 ifscope [ethernet]\n? (224.0.0.251) at 1:0:5e:0:0:fb on en8 ifscope permanent [ethernet]\n";
        assert_eq!(parse_arp(mac), vec![("192.168.10.5".to_string(), "00:11:32:0a:bb:cc".to_string())]);
        let win = "Interface: 192.168.10.40 --- 0x7\n  Internet Address      Physical Address      Type\n  192.168.10.1          00-11-22-33-44-55     dynamic\n  192.168.10.255        ff-ff-ff-ff-ff-ff     static\n";
        assert_eq!(parse_arp(win), vec![("192.168.10.1".to_string(), "00:11:22:33:44:55".to_string())]);
        let lin = "192.168.10.7 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE\n";
        assert_eq!(parse_arp(lin).len(), 1);
    }
}
