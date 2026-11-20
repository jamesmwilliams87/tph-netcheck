//! Finds the adapter this machine uses to reach Neptune and reads its
//! negotiated speed, MTU, address and gateway.

use crate::report::{LinkInfo, LinkKind};
#[allow(unused_imports)]
use crate::sys;

pub fn detect(target_ip: &str) -> Result<LinkInfo, String> {
    imp::detect(target_ip)
}

// ---------- macOS ----------
#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    pub fn detect(target_ip: &str) -> Result<LinkInfo, String> {
        let route = sys::output("/sbin/route", &["-n", "get", target_ip])?;
        let iface = route_field(&route, "interface").ok_or("could not find which adapter reaches Neptune")?;
        let ifc = sys::output("/sbin/ifconfig", &[&iface])?;
        let ports = sys::output("/usr/sbin/networksetup", &["-listallhardwareports"]).unwrap_or_default();
        let gw = sys::output("/sbin/route", &["-n", "get", "default"]).ok().and_then(|r| route_field(&r, "gateway"));
        Ok(from_ifconfig(&iface, &ifc, &ports, gw))
    }
}

// ---------- Windows ----------
#[cfg(windows)]
mod imp {
    use super::*;
    pub fn detect(target_ip: &str) -> Result<LinkInfo, String> {
        // Only an IPv4 literal reaches here; it is validated before use.
        target_ip.parse::<std::net::Ipv4Addr>().map_err(|_| "bad address")?;
        let script = format!(
            r#"$ErrorActionPreference='SilentlyContinue';
$r = Find-NetRoute -RemoteIPAddress '{target_ip}';
$ipo = $r | Where-Object {{ $_.IPAddress }} | Select-Object -First 1;
$idx = $ipo.InterfaceIndex;
$a = Get-NetAdapter -InterfaceIndex $idx;
$ipi = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4;
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop;
[pscustomobject]@{{
 name=$a.Name; desc=$a.InterfaceDescription; media=[string]$a.PhysicalMediaType;
 speed=[uint64]$a.ReceiveLinkSpeed; mtu=[uint32]$ipi.NlMtu;
 ip=$ipo.IPAddress; prefix=[int]$ipo.PrefixLength; gw=$gw
}} | ConvertTo-Json -Compress"#
        );
        let out = sys::powershell(&script)?;
        parse_windows_json(&out)
    }
}

// ---------- Linux (development only) ----------
#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::*;
    pub fn detect(target_ip: &str) -> Result<LinkInfo, String> {
        let r = sys::output("ip", &["-o", "route", "get", target_ip])?;
        let tok: Vec<&str> = r.split_whitespace().collect();
        let after = |k: &str| tok.iter().position(|t| *t == k).and_then(|i| tok.get(i + 1)).map(|s| s.to_string());
        let iface = after("dev").ok_or("no route")?;
        let read = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{iface}/{f}")).unwrap_or_default();
        let speed = read("speed").trim().parse::<i64>().ok().filter(|v| *v > 0).map(|v| v as u64);
        let mtu = read("mtu").trim().parse().ok();
        let wifi = std::path::Path::new(&format!("/sys/class/net/{iface}/wireless")).exists();
        let addr = sys::output("ip", &["-o", "-4", "addr", "show", "dev", &iface]).unwrap_or_default();
        let cidr = addr.split_whitespace().skip_while(|t| *t != "inet").nth(1).unwrap_or("").to_string();
        let (ip, prefix) = cidr.split_once('/').map(|(a, b)| (Some(a.to_string()), b.parse().ok())).unwrap_or((None, None));
        let gw = sys::output("ip", &["-o", "route", "show", "default"]).ok().and_then(|g| {
            let t: Vec<&str> = g.split_whitespace().collect();
            t.iter().position(|x| *x == "via").and_then(|i| t.get(i + 1)).map(|s| s.to_string())
        });
        Ok(LinkInfo {
            description: iface.clone(),
            iface,
            kind: if wifi { LinkKind::Wifi } else { LinkKind::Wired },
            speed_mbps: speed,
            mtu,
            local_ip: ip.or(after("src")),
            prefix_len: prefix,
            gateway: gw,
        })
    }
}

// ---------- Parsers (pure, tested on every platform) ----------

/// `route -n get` prints lines like "  interface: en7".
pub fn route_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.trim().split_once(':')?;
        (k.trim() == key).then(|| v.trim().to_string())
    })
}

/// Reads speed from an ifconfig media line, e.g.
/// "media: autoselect (10Gbase-T <full-duplex>)" or "(1000baseT <full-duplex>)".
pub fn parse_media_speed(media: &str) -> Option<u64> {
    let inner = media.split('(').nth(1)?;
    let digits: String = inner.chars().take_while(|c| c.is_ascii_digit()).collect();
    let n: u64 = digits.parse().ok()?;
    let rest = &inner[digits.len()..];
    let unit = rest.chars().next()?;
    match unit {
        'G' | 'g' => Some(n * 1000),
        'b' | 'B' => Some(n),
        _ => None,
    }
}

pub fn from_ifconfig(iface: &str, ifconfig: &str, hw_ports: &str, gateway: Option<String>) -> LinkInfo {
    let mut mtu = None;
    let mut ip = None;
    let mut prefix = None;
    let mut speed = None;
    for line in ifconfig.lines() {
        let t = line.trim();
        if let Some(i) = t.find("mtu ") {
            mtu = t[i + 4..].split_whitespace().next().and_then(|v| v.parse().ok());
        }
        if let Some(rest) = t.strip_prefix("inet ") {
            let f: Vec<&str> = rest.split_whitespace().collect();
            ip = f.first().map(|s| s.to_string());
            if let Some(i) = f.iter().position(|x| *x == "netmask") {
                prefix = f.get(i + 1).and_then(|m| u32::from_str_radix(m.trim_start_matches("0x"), 16).ok()).map(|m| m.count_ones() as u8);
            }
        }
        if let Some(rest) = t.strip_prefix("media:") {
            speed = parse_media_speed(rest);
        }
    }
    let (kind, description) = hardware_port(hw_ports, iface);
    LinkInfo { iface: iface.to_string(), description, kind, speed_mbps: speed, mtu, local_ip: ip, prefix_len: prefix, gateway }
}

/// Maps "en0" to its hardware port name from `networksetup -listallhardwareports`.
pub fn hardware_port(text: &str, iface: &str) -> (LinkKind, String) {
    let mut last = String::new();
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("Hardware Port:") {
            last = p.trim().to_string();
        } else if let Some(d) = line.strip_prefix("Device:") {
            if d.trim() == iface {
                let wifi = last.contains("Wi-Fi") || last.contains("AirPort");
                return (if wifi { LinkKind::Wifi } else { LinkKind::Wired }, last);
            }
        }
    }
    (LinkKind::Unknown, iface.to_string())
}

pub fn parse_windows_json(text: &str) -> Result<LinkInfo, String> {
    let v: serde_json::Value = serde_json::from_str(text.trim()).map_err(|_| format!("could not read adapter details: {}", text.trim()))?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let n = |k: &str| v.get(k).and_then(|x| x.as_u64());
    let desc = s("desc");
    let media = s("media");
    let wifi = media.contains("802.11") || desc.to_lowercase().contains("wi-fi") || desc.to_lowercase().contains("wireless");
    let gw = Some(s("gw")).filter(|g| !g.is_empty() && g != "0.0.0.0");
    Ok(LinkInfo {
        iface: s("name"),
        description: desc,
        kind: if wifi { LinkKind::Wifi } else { LinkKind::Wired },
        speed_mbps: n("speed").filter(|x| *x > 0).map(|b| b / 1_000_000),
        mtu: n("mtu").map(|x| x as u32),
        local_ip: Some(s("ip")).filter(|x| !x.is_empty()),
        prefix_len: n("prefix").map(|x| x as u8),
        gateway: gw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_speeds() {
        assert_eq!(parse_media_speed(" autoselect (10Gbase-T <full-duplex>)"), Some(10_000));
        assert_eq!(parse_media_speed(" autoselect (1000baseT <full-duplex>)"), Some(1000));
        assert_eq!(parse_media_speed(" autoselect (2500Base-T <full-duplex>)"), Some(2500));
        assert_eq!(parse_media_speed(" autoselect (5000baseT <full-duplex>)"), Some(5000));
        assert_eq!(parse_media_speed(" autoselect (100baseTX <full-duplex>)"), Some(100));
        assert_eq!(parse_media_speed(" autoselect"), None);
    }

    #[test]
    fn mac_ifconfig() {
        let ifc = "en8: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 9000\n\tether aa:bb:cc:dd:ee:ff\n\tinet 192.168.10.23 netmask 0xffffff00 broadcast 192.168.10.255\n\tmedia: autoselect (10Gbase-T <full-duplex>)\n\tstatus: active\n";
        let ports = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: x\n\nHardware Port: OWC Thunderbolt 3 10G Ethernet\nDevice: en8\n";
        let l = from_ifconfig("en8", ifc, ports, Some("192.168.10.1".into()));
        assert_eq!(l.speed_mbps, Some(10_000));
        assert_eq!(l.mtu, Some(9000));
        assert_eq!(l.local_ip.as_deref(), Some("192.168.10.23"));
        assert_eq!(l.prefix_len, Some(24));
        assert_eq!(l.kind, LinkKind::Wired);
        assert!(l.description.contains("OWC"));
        assert_eq!(hardware_port(ports, "en0").0, LinkKind::Wifi);
    }

    #[test]
    fn route_get() {
        let t = "   route to: 192.168.10.5\ndestination: 192.168.10.0\n  interface: en8\n      flags: <UP,DONE>\n";
        assert_eq!(route_field(t, "interface").as_deref(), Some("en8"));
        assert_eq!(route_field(t, "gateway"), None);
    }

    #[test]
    fn windows_json() {
        let t = r#"{"name":"Ethernet 2","desc":"Aquantia AQtion 10Gbit Network Adapter","media":"802.3","speed":10000000000,"mtu":1500,"ip":"192.168.10.40","prefix":24,"gw":"192.168.10.1"}"#;
        let l = parse_windows_json(t).unwrap();
        assert_eq!(l.speed_mbps, Some(10_000));
        assert_eq!(l.kind, LinkKind::Wired);
        assert_eq!(l.gateway.as_deref(), Some("192.168.10.1"));
        let w = r#"{"name":"Wi-Fi","desc":"Intel(R) Wi-Fi 6 AX201","media":"Native 802.11","speed":866700000,"mtu":1500,"ip":"192.168.10.41","prefix":24,"gw":"0.0.0.0"}"#;
        let l = parse_windows_json(w).unwrap();
        assert_eq!(l.kind, LinkKind::Wifi);
        assert_eq!(l.speed_mbps, Some(866));
        assert_eq!(l.gateway, None);
    }
}
