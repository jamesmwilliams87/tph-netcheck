//! Latency, jitter and loss using the system ping, which needs no special
//! permissions on macOS or Windows.

use crate::report::PingResult;
use crate::sys;

pub fn ping(label: &str, target: &str, count: u32) -> PingResult {
    let c = count.to_string();
    #[cfg(windows)]
    let out = sys::output("ping", &["-n", &c, "-w", "1000", target]);
    #[cfg(target_os = "macos")]
    let out = sys::output("/sbin/ping", &["-c", &c, "-i", "0.2", "-t", &(count / 2 + 5).to_string(), target]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let out = sys::output("ping", &["-c", &c, "-i", "0.2", "-W", "1", target]);
    let times = parse_times(&out.unwrap_or_default());
    summarise(label, target, count, &times)
}

/// Sends pings that must not be fragmented. Passing means every hop to the
/// target accepts frames of this size.
pub fn dont_fragment(target: &str, payload: u32) -> bool {
    let p = payload.to_string();
    #[cfg(windows)]
    let out = sys::output("ping", &["-n", "3", "-w", "1000", "-f", "-l", &p, target]);
    #[cfg(target_os = "macos")]
    let out = sys::output("/sbin/ping", &["-c", "3", "-i", "0.2", "-t", "4", "-D", "-s", &p, target]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let out = sys::output("ping", &["-c", "3", "-i", "0.2", "-W", "1", "-M", "do", "-s", &p, target]);
    !parse_times(&out.unwrap_or_default()).is_empty()
}

/// Pulls round-trip times from ping output on any platform.
/// macOS/Linux: "time=0.412 ms". Windows: "time=1ms" or "time<1ms".
pub fn parse_times(text: &str) -> Vec<f64> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(pos) = lower.find("time").filter(|_| lower.contains("ttl") || lower.contains("bytes from")) else { continue };
        let rest = &lower[pos + 4..];
        let (lt, rest) = match rest.chars().next() {
            Some('=') => (false, &rest[1..]),
            Some('<') => (true, &rest[1..]),
            _ => continue,
        };
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        if let Ok(v) = num.parse::<f64>() {
            out.push(if lt { v / 2.0 } else { v });
        }
    }
    out
}

pub fn summarise(label: &str, target: &str, sent: u32, times: &[f64]) -> PingResult {
    let received = times.len() as u32;
    let loss_pct = if sent == 0 { 0.0 } else { (sent.saturating_sub(received)) as f64 / sent as f64 * 100.0 };
    let avg = (!times.is_empty()).then(|| times.iter().sum::<f64>() / times.len() as f64);
    let max = times.iter().cloned().reduce(f64::max);
    let jitter = (times.len() > 1).then(|| times.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (times.len() - 1) as f64);
    PingResult {
        label: label.into(),
        target: target.into(),
        sent,
        received,
        loss_pct,
        avg_ms: avg,
        max_ms: max,
        jitter_ms: jitter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_output() {
        let t = "PING 192.168.10.5 (192.168.10.5): 56 data bytes\n64 bytes from 192.168.10.5: icmp_seq=0 ttl=64 time=0.412 ms\n64 bytes from 192.168.10.5: icmp_seq=1 ttl=64 time=0.388 ms\nRequest timeout for icmp_seq 2\n\n--- stats ---\nround-trip min/avg/max/stddev = 0.388/0.400/0.412/0.012 ms\n";
        assert_eq!(parse_times(t), vec![0.412, 0.388]);
        let r = summarise("Neptune", "x", 3, &parse_times(t));
        assert_eq!(r.received, 2);
        assert!((r.loss_pct - 33.33).abs() < 0.1);
    }

    #[test]
    fn windows_output() {
        let t = "Pinging 192.168.10.5 with 32 bytes of data:\r\nReply from 192.168.10.5: bytes=32 time<1ms TTL=64\r\nReply from 192.168.10.5: bytes=32 time=2ms TTL=64\r\nReply from 192.168.10.9: Destination host unreachable.\r\nRequest timed out.\r\n\r\nPing statistics for 192.168.10.5:\r\n    Minimum = 0ms, Maximum = 2ms, Average = 1ms\r\n";
        assert_eq!(parse_times(t), vec![0.5, 2.0]);
    }

    #[test]
    fn df_failure_has_no_times() {
        let w = "Pinging 192.168.10.5 with 8972 bytes of data:\r\nPacket needs to be fragmented but DF set.\r\n";
        assert!(parse_times(w).is_empty());
        let m = "PING 192.168.10.5: 8972 data bytes\nping: sendto: Message too long\n";
        assert!(parse_times(m).is_empty());
    }
}
