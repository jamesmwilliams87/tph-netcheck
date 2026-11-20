//! Raw network speed to Neptune with the disks out of the picture.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use netcheck_proto::{MODE_DOWNLOAD, MODE_QUIT, MODE_UPLOAD};

struct Leg {
    bytes: u64,
    start: Instant,
    end: Instant,
}

fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.set_write_timeout(Some(Duration::from_secs(15)))?;
    Ok(s)
}

fn rate_mbps(legs: &[Leg]) -> Option<f64> {
    let start = legs.iter().map(|l| l.start).min()?;
    let end = legs.iter().map(|l| l.end).max()?;
    let secs = end.duration_since(start).as_secs_f64();
    let bytes: u64 = legs.iter().map(|l| l.bytes).sum();
    (secs > 0.2 && bytes > 0).then(|| bytes as f64 * 8.0 / secs / 1e6)
}

/// Neptune sends, this machine receives.
pub fn download(addr: SocketAddr, seconds: u32, streams: u32) -> Result<f64, String> {
    let legs: Vec<Leg> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..streams)
            .map(|_| {
                sc.spawn(move || -> std::io::Result<Leg> {
                    let mut s = connect(addr)?;
                    let mut hdr = vec![MODE_DOWNLOAD];
                    hdr.extend_from_slice(&seconds.to_be_bytes());
                    s.write_all(&hdr)?;
                    let mut buf = vec![0u8; 256 * 1024];
                    let mut bytes = 0u64;
                    let mut start = None;
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                start.get_or_insert_with(Instant::now);
                                bytes += n as u64;
                            }
                            Err(_) => break,
                        }
                    }
                    let end = Instant::now();
                    Ok(Leg { bytes, start: start.unwrap_or(end), end })
                })
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok().and_then(Result::ok)).collect()
    });
    if legs.is_empty() {
        return Err(format!("Could not connect to the test server on Neptune ({addr}). Check DSM's firewall allows that port."));
    }
    rate_mbps(&legs).ok_or_else(|| "No data came back from Neptune".into())
}

/// This machine sends, Neptune receives.
pub fn upload(addr: SocketAddr, seconds: u32, streams: u32) -> Result<f64, String> {
    let legs: Vec<Leg> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..streams)
            .map(|_| {
                sc.spawn(move || -> std::io::Result<Leg> {
                    let mut s = connect(addr)?;
                    s.write_all(&[MODE_UPLOAD])?;
                    let buf = crate::smb::noise(256 * 1024);
                    let start = Instant::now();
                    let mut bytes = 0u64;
                    while start.elapsed() < Duration::from_secs(seconds as u64) {
                        match s.write(&buf) {
                            Ok(n) => bytes += n as u64,
                            Err(_) => break,
                        }
                    }
                    let _ = s.shutdown(Shutdown::Write);
                    // Wait for the server to close so the bytes are really delivered.
                    let mut sink = [0u8; 64];
                    let _ = s.read(&mut sink);
                    Ok(Leg { bytes, start, end: Instant::now() })
                })
            })
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok().and_then(Result::ok)).collect()
    });
    if legs.is_empty() {
        return Err(format!("Could not connect to the test server on Neptune ({addr})"));
    }
    rate_mbps(&legs).ok_or_else(|| "No data reached Neptune".into())
}

pub fn quit(addr: SocketAddr) {
    if let Ok(mut s) = connect(addr) {
        let _ = s.write_all(&[MODE_QUIT]);
    }
}
