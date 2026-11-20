//! Throughput endpoint. Accepts connections until the client sends Quit or
//! the time limit passes, then prints a JSON report and exits.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netcheck_proto::{PhaseReport, ServeReport, MODE_DOWNLOAD, MODE_QUIT, MODE_UPLOAD, READY_LINE};

use crate::procfs::{compare, Snapshot};

struct Phase {
    mode: u8,
    start: f64,
    end: f64,
    bytes: u64,
}

pub fn serve(port: u16, max: Duration) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    listener.set_nonblocking(true)?;
    let origin = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let phases: Arc<Mutex<Vec<Phase>>> = Arc::default();
    let cpu: Arc<Mutex<Vec<(f64, f64, f64)>>> = Arc::default();

    // CPU sampler: whole system and busiest core every 250 ms.
    let sampler = {
        let stop = stop.clone();
        let cpu = cpu.clone();
        std::thread::spawn(move || {
            let mut prev = Snapshot::take_cpu_only();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                let now = Snapshot::take_cpu_only();
                let s = compare(&prev, &now, false);
                cpu.lock().unwrap().push((origin.elapsed().as_secs_f64(), s.cpu_pct, s.busiest_core_pct));
                prev = now;
            }
        })
    };

    println!("{READY_LINE} {port}");
    io::stdout().flush()?;

    let mut workers = Vec::new();
    while !stop.load(Ordering::Relaxed) && origin.elapsed() < max {
        match listener.accept() {
            Ok((stream, _)) => {
                let stop = stop.clone();
                let phases = phases.clone();
                workers.push(std::thread::spawn(move || {
                    let _ = handle(stream, origin, &stop, &phases);
                }));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = w.join();
    }
    let _ = sampler.join();

    let phases = phases.lock().unwrap();
    let cpu = cpu.lock().unwrap();
    let report = ServeReport {
        download: summarise(&phases, &cpu, MODE_DOWNLOAD),
        upload: summarise(&phases, &cpu, MODE_UPLOAD),
    };
    println!("{}", serde_json::to_string(&report).unwrap());
    io::stdout().flush()
}

fn handle(mut s: TcpStream, origin: Instant, stop: &AtomicBool, phases: &Mutex<Vec<Phase>>) -> io::Result<()> {
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(Duration::from_secs(20)))?;
    s.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut mode = [0u8; 1];
    s.read_exact(&mut mode)?;
    let mut buf = vec![0u8; 256 * 1024];
    match mode[0] {
        MODE_QUIT => {
            stop.store(true, Ordering::Relaxed);
        }
        MODE_DOWNLOAD => {
            let mut secs = [0u8; 4];
            s.read_exact(&mut secs)?;
            let secs = u32::from_be_bytes(secs).clamp(1, 60) as f64;
            fill(&mut buf);
            let start = origin.elapsed().as_secs_f64();
            let mut bytes = 0u64;
            while origin.elapsed().as_secs_f64() - start < secs && !stop.load(Ordering::Relaxed) {
                match s.write(&buf) {
                    Ok(0) => break,
                    Ok(n) => bytes += n as u64,
                    Err(_) => break,
                }
            }
            let end = origin.elapsed().as_secs_f64();
            phases.lock().unwrap().push(Phase { mode: MODE_DOWNLOAD, start, end, bytes });
        }
        MODE_UPLOAD => {
            let start = origin.elapsed().as_secs_f64();
            let mut bytes = 0u64;
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => bytes += n as u64,
                    Err(_) => break,
                }
            }
            let end = origin.elapsed().as_secs_f64();
            phases.lock().unwrap().push(Phase { mode: MODE_UPLOAD, start, end, bytes });
        }
        _ => {}
    }
    Ok(())
}

/// Incompressible filler so nothing along the path can shortcut the test.
fn fill(buf: &mut [u8]) {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for chunk in buf.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

fn summarise(phases: &[Phase], cpu: &[(f64, f64, f64)], mode: u8) -> Option<PhaseReport> {
    let ps: Vec<&Phase> = phases.iter().filter(|p| p.mode == mode).collect();
    if ps.is_empty() {
        return None;
    }
    let start = ps.iter().map(|p| p.start).fold(f64::MAX, f64::min);
    let end = ps.iter().map(|p| p.end).fold(0.0, f64::max);
    let inside: Vec<&(f64, f64, f64)> = cpu.iter().filter(|(t, _, _)| *t >= start && *t <= end + 0.3).collect();
    let cpu_avg_pct = if inside.is_empty() { 0.0 } else { inside.iter().map(|x| x.1).sum::<f64>() / inside.len() as f64 };
    let busiest_core_peak_pct = inside.iter().map(|x| x.2).fold(0.0, f64::max);
    Some(PhaseReport {
        bytes: ps.iter().map(|p| p.bytes).sum(),
        seconds: (end - start).max(0.001),
        streams: ps.len() as u32,
        cpu_avg_pct,
        busiest_core_peak_pct,
    })
}
