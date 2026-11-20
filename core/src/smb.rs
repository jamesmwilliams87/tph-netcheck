//! Real file speed on the Neptune share, with this machine's file cache
//! switched off so the numbers are honest.
//!
//! Two test files per machine are kept and alternated. Each run writes one
//! and reads the other, which was written on the previous run and has most
//! likely dropped out of Neptune's memory since. That way the read figure
//! reflects the disks, not Neptune's RAM.

use std::alloc::{alloc, dealloc, Layout};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const CHUNK: usize = 8 * 1024 * 1024;
const ALIGN: usize = 4096;

/// Heap buffer aligned for unbuffered I/O on Windows.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, ALIGN).unwrap();
        // SAFETY: layout has non-zero size.
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null(), "out of memory");
        AlignedBuf { ptr, len }
    }
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for len bytes for the life of self.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: same layout as alloc.
        unsafe { dealloc(self.ptr, Layout::from_size_align(self.len, ALIGN).unwrap()) }
    }
}

/// Incompressible test data.
pub fn noise(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill_noise(&mut v, 0x2545_F491_4F6C_DD1D);
    v
}

fn fill_noise(buf: &mut [u8], seed: u64) {
    let mut x = seed | 1;
    for chunk in buf.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

#[cfg(target_os = "macos")]
fn no_cache(f: &File) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: valid fd; F_NOCACHE only changes caching policy.
    unsafe {
        libc::fcntl(f.as_raw_fd(), libc::F_NOCACHE, 1);
    }
}

#[cfg(not(target_os = "macos"))]
fn no_cache(_f: &File) {}

fn open_write(p: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
        o.custom_flags(FILE_FLAG_NO_BUFFERING);
    }
    let f = o.open(p)?;
    no_cache(&f);
    Ok(f)
}

fn open_read(p: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
        o.custom_flags(FILE_FLAG_NO_BUFFERING);
    }
    let f = o.open(p)?;
    no_cache(&f);
    Ok(f)
}

pub struct Plan {
    pub write_path: PathBuf,
    pub read_path: PathBuf,
    /// The read file was written moments ago or recently, so Neptune may still
    /// hold it in memory.
    pub read_maybe_cached: bool,
    pub read_after_write: bool,
}

fn safe_name(host: &str) -> String {
    let s: String = host.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    if s.is_empty() { "machine".into() } else { s }
}

/// Decides which file to write and which to read this run.
pub fn plan(dir: &Path, host: &str) -> Plan {
    let name = safe_name(host);
    let a = dir.join(format!("{name}-a.bin"));
    let b = dir.join(format!("{name}-b.bin"));
    let mtime = |p: &Path| fs::metadata(p).and_then(|m| m.modified()).ok();
    let (ma, mb) = (mtime(&a), mtime(&b));
    let (write_path, other, other_m) = match (ma, mb) {
        (None, _) => (a.clone(), b.clone(), mb),
        (_, None) => (b.clone(), a.clone(), ma),
        (Some(x), Some(y)) if x <= y => (a.clone(), b.clone(), mb),
        _ => (b.clone(), a.clone(), ma),
    };
    match other_m {
        Some(m) => {
            let age = SystemTime::now().duration_since(m).unwrap_or(Duration::ZERO);
            Plan { write_path, read_path: other, read_maybe_cached: age < Duration::from_secs(600), read_after_write: false }
        }
        None => Plan { read_path: write_path.clone(), write_path, read_maybe_cached: true, read_after_write: true },
    }
}

pub struct Timed {
    pub mb: u64,
    pub mb_s: f64,
    pub start: Instant,
    pub end: Instant,
}

pub fn write_test(path: &Path, size_mb: u64) -> Result<Timed, String> {
    let chunks = (size_mb * 1024 * 1024).div_ceil(CHUNK as u64).max(1);
    let mut buf = AlignedBuf::new(CHUNK);
    fill_noise(buf.as_mut(), SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(7));
    let start = Instant::now();
    let mut f = open_write(path).map_err(|e| format!("Could not create the test file on the share: {e}"))?;
    for _ in 0..chunks {
        f.write_all(buf.as_mut()).map_err(|e| format!("Write to the share failed: {e}"))?;
    }
    f.sync_all().map_err(|e| format!("Flushing the test file failed: {e}"))?;
    drop(f);
    let end = Instant::now();
    let mb = chunks * CHUNK as u64 / (1024 * 1024);
    Ok(Timed { mb, mb_s: mb as f64 / end.duration_since(start).as_secs_f64(), start, end })
}

pub fn read_test(path: &Path) -> Result<Timed, String> {
    let mut buf = AlignedBuf::new(CHUNK);
    let start = Instant::now();
    let mut f = open_read(path).map_err(|e| format!("Could not open the test file: {e}"))?;
    let mut total = 0u64;
    loop {
        match f.read(buf.as_mut()) {
            Ok(0) => break,
            Ok(n) => total += n as u64,
            Err(e) => return Err(format!("Read from the share failed: {e}")),
        }
    }
    let end = Instant::now();
    let mb = total / (1024 * 1024);
    Ok(Timed { mb, mb_s: mb as f64 / end.duration_since(start).as_secs_f64().max(0.001), start, end })
}

pub fn check_dir(dir: &str) -> Result<PathBuf, String> {
    if dir.trim().is_empty() {
        return Err("No test folder on the Neptune share is set in Settings".into());
    }
    let p = PathBuf::from(dir.trim());
    if !p.exists() {
        let parent_ok = p.parent().map(|x| x.exists()).unwrap_or(false);
        if !parent_ok {
            return Err(format!("{} is not reachable. Is the Neptune share mounted?", p.display()));
        }
        fs::create_dir_all(&p).map_err(|e| format!("Could not create {}: {e}", p.display()))?;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternates_files() {
        let dir = std::env::temp_dir().join(format!("netcheck-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p1 = plan(&dir, "James Mac");
        assert!(p1.read_after_write);
        assert!(p1.write_path.ends_with("James_Mac-a.bin"));
        write_test(&p1.write_path, 8).unwrap();
        let p2 = plan(&dir, "James Mac");
        assert!(p2.write_path.ends_with("James_Mac-b.bin"));
        assert!(p2.read_path.ends_with("James_Mac-a.bin"));
        assert!(p2.read_maybe_cached); // written seconds ago
        write_test(&p2.write_path, 8).unwrap();
        let r = read_test(&p2.read_path).unwrap();
        assert_eq!(r.mb, 8);
        std::thread::sleep(Duration::from_millis(20));
        let p3 = plan(&dir, "James Mac");
        assert!(p3.write_path.ends_with("James_Mac-a.bin"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
