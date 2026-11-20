//! Keeps past reports as JSON files so a slow day can be compared with a normal one.

use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::report::{Report, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub id: String,
    pub started_at_ms: u64,
    pub machine: String,
    pub severity: Severity,
    pub headline: String,
    pub link_mbps: Option<u64>,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub write_mb_s: Option<f64>,
    pub read_mb_s: Option<f64>,
}

const KEEP: usize = 200;

pub fn save(dir: &Path, r: &Report) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    fs::write(dir.join(format!("{}.json", r.id)), json).map_err(|e| e.to_string())?;
    prune(dir);
    Ok(())
}

fn ids(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_string))
                .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b.cmp(a));
    v
}

fn prune(dir: &Path) {
    for old in ids(dir).into_iter().skip(KEEP) {
        let _ = fs::remove_file(dir.join(format!("{old}.json")));
    }
}

pub fn load(dir: &Path, id: &str) -> Result<Report, String> {
    if !id.chars().all(|c| c.is_ascii_digit()) {
        return Err("bad id".into());
    }
    let text = fs::read_to_string(dir.join(format!("{id}.json"))).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

pub fn list(dir: &Path) -> Vec<Summary> {
    ids(dir)
        .into_iter()
        .filter_map(|id| load(dir, &id).ok())
        .map(|r| Summary {
            id: r.id.clone(),
            started_at_ms: r.started_at_ms,
            machine: r.machine.clone(),
            severity: r.headline.severity,
            headline: r.headline.title.clone(),
            link_mbps: r.link.as_ref().and_then(|l| l.speed_mbps),
            download_mbps: r.throughput.as_ref().and_then(|t| t.download_mbps),
            upload_mbps: r.throughput.as_ref().and_then(|t| t.upload_mbps),
            write_mb_s: r.smb.as_ref().and_then(|s| s.write_mb_s),
            read_mb_s: r.smb.as_ref().and_then(|s| s.read_mb_s),
        })
        .collect()
}
