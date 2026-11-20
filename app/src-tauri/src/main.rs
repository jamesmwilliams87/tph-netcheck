// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use netcheck_core::{history, link, scan, ssh, sys, unifi, Report, ScanReport, Settings};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

const KEYRING_SERVICE: &str = "TPH Net Check";
const KEYRING_USER: &str = "unifi";

struct Busy(AtomicBool);

fn config_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

fn history_dir(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join("history"))
}

fn key_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(config_dir(app)?.join("netcheck_key"))
}

fn unifi_password() -> String {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .and_then(|e| e.get_password())
        .unwrap_or_default()
}

/// Settings from disk, plus the key path and the password from the keychain.
fn load_settings(app: &AppHandle) -> Result<Settings, String> {
    let p = config_dir(app)?.join("settings.json");
    let mut s: Settings = std::fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let k = key_path(app)?;
    s.ssh_key_path = if k.exists() { k.display().to_string() } else { String::new() };
    s.unifi_password = unifi_password();
    Ok(s)
}

#[derive(Serialize)]
struct SettingsView {
    settings: Settings,
    has_key: bool,
    has_unifi_password: bool,
    machine: String,
    os: String,
}

#[tauri::command]
fn get_settings(app: AppHandle) -> Result<SettingsView, String> {
    let s = load_settings(&app)?;
    Ok(SettingsView {
        has_key: !s.ssh_key_path.is_empty(),
        has_unifi_password: !s.unifi_password.is_empty(),
        settings: s,
        machine: sys::hostname(),
        os: sys::os_name(),
    })
}

#[tauri::command]
fn save_settings(app: AppHandle, settings: Settings, unifi_password: Option<String>) -> Result<(), String> {
    let p = config_dir(&app)?.join("settings.json");
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(p, json).map_err(|e| e.to_string())?;
    if let Some(pw) = unifi_password.filter(|p| !p.is_empty()) {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .and_then(|e| e.set_password(&pw))
            .map_err(|e| format!("Could not store the UniFi password in the keychain: {e}"))?;
    }
    Ok(())
}

/// Saves the private key the team shares for Neptune, readable by this user only.
#[tauri::command]
fn import_key(app: AppHandle, private_key: String) -> Result<(), String> {
    let text = private_key.trim().replace("\r\n", "\n");
    if !text.starts_with("-----BEGIN") || !text.contains("PRIVATE KEY-----") {
        return Err("That does not look like a private key. Paste the whole file, including the BEGIN and END lines.".into());
    }
    let p = key_path(&app)?;
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, format!("{text}\n")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    {
        // OpenSSH on Windows refuses keys other accounts can read.
        let user = std::env::var("USERNAME").unwrap_or_default();
        let path = p.display().to_string();
        let grant = format!("{user}:F");
        let out = sys::command("icacls")
            .args([path.as_str(), "/inheritance:r", "/grant:r", grant.as_str()])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("Could not lock down the key file: {}", String::from_utf8_lossy(&out.stdout)));
        }
    }
    Ok(())
}

#[tauri::command]
fn remove_key(app: AppHandle) -> Result<(), String> {
    let p = key_path(&app)?;
    if p.exists() {
        std::fs::remove_file(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Serialize)]
struct NeptuneCheck {
    hostname: String,
    cores: usize,
    mem_total_mb: u64,
    interfaces: Vec<String>,
}

#[tauri::command]
async fn test_neptune(app: AppHandle) -> Result<NeptuneCheck, String> {
    let s = load_settings(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let snap = ssh::stats(&s, 1)?;
        let info = snap.info.ok_or("No answer from Neptune")?;
        Ok(NeptuneCheck {
            hostname: info.hostname,
            cores: info.cores,
            mem_total_mb: info.mem_total_mb,
            interfaces: info
                .interfaces
                .iter()
                .filter(|i| i.up && !i.ipv4.is_empty())
                .map(|i| {
                    format!(
                        "{} {} at {}, MTU {}",
                        i.name,
                        i.ipv4.join(", "),
                        i.speed_mbps.map(netcheck_core::verdict::speed_label).unwrap_or("unknown speed".into()),
                        i.mtu.map(|m| m.to_string()).unwrap_or("?".into())
                    )
                })
                .collect(),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_unifi(app: AppHandle) -> Result<String, String> {
    let s = load_settings(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let c = unifi::Unifi::login(&s)?;
        let snap = c.snapshot()?;
        let names: Vec<String> = snap.switches.iter().map(|x| format!("{} ({} ports)", x.name, x.ports.len())).collect();
        Ok(format!("Connected. Switches: {}. Clients seen: {}.", if names.is_empty() { "none".into() } else { names.join(", ") }, snap.clients.len()))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn run_diagnosis(app: AppHandle, busy: State<'_, Busy>) -> Result<Report, String> {
    if busy.0.swap(true, Ordering::SeqCst) {
        return Err("A check is already running".into());
    }
    let s = load_settings(&app);
    let a2 = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<Report, String> {
        let s = s?;
        let report = netcheck_core::diagnose(&s, &|e| {
            let _ = a2.emit("step", e);
        });
        if let Ok(dir) = history_dir(&a2) {
            let _ = history::save(&dir, &report);
        }
        Ok(report)
    })
    .await
    .map_err(|e| e.to_string());
    busy.0.store(false, Ordering::SeqCst);
    result?
}

#[tauri::command]
async fn run_scan(app: AppHandle, busy: State<'_, Busy>) -> Result<ScanReport, String> {
    if busy.0.swap(true, Ordering::SeqCst) {
        return Err("A check is already running".into());
    }
    let s = load_settings(&app);
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<ScanReport, String> {
        let s = s?;
        let nip = sys::resolve_ipv4(&s.neptune_host).ok_or("Neptune's address is not set or cannot be resolved")?;
        let l = link::detect(&nip)?;
        let u = if s.unifi_ready() {
            unifi::Unifi::login(&s).ok().and_then(|c| {
                let a = c.snapshot().ok()?;
                Some(unifi::compare(&a, &a, None, Some(&nip), vec![]))
            })
        } else {
            None
        };
        scan::scan(&l, &s, Some(&nip), u.as_ref())
    })
    .await
    .map_err(|e| e.to_string());
    busy.0.store(false, Ordering::SeqCst);
    result?
}

#[tauri::command]
fn list_history(app: AppHandle) -> Result<Vec<history::Summary>, String> {
    Ok(history::list(&history_dir(&app)?))
}

#[tauri::command]
fn load_history(app: AppHandle, id: String) -> Result<Report, String> {
    history::load(&history_dir(&app)?, &id)
}

fn main() {
    tauri::Builder::default()
        .manage(Busy(AtomicBool::new(false)))
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            import_key,
            remove_key,
            test_neptune,
            test_unifi,
            run_diagnosis,
            run_scan,
            list_history,
            load_history
        ])
        .run(tauri::generate_context!())
        .expect("error while running TPH Net Check");
}
