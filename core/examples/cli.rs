//! Command-line runner, useful for testing without the app.
//!   cargo run -p netcheck-core --example cli -- settings.json

fn main() {
    let path = std::env::args().nth(1).expect("usage: cli <settings.json>");
    let text = std::fs::read_to_string(&path).expect("read settings");
    let mut s: netcheck_core::Settings = serde_json::from_str(&text).expect("parse settings");
    if let Ok(p) = std::env::var("UNIFI_PASSWORD") {
        s.unifi_password = p;
    }
    let report = netcheck_core::diagnose(&s, &|e| {
        let netcheck_core::Event::Step { label, state, note, .. } = e;
        eprintln!("[{state:>7}] {label} {note}");
    });
    println!("\n== {} ==\n{}\n", report.headline.title, report.headline.detail);
    for f in &report.findings {
        println!("{:?} | {} | {}\n    {}", f.severity, f.area, f.title, f.detail);
    }
    if std::env::var("JSON").is_ok() {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
}
