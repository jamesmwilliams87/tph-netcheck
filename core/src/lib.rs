//! TPH Net Check diagnostic engine.
//!
//! Works out why Neptune feels slow from one machine by testing each layer in
//! turn: this machine's link, the path, raw network speed, real file speed,
//! what Neptune is doing, and what the UniFi switches report. Then it turns
//! the evidence into a plain verdict.

pub mod history;
pub mod link;
pub mod ping;
pub mod report;
pub mod run;
pub mod scan;
pub mod settings;
pub mod smb;
pub mod ssh;
pub mod sys;
pub mod throughput;
pub mod unifi;
pub mod verdict;

pub use report::*;
pub use run::{diagnose, Event};
pub use settings::Settings;
