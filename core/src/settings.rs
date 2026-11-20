use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Neptune's IP address or hostname.
    pub neptune_host: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    /// Path to the private key. Managed by the app.
    pub ssh_key_path: String,
    /// Where tph-netcheck-server lives on Neptune.
    pub server_path: String,
    pub test_port: u16,
    /// A folder on the Neptune share as this machine sees it,
    /// e.g. /Volumes/Projects/_netcheck or Z:\_netcheck
    pub smb_test_dir: String,
    pub smb_test_size_mb: u64,
    pub throughput_seconds: u32,
    pub throughput_streams: u32,
    /// UniFi Network controller, e.g. https://192.168.1.20:8443
    pub unifi_url: String,
    pub unifi_site: String,
    pub unifi_user: String,
    /// Never written to disk. The app keeps it in the system keychain.
    #[serde(skip)]
    pub unifi_password: String,
    pub unifi_insecure_tls: bool,
    /// Something on the internet to ping.
    pub internet_target: String,
    /// What a healthy link should run at, in Mb/s.
    pub expected_link_mbps: u64,
    /// Devices to label in the isolation check.
    pub known_devices: Vec<KnownDevice>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnownDevice {
    pub name: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub ip: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            neptune_host: String::new(),
            ssh_user: "netcheck".into(),
            ssh_port: 22,
            ssh_key_path: String::new(),
            server_path: "/volume1/tools/tph-netcheck/tph-netcheck-server".into(),
            test_port: netcheck_proto::DEFAULT_PORT,
            smb_test_dir: String::new(),
            smb_test_size_mb: 2048,
            throughput_seconds: 8,
            throughput_streams: 4,
            unifi_url: String::new(),
            unifi_site: "default".into(),
            unifi_user: String::new(),
            unifi_password: String::new(),
            unifi_insecure_tls: true,
            internet_target: "1.1.1.1".into(),
            expected_link_mbps: 10_000,
            known_devices: Vec::new(),
        }
    }
}

impl Settings {
    pub fn ssh_ready(&self) -> bool {
        !self.neptune_host.is_empty() && !self.ssh_user.is_empty() && !self.ssh_key_path.is_empty() && !self.server_path.is_empty()
    }
    pub fn unifi_ready(&self) -> bool {
        !self.unifi_url.is_empty() && !self.unifi_user.is_empty() && !self.unifi_password.is_empty()
    }
}
