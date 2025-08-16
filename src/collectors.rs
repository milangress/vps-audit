use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use sysinfo::{Disks, System};

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hostname: Option<String>,
    pub os_pretty_name: Option<String>,
    pub kernel_version: Option<String>,
    pub uptime_seconds: u64,
    pub total_memory_bytes: u64,
    pub total_swap_bytes: u64,
    pub load_average_1m: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshdConfigDump {
    pub ok: bool,
    pub values: BTreeMap<String, String>,
    pub stderr: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Collectors {
    pub system: SystemInfo,
    pub disk: DiskInfo,
    pub sshd: Option<SshdConfigDump>,
    pub files_exist: BTreeMap<String, bool>,
}

impl Collectors {
    pub fn collect() -> Self {
        let system = System::new_all();

        let hostname = System::host_name();
        let kernel_version = System::kernel_version();
        let uptime_seconds = System::uptime();
        let total_memory_bytes = system.total_memory();
        let total_swap_bytes = system.total_swap();

        // Parse /etc/os-release PRETTY_NAME
        let os_pretty_name = fs::read_to_string("/etc/os-release").ok().and_then(|content| {
            for line in content.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                    let val = rest.trim().trim_matches('"').to_string();
                    return Some(val);
                }
            }
            None
        });

        let disks = Disks::new_with_refreshed_list();
        let mut total = 0u64;
        let mut avail = 0u64;
        for disk in disks.list() {
            total = total.saturating_add(disk.total_space());
            avail = avail.saturating_add(disk.available_space());
        }

        let load_average_1m = read_loadavg();

        let sshd = dump_sshd_config();

        let mut files_exist = BTreeMap::new();
        for path in [
            "/var/run/reboot-required",
            "/etc/sudoers",
            "/etc/security/pwquality.conf",
        ] {
            files_exist.insert(path.to_string(), Path::new(path).exists());
        }

        Self {
            system: SystemInfo {
                hostname,
                os_pretty_name,
                kernel_version,
                uptime_seconds,
                total_memory_bytes,
                total_swap_bytes,
                load_average_1m,
            },
            disk: DiskInfo { total_bytes: total, available_bytes: avail },
            sshd,
            files_exist,
        }
    }
}

fn read_loadavg() -> Option<f64> {
    if let Ok(content) = fs::read_to_string("/proc/loadavg") {
        let mut parts = content.split_whitespace();
        if let Some(first) = parts.next() {
            return first.parse::<f64>().ok();
        }
    }
    None
}

fn dump_sshd_config() -> Option<SshdConfigDump> {
    // Prefer robust `sshd -T` (effective config). Fallback to parsing file if sshd missing.
    if let Ok(output) = std::process::Command::new("sshd").arg("-T").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut map = BTreeMap::new();
            for line in stdout.lines() {
                if let Some((k, v)) = line.split_once(' ') {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
            return Some(SshdConfigDump { ok: true, values: map, stderr: None });
        } else {
            return Some(SshdConfigDump { ok: false, values: BTreeMap::new(), stderr: Some(String::from_utf8_lossy(&output.stderr).to_string()) });
        }
    }

    // Fallback: try to read sshd_config to avoid external deps; best-effort.
    let mut map = BTreeMap::new();
    if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let lower = line.to_lowercase();
            if let Some((k, v)) = lower.split_once(' ') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        return Some(SshdConfigDump { ok: true, values: map, stderr: None });
    }

    None
}


