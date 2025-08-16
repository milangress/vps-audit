use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};

pub struct RebootRequiredCheck;
pub struct DiskUsageCheck;
pub struct MemoryUsageCheck;
pub struct CpuUsageCheck;

impl AuditCheck for RebootRequiredCheck {
    fn id(&self) -> &'static str { "system.reboot_required" }
    fn title(&self) -> &'static str { "System does not require reboot" }
    fn categories(&self) -> &'static [&'static str] { &["linux", "performance", "security"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        let reboot_required = ctx.files_exist.get("/var/run/reboot-required").copied().unwrap_or(false);
        let status = if reboot_required { Status::Warn } else { Status::Pass };
        let reason = if reboot_required { "System indicates a reboot is required".into() } else { "No reboot required".into() };
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Reboot to apply pending updates".into()), evidence: None }
    }
}

impl AuditCheck for DiskUsageCheck {
    fn id(&self) -> &'static str { "system.disk_usage" }
    fn title(&self) -> &'static str { "Disk usage is healthy" }
    fn categories(&self) -> &'static [&'static str] { &["performance", "linux"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        let total = ctx.disk.total_bytes as f64;
        let avail = ctx.disk.available_bytes as f64;
        let used_pct = if total > 0.0 { (1.0 - (avail / total)) * 100.0 } else { 0.0 };
        let status = if used_pct < 50.0 { Status::Pass } else if used_pct < 80.0 { Status::Warn } else { Status::Fail };
        let reason = format!("Disk used: {:.0}% (total: {}, available: {})", used_pct, human_bytes(total as u64), human_bytes(avail as u64));
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Clean unused files, logs, images; consider expanding disk".into()), evidence: None }
    }
}

impl AuditCheck for MemoryUsageCheck {
    fn id(&self) -> &'static str { "system.memory_usage" }
    fn title(&self) -> &'static str { "Memory usage is healthy" }
    fn categories(&self) -> &'static [&'static str] { &["performance", "linux"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        // total_memory_bytes includes caches in sysinfo; we approximate with available from /proc/meminfo when possible
        let (total, avail) = read_meminfo().unwrap_or((ctx.system.total_memory_bytes, ctx.system.total_memory_bytes / 2));
        let total_f = total as f64;
        let avail_f = avail as f64;
        let used_pct = if total_f > 0.0 { (1.0 - (avail_f / total_f)) * 100.0 } else { 0.0 };
        let status = if used_pct < 50.0 { Status::Pass } else if used_pct < 80.0 { Status::Warn } else { Status::Fail };
        let reason = format!("Memory used: {:.0}% (total: {}, available: {})", used_pct, human_bytes(total), human_bytes(avail));
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Reduce memory usage, tune services, or increase RAM/swap".into()), evidence: None }
    }
}

impl AuditCheck for CpuUsageCheck {
    fn id(&self) -> &'static str { "system.cpu_usage" }
    fn title(&self) -> &'static str { "CPU usage is healthy" }
    fn categories(&self) -> &'static [&'static str] { &["performance", "linux"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        let load1 = ctx.system.load_average_1m.unwrap_or(0.0);
        // Without external tools, we approximate: load per core
        let cores = num_cpus::get() as f64;
        let load_ratio = if cores > 0.0 { load1 / cores } else { 0.0 };
        let status = if load_ratio < 0.5 { Status::Pass } else if load_ratio < 0.9 { Status::Warn } else { Status::Fail };
        let reason = format!("Load(1m): {:.2}, cores: {}, ratio: {:.2}", load1, cores as u64, load_ratio);
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Investigate high CPU processes, tune services, or scale resources".into()), evidence: None }
    }
}

fn human_bytes(bytes: u64) -> String {
    // Simple IEC units
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut n = bytes as f64;
    let mut idx = 0;
    while n >= 1024.0 && idx < UNITS.len() - 1 {
        n /= 1024.0;
        idx += 1;
    }
    format!("{:.1} {}", n, UNITS[idx])
}

fn read_meminfo() -> Option<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut avail = None;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = parse_kib_line(line);
        } else if line.starts_with("MemAvailable:") {
            avail = parse_kib_line(line);
        }
    }
    Some((total?, avail?))
}

fn parse_kib_line(line: &str) -> Option<u64> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 { return None; }
    let kib: u64 = parts[1].parse().ok()?;
    Some(kib * 1024)
}


