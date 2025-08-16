use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};
use std::collections::BTreeSet;
use std::fs;

pub struct ListeningPortsCheck;

impl AuditCheck for ListeningPortsCheck {
    fn id(&self) -> &'static str { "network.listening_ports" }
    fn title(&self) -> &'static str { "Public listening ports are limited" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux", "network"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        let ports = collect_listening_ports();
        let total = ports.len();
        let internet_facing = ports.iter().filter(|p| p.is_public).count();
        let status = if total < 10 && internet_facing < 3 { Status::Pass } else if total < 20 && internet_facing < 5 { Status::Warn } else { Status::Fail };
        let reason = format!("Listening ports total: {}, public: {}", total, internet_facing);
        let evidence = serde_json::json!({
            "ports": ports.iter().map(|p| serde_json::json!({"port": p.port, "proto": p.proto, "public": p.is_public})).collect::<Vec<_>>()
        });
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Close unnecessary ports; bind services to localhost; use a firewall".into()), evidence: Some(evidence) }
    }
}

#[derive(Debug, Clone)]
struct PortInfo { port: u16, proto: &'static str, is_public: bool }

fn collect_listening_ports() -> Vec<PortInfo> {
    let mut ports = BTreeSet::new();
    // IPv4 TCP
    parse_proc_net("/proc/net/tcp", "tcp", &mut ports);
    // IPv6 TCP
    parse_proc_net("/proc/net/tcp6", "tcp6", &mut ports);
    // UDP v4
    parse_proc_net("/proc/net/udp", "udp", &mut ports);
    // UDP v6
    parse_proc_net("/proc/net/udp6", "udp6", &mut ports);
    ports.into_iter().collect()
}

fn parse_proc_net(path: &str, proto: &'static str, set: &mut BTreeSet<PortInfo>) {
    let content = match fs::read_to_string(path) { Ok(s) => s, Err(_) => return };
    for (i, line) in content.lines().enumerate() {
        if i == 0 { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        let local = cols[1]; // ip:port in hex
        let state = cols[3]; // 0A is LISTEN for TCP; for UDP we consider open sockets
        if proto.starts_with("tcp") && state != "0A" { continue; }
        if let Some((_ip_hex, port_hex)) = local.split_once(':') {
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                // public if not bound to 127.0.0.1 or ::1
                let ip_hex = &local[..local.find(':').unwrap_or(local.len())];
                let is_public = !is_loopback_hex(ip_hex, proto);
                set.insert(PortInfo { port, proto, is_public });
            }
        }
    }
}

fn is_loopback_hex(ip_hex: &str, proto: &str) -> bool {
    if proto.ends_with('6') {
        // IPv6 loopback ::1 is 00000000000000000000000000000001
        return ip_hex == "00000000000000000000000000000001";
    }
    // IPv4 127.0.0.1 is 0100007F (little endian in /proc)
    ip_hex.eq_ignore_ascii_case("0100007F")
}

impl PartialEq for PortInfo { fn eq(&self, other: &Self) -> bool { self.port == other.port && self.proto == other.proto && self.is_public == other.is_public } }
impl Eq for PortInfo {}
impl Ord for PortInfo { fn cmp(&self, other: &Self) -> std::cmp::Ordering { (self.port, self.proto).cmp(&(other.port, other.proto)) } }
impl PartialOrd for PortInfo { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) } }


