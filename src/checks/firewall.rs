use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};
use std::fs;
use std::path::Path;

pub struct FirewallPresenceCheck;

impl AuditCheck for FirewallPresenceCheck {
    fn id(&self) -> &'static str { "firewall.presence" }
    fn title(&self) -> &'static str { "A firewall is installed and configured" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux", "network"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        // Self-contained heuristic (no external binaries): look for config files and ruleset files commonly present.
        // nftables: /etc/nftables.conf or /etc/nftables/*.conf
        // iptables: iptables-save files may exist in /etc/iptables/
        // ufw: /etc/ufw/ufw.conf
        let nft_present = Path::new("/etc/nftables.conf").exists() || Path::new("/etc/nftables").exists();
        let ufw_present = Path::new("/etc/ufw/ufw.conf").exists();
        let ipt_present = Path::new("/etc/iptables").exists();

        // Also check systemd unit files existence as a hint
        let nft_unit = Path::new("/lib/systemd/system/nftables.service").exists() || Path::new("/etc/systemd/system/nftables.service").exists();
        let ufw_unit = Path::new("/lib/systemd/system/ufw.service").exists() || Path::new("/etc/systemd/system/ufw.service").exists();

        let any_present = nft_present || ufw_present || ipt_present || nft_unit || ufw_unit;
        let status = if any_present { Status::Warn } else { Status::Fail }; // Warn because presence != active
        let reason = if any_present { "Firewall tooling detected (verify active rules)".into() } else { "No firewall tooling detected".into() };
        let evidence = serde_json::json!({"nftables": nft_present || nft_unit, "ufw": ufw_present || ufw_unit, "iptables": ipt_present});

        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Install and enable nftables (preferred) or UFW; define a default-deny inbound policy with explicit allows".into()), evidence: Some(evidence) }
    }
}

pub struct NftablesRulesCheck;

impl AuditCheck for NftablesRulesCheck {
    fn id(&self) -> &'static str { "firewall.nftables_rules" }
    fn title(&self) -> &'static str { "nftables has default-deny inbound policy with explicit allows" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux", "network"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        // Best-effort parse nftables config files for a default drop on input and explicit accepts
        let paths = ["/etc/nftables.conf", "/etc/nftables"]; // directory or file
        let mut content = String::new();
        for p in &paths {
            let path = Path::new(p);
            if path.is_file() {
                if let Ok(c) = fs::read_to_string(path) { content.push_str(&c); content.push('\n'); }
            } else if path.is_dir() {
                if let Ok(rd) = fs::read_dir(path) {
                    for entry in rd.flatten() {
                        let ep = entry.path();
                        if ep.extension().map(|e| e == "conf").unwrap_or(false) {
                            if let Ok(c) = fs::read_to_string(&ep) { content.push_str(&c); content.push('\n'); }
                        }
                    }
                }
            }
        }
        if content.is_empty() {
            return CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status: Status::Skip, reason: "No nftables configuration files found".into(), remediation: Some("Create /etc/nftables.conf with a default deny policy".into()), evidence: None };
        }

        let has_input_chain = content.contains("chain input");
        let has_default_drop = content.lines().any(|l| l.contains("type filter hook input") && l.contains("policy drop")) || content.lines().any(|l| l.contains("chain input") && l.contains("policy drop"));
        let has_accept_ssh = content.contains("tcp dport 22 accept") || content.contains("ct state established,related accept");

        let status = if has_input_chain && has_default_drop { Status::Pass } else { Status::Warn };
        let reason = if status == Status::Pass { "Found input chain with policy drop".into() } else { "Default drop policy not clearly configured in nftables".into() };
        let evidence = serde_json::json!({"input_chain": has_input_chain, "default_drop": has_default_drop, "has_accept_examples": has_accept_ssh});
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Define 'chain input { type filter hook input priority 0; policy drop; ... }' with explicit allows".into()), evidence: Some(evidence) }
    }
}


