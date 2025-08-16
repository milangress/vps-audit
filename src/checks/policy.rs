use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};
use std::fs;

pub struct SudoLoggingCheck;
pub struct PasswordPolicyCheck;

impl AuditCheck for SudoLoggingCheck {
    fn id(&self) -> &'static str { "policy.sudo_logging" }
    fn title(&self) -> &'static str { "Sudo logging is enabled" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        // Parse /etc/sudoers for Defaults logfile=... without invoking visudo
        let content = fs::read_to_string("/etc/sudoers").unwrap_or_default();
        let enabled = content.lines().any(|l| l.trim().starts_with("Defaults") && l.contains("logfile"));
        let status = if enabled { Status::Pass } else { Status::Fail };
        let reason = if enabled { "Found Defaults logfile in /etc/sudoers".into() } else { "No Defaults logfile directive found in /etc/sudoers".into() };
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers via visudo".into()), evidence: None }
    }
}

impl AuditCheck for PasswordPolicyCheck {
    fn id(&self) -> &'static str { "policy.password_policy" }
    fn title(&self) -> &'static str { "Strong password policy is enforced" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        let content = fs::read_to_string("/etc/security/pwquality.conf").unwrap_or_default();
        // Check for minlen >= 12 as in the bash script idea
        let mut minlen_ok = false;
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.starts_with("minlen") {
                if let Some((_, v)) = line.split_once('=') {
                    if v.trim().parse::<u32>().unwrap_or(0) >= 12 { minlen_ok = true; }
                }
            }
        }
        let status = if minlen_ok { Status::Pass } else { Status::Fail };
        let reason = if minlen_ok { "minlen >= 12 configured".into() } else { "minlen < 12 or no policy configured".into() };
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Configure /etc/security/pwquality.conf with 'minlen=12' or higher".into()), evidence: None }
    }
}


