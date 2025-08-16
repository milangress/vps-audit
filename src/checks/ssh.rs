use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};

pub struct SshRootLoginCheck;
pub struct SshPasswordAuthCheck;
pub struct SshPortCheck;

impl AuditCheck for SshRootLoginCheck {
    fn id(&self) -> &'static str { "ssh.root_login" }
    fn title(&self) -> &'static str { "SSH root login is disabled" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux", "config"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        if let Some(sshd) = &ctx.sshd {
            if !sshd.ok {
                return CheckResult {
                    id: self.id().to_string(),
                    title: self.title().to_string(),
                    categories: self.categories().iter().map(|s| s.to_string()).collect(),
                    status: Status::Skip,
                    reason: format!("Unable to obtain sshd config: {}", sshd.stderr.clone().unwrap_or_default()),
                    remediation: Some("Ensure OpenSSH server is installed and accessible".into()),
                    evidence: None,
                };
            }
            let value = sshd.values.get("permitrootlogin").cloned().unwrap_or_else(|| "prohibit-password".to_string());
            let status = if value == "no" || value == "prohibit-password" { Status::Pass } else { Status::Fail };
            let reason = match status {
                Status::Pass => format!("PermitRootLogin is '{}'", value),
                Status::Fail => format!("PermitRootLogin is '{}' (should be 'no' or 'prohibit-password')", value),
                _ => unreachable!(),
            };
            return CheckResult {
                id: self.id().to_string(),
                title: self.title().to_string(),
                categories: self.categories().iter().map(|s| s.to_string()).collect(),
                status,
                reason,
                remediation: Some("Edit sshd_config to set PermitRootLogin no or prohibit-password; then systemctl reload sshd".into()),
                evidence: Some(serde_json::json!({"permitrootlogin": value})),
            };
        }
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status: Status::Skip, reason: "OpenSSH server configuration not found".into(), remediation: None, evidence: None }
    }
}

impl AuditCheck for SshPasswordAuthCheck {
    fn id(&self) -> &'static str { "ssh.password_auth" }
    fn title(&self) -> &'static str { "SSH password authentication is disabled" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux", "config"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        if let Some(sshd) = &ctx.sshd {
            if !sshd.ok {
                return CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status: Status::Skip, reason: "Unable to obtain sshd config".into(), remediation: None, evidence: None };
            }
            let value = sshd.values.get("passwordauthentication").cloned().unwrap_or_else(|| "yes".to_string());
            let status = if value == "no" { Status::Pass } else { Status::Fail };
            let reason = match status {
                Status::Pass => "PasswordAuthentication is 'no'".to_string(),
                Status::Fail => format!("PasswordAuthentication is '{}' (should be 'no')", value),
                _ => unreachable!(),
            };
            return CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Set PasswordAuthentication no; enforce key-based auth".into()), evidence: Some(serde_json::json!({"passwordauthentication": value})) };
        }
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status: Status::Skip, reason: "OpenSSH server configuration not found".into(), remediation: None, evidence: None }
    }
}

impl AuditCheck for SshPortCheck {
    fn id(&self) -> &'static str { "ssh.port" }
    fn title(&self) -> &'static str { "SSH uses a non-default and privileged port" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux", "config"] }
    fn run(&self, ctx: &Collectors) -> CheckResult {
        if let Some(sshd) = &ctx.sshd {
            if !sshd.ok {
                return CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status: Status::Skip, reason: "Unable to obtain sshd config".into(), remediation: None, evidence: None };
            }
            let port_str = sshd.values.get("port").cloned().unwrap_or_else(|| "22".to_string());
            let port: u16 = port_str.parse().unwrap_or(22);
            // Linux kernel unprivileged start defaults to 1024; system tunable sometimes at net.ipv4.ip_unprivileged_port_start
            let unpriv_start = read_unprivileged_start().unwrap_or(1024);
            let status = if port == 22 {
                Status::Warn
            } else if port >= unpriv_start as u16 {
                Status::Fail
            } else {
                Status::Pass
            };
            let reason = match status {
                Status::Pass => format!("Using privileged non-default port {} (< {})", port, unpriv_start),
                Status::Warn => "Using default SSH port 22".to_string(),
                Status::Fail => format!("Using unprivileged port {} (>= {})", port, unpriv_start),
                _ => unreachable!(),
            };
            return CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some(format!("Choose a port < {} and not 22; update sshd_config and reload", unpriv_start)), evidence: Some(serde_json::json!({"port": port})) };
        }
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status: Status::Skip, reason: "OpenSSH server configuration not found".into(), remediation: None, evidence: None }
    }
}

fn read_unprivileged_start() -> Option<u32> {
    // Read from procfs if available to avoid external binary dependency
    if let Ok(s) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start") {
        return s.trim().parse::<u32>().ok();
    }
    // Fallback default
    Some(1024)
}


