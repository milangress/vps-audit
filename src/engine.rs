use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub struct AuditEngine {
    categories_filter: Option<Vec<String>>,
    checks: Vec<Box<dyn AuditCheck>>,
}

impl AuditEngine {
    pub fn new(categories_filter: Option<Vec<String>>) -> Self {
        Self { categories_filter, checks: Vec::new() }
    }

    pub fn register<C: AuditCheck + 'static>(&mut self, check: C) {
        self.checks.push(Box::new(check));
    }

    pub fn register_default_checks(&mut self) {
        use crate::checks::*;
        self.register(ssh::SshRootLoginCheck);
        self.register(ssh::SshPasswordAuthCheck);
        self.register(ssh::SshPortCheck);
        self.register(system::RebootRequiredCheck);
        self.register(system::DiskUsageCheck);
        self.register(system::MemoryUsageCheck);
        self.register(system::CpuUsageCheck);
        self.register(policy::SudoLoggingCheck);
        self.register(policy::PasswordPolicyCheck);
        self.register(files::SuidFilesCheck);
        self.register(network::ListeningPortsCheck);
        self.register(firewall::FirewallPresenceCheck);
        self.register(firewall::NftablesRulesCheck);
    }

    pub fn run_all(&self) -> Vec<CheckResult> {
        let collectors = Collectors::collect();
        let mut results = Vec::with_capacity(self.checks.len());
        // Per-check timeout budget to avoid long hangs (e.g., massive filesystem walks)
        let timeout = Duration::from_secs(5);

        thread::scope(|scope| {
            'outer: for check in &self.checks {
                if let Some(filter) = &self.categories_filter {
                    let categories: Vec<String> = check.categories().iter().map(|s| s.to_string()).collect();
                    let matches_any = filter.iter().any(|wanted| {
                        categories.iter().any(|c| c.eq_ignore_ascii_case(wanted))
                    });
                    if !matches_any { continue 'outer; }
                }

                let (tx, rx) = mpsc::channel();
                let collectors_clone = collectors.clone();
                scope.spawn(move || {
                    let result = check.run(&collectors_clone);
                    let _ = tx.send(result);
                });

                match rx.recv_timeout(timeout) {
                    Ok(result) => results.push(result),
                    Err(_) => {
                        results.push(CheckResult {
                            id: check.id().to_string(),
                            title: check.title().to_string(),
                            categories: check.categories().iter().map(|s| s.to_string()).collect(),
                            status: Status::Skip,
                            reason: format!("Check timed out after {}s", timeout.as_secs()),
                            remediation: Some("Re-run with narrower categories or open an issue if this persists".into()),
                            evidence: None,
                        });
                    }
                }
            }
        });

        results
    }
}


