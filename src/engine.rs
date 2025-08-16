use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult};

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
    }

    pub fn run_all(&self) -> Vec<CheckResult> {
        let collectors = Collectors::collect();
        let mut results = Vec::with_capacity(self.checks.len());
        'outer: for check in &self.checks {
            if let Some(filter) = &self.categories_filter {
                let categories: Vec<String> = check.categories().iter().map(|s| s.to_string()).collect();
                let matches_any = filter.iter().any(|wanted| {
                    categories.iter().any(|c| c.eq_ignore_ascii_case(wanted))
                });
                if !matches_any { continue 'outer; }
            }
            let result = check.run(&collectors);
            results.push(result);
        }
        results
    }
}


