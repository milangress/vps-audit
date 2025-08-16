use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};
use walkdir::WalkDir;

pub struct SuidFilesCheck;

impl AuditCheck for SuidFilesCheck {
    fn id(&self) -> &'static str { "files.suid_suspicious" }
    fn title(&self) -> &'static str { "No suspicious SUID files exist outside standard locations" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        let mut suspicious_count = 0usize;
        let allowed_prefixes = [
            "/usr/bin",
            "/bin",
            "/sbin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/libexec",
        ];
        for entry in WalkDir::new("/").into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() { continue; }
            let path = entry.path();
            if let Ok(meta) = entry.metadata() {
                // Check suid bit (04000)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o4000 != 0 {
                        let p = path.to_string_lossy();
                        let is_allowed = allowed_prefixes.iter().any(|pref| p.starts_with(pref));
                        let is_known = is_known_suid_binary(&p);
                        if !(is_allowed || is_known) {
                            suspicious_count += 1;
                        }
                    }
                }
            }
        }
        let status = if suspicious_count == 0 { Status::Pass } else { Status::Warn };
        let reason = if suspicious_count == 0 { "No suspicious SUID files found".into() } else { format!("Found {} potential suspicious SUID files", suspicious_count) };
        CheckResult { id: self.id().to_string(), title: self.title().to_string(), categories: self.categories().iter().map(|s| s.to_string()).collect(), status, reason, remediation: Some("Investigate SUID files; remove SUID bit if unnecessary".into()), evidence: None }
    }
}

fn is_known_suid_binary(path: &str) -> bool {
    let known = [
        "/usr/bin/ping",
        "/usr/bin/sudo",
        "/bin/mount",
        "/bin/umount",
        "/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/chfn",
    ];
    known.iter().any(|k| path.ends_with(k))
}


