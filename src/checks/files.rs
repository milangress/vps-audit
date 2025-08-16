use crate::collectors::Collectors;
use crate::model::{AuditCheck, CheckResult, Status};
use walkdir::WalkDir;
use std::time::{Duration, Instant};

pub struct SuidFilesCheck;

impl AuditCheck for SuidFilesCheck {
    fn id(&self) -> &'static str { "files.suid_suspicious" }
    fn title(&self) -> &'static str { "No suspicious SUID files exist outside standard locations" }
    fn categories(&self) -> &'static [&'static str] { &["security", "linux"] }
    fn run(&self, _ctx: &Collectors) -> CheckResult {
        let mut suspicious_count = 0usize;
        let mut visited_files = 0usize;
        let start_time = Instant::now();
        let budget = Duration::from_secs(5);
        let max_files = 100_000usize;
        let allowed_prefixes = [
            "/usr/bin",
            "/bin",
            "/sbin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/libexec",
        ];
        let ignored_prefixes = [
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/var/lib/docker",
            "/var/lib/containers",
            "/snap",
            "/boot/efi",
            "/mnt",
            "/media",
            "/tmp",
        ];

        for entry in WalkDir::new("/")
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() { continue; }
            let path = entry.path();
            let p = path.to_string_lossy();
            if ignored_prefixes.iter().any(|pref| p.starts_with(pref)) { continue; }
            visited_files += 1;
            if visited_files >= max_files || start_time.elapsed() > budget { break; }
            if let Ok(meta) = entry.metadata() {
                // Check suid bit (04000)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o4000 != 0 {
                        let is_allowed = allowed_prefixes.iter().any(|pref| p.starts_with(pref));
                        let is_known = is_known_suid_binary(&p);
                        if !(is_allowed || is_known) {
                            suspicious_count += 1;
                        }
                    }
                }
            }
        }
        let timed_out = start_time.elapsed() > budget || visited_files >= max_files;
        let status = if suspicious_count == 0 && !timed_out { Status::Pass } else { Status::Warn };
        let reason = if suspicious_count == 0 && !timed_out {
            "No suspicious SUID files found".into()
        } else if timed_out {
            format!("Partial scan ({} files, ~{}s budget) found {} potential suspicious SUID files", visited_files, budget.as_secs(), suspicious_count)
        } else {
            format!("Found {} potential suspicious SUID files", suspicious_count)
        };
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


