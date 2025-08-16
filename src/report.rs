use crate::model::{CheckResult, Status};

#[derive(Clone, Copy)]
pub enum OutputFormat { Text, Json }

pub struct Reporter {
    verbose: bool,
    format: OutputFormat,
}

impl Reporter {
    pub fn new(verbose: bool, format: OutputFormat) -> Self { Self { verbose, format } }

    pub fn print(&self, results: &[CheckResult]) {
        match self.format {
            OutputFormat::Text => self.print_text(results),
            OutputFormat::Json => self.print_json(results),
        }
    }

    fn print_text(&self, results: &[CheckResult]) {
        println!("VPS Audit Results");
        println!("=================");
        for r in results {
            if !self.verbose && matches!(r.status, Status::Pass | Status::Skip) {
                continue;
            }
            println!("[{}] {}", match r.status { Status::Pass => "PASS", Status::Warn => "WARN", Status::Fail => "FAIL", Status::Skip => "SKIP" }, r.title);
            println!("  id: {}", r.id);
            if !r.categories.is_empty() { println!("  categories: {}", r.categories.join(", ")); }
            println!("  reason: {}", r.reason);
            if let Some(remediation) = &r.remediation { println!("  remediation: {}", remediation); }
            if let Some(evidence) = &r.evidence { println!("  evidence: {}", evidence); }
            println!();
        }
        let counts = Self::counts(results);
        println!("Summary: PASS={}, WARN={}, FAIL={}, SKIP={}", counts.0, counts.1, counts.2, counts.3);
    }

    fn print_json(&self, results: &[CheckResult]) {
        let out: Vec<_> = results
            .iter()
            .filter(|r| self.verbose || !matches!(r.status, Status::Pass | Status::Skip))
            .cloned()
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }

    fn counts(results: &[CheckResult]) -> (usize, usize, usize, usize) {
        let pass = results.iter().filter(|r| matches!(r.status, Status::Pass)).count();
        let warn = results.iter().filter(|r| matches!(r.status, Status::Warn)).count();
        let fail = results.iter().filter(|r| matches!(r.status, Status::Fail)).count();
        let skip = results.iter().filter(|r| matches!(r.status, Status::Skip)).count();
        (pass, warn, fail, skip)
    }
}


