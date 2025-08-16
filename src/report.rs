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

    pub fn render(&self, results: &[CheckResult]) -> String {
        match self.format {
            OutputFormat::Text => self.render_text(results),
            OutputFormat::Json => self.render_json(results),
        }
    }

    fn print_text(&self, results: &[CheckResult]) {
        println!("{}", self.render_text(results));
    }

    fn render_text(&self, results: &[CheckResult]) -> String {
        let mut s = String::new();
        s.push_str("VPS Audit Results\n");
        s.push_str("=================\n");
        let (pass, warn, fail, skip) = Self::counts(results);
        let score = Self::score(results);
        s.push_str(&format!("Score: {} / 100\n", score));
        s.push_str(&format!("PASS={}, WARN={}, FAIL={}, SKIP={}\n", pass, warn, fail, skip));
        for r in results {
            if !self.verbose && matches!(r.status, Status::Pass | Status::Skip) { continue; }
            s.push_str(&format!("[{}] {}\n", match r.status { Status::Pass => "PASS", Status::Warn => "WARN", Status::Fail => "FAIL", Status::Skip => "SKIP" }, r.title));
            s.push_str(&format!("  id: {}\n", r.id));
            if !r.categories.is_empty() { s.push_str(&format!("  categories: {}\n", r.categories.join(", "))); }
            s.push_str(&format!("  reason: {}\n", r.reason));
            if let Some(remediation) = &r.remediation { s.push_str(&format!("  remediation: {}\n", remediation)); }
            if let Some(evidence) = &r.evidence { s.push_str(&format!("  evidence: {}\n", evidence)); }
            s.push('\n');
        }
        s
    }

    fn print_json(&self, results: &[CheckResult]) { println!("{}", self.render_json(results)); }

    fn render_json(&self, results: &[CheckResult]) -> String {
        let out: Vec<_> = results
            .iter()
            .filter(|r| self.verbose || !matches!(r.status, Status::Pass | Status::Skip))
            .cloned()
            .collect();
        serde_json::to_string_pretty(&out).unwrap()
    }

    pub fn counts(results: &[CheckResult]) -> (usize, usize, usize, usize) {
        let pass = results.iter().filter(|r| matches!(r.status, Status::Pass)).count();
        let warn = results.iter().filter(|r| matches!(r.status, Status::Warn)).count();
        let fail = results.iter().filter(|r| matches!(r.status, Status::Fail)).count();
        let skip = results.iter().filter(|r| matches!(r.status, Status::Skip)).count();
        (pass, warn, fail, skip)
    }

    pub fn score(results: &[CheckResult]) -> u32 {
        // Simple scoring: each check is equal weight: Pass=1, Warn=0.5, Fail=0, Skip excluded
        let mut total = 0.0f32;
        let mut max = 0.0f32;
        for r in results {
            if matches!(r.status, Status::Skip) { continue; }
            max += 1.0;
            total += match r.status { Status::Pass => 1.0, Status::Warn => 0.5, Status::Fail => 0.0, Status::Skip => 0.0 };
        }
        if max == 0.0 { return 100; }
        ((total / max) * 100.0).round() as u32
    }
}


