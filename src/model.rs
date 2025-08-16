use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl Status {
    pub fn is_fail(&self) -> bool { matches!(self, Status::Fail) }
    pub fn is_warn(&self) -> bool { matches!(self, Status::Warn) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub categories: Vec<String>,
    pub status: Status,
    pub reason: String,
    pub remediation: Option<String>,
    pub evidence: Option<serde_json::Value>,
}

pub trait AuditCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn categories(&self) -> &'static [&'static str];
    fn run(&self, ctx: &crate::collectors::Collectors) -> CheckResult;
}


