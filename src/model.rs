use clap::ValueEnum;
use serde::Serialize;
use std::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
#[derive(Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub file: String,
    pub location: Option<String>,
    pub detail: String,
    pub recommendation: &'static str,
}
#[derive(Serialize)]
pub struct Report {
    pub scanned_files: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}
