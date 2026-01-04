//! # V012 - Rent Exemption Bypass Detector
//!
//! Detects account creation without rent exemption calculation.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct RentBypassDetector;

impl RentBypassDetector {
    pub fn new() -> Self { Self }

    fn has_rent_check(&self, source: &str, create_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = create_line.saturating_sub(10);
        let end = (create_line + 5).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                if line.contains("minimum_balance")
                    || line.contains("rent")
                    || line.contains("LAMPORTS_PER_SOL")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for RentBypassDetector {
    fn id(&self) -> &'static str { "V012" }
    fn name(&self) -> &'static str { "Rent Exemption Bypass" }
    fn description(&self) -> &'static str {
        "Detects account creation without rent exemption calculation, causing DoS via underfunding."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-400") }
    fn remediation(&self) -> &'static str {
        "Calculate rent: Rent::get()?.minimum_balance(space)"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let pattern = Regex::new(r"create_account\s*\(").unwrap();

        for (line_num, line) in source.lines().enumerate() {
            if pattern.is_match(line) && !self.has_rent_check(source, line_num) {
                findings.push(Finding {
                    id: format!("V012-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "Account creation without rent calculation".to_string(),
                    description: "create_account without rent exemption check.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(line.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.75,
                });
            }
        }
        findings
    }
}

impl Default for RentBypassDetector {
    fn default() -> Self { Self::new() }
}
