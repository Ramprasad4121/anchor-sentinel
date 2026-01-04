//! # V014 - Oracle Dependency Risks Detector
//!
//! Detects oracle calls without staleness or validity checks.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct OracleRisksDetector;

impl OracleRisksDetector {
    pub fn new() -> Self { Self }

    fn has_staleness_check(&self, source: &str, oracle_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = oracle_line;
        let end = (oracle_line + 15).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("timestamp")
                    || lower.contains("staleness")
                    || lower.contains("price > 0")
                    || lower.contains("price != 0")
                    || lower.contains("updated_at")
                    || lower.contains("clock")
                    || lower.contains("slot")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for OracleRisksDetector {
    fn id(&self) -> &'static str { "V014" }
    fn name(&self) -> &'static str { "Oracle Dependency Risks" }
    fn description(&self) -> &'static str {
        "Detects oracle price feeds without staleness or validity checks."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-829") }
    fn remediation(&self) -> &'static str {
        "Validate oracle data:\n\
         require!(price > 0, \"Invalid price\");\n\
         require!(clock.slot - last_update < MAX_STALENESS, \"Stale price\");"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"pyth").unwrap(),
            Regex::new(r"switchboard").unwrap(),
            Regex::new(r"chainlink").unwrap(),
            Regex::new(r"oracle").unwrap(),
            Regex::new(r"price_feed").unwrap(),
            Regex::new(r"get_price").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            let lower = line.to_lowercase();
            for pattern in &patterns {
                if pattern.is_match(&lower) && !self.has_staleness_check(source, line_num) {
                    findings.push(Finding {
                        id: format!("V014-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "Oracle usage without staleness check".to_string(),
                        description: "Price feed used without validating freshness or value.".to_string(),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.65,
                    });
                    break; // Only one finding per line
                }
            }
        }
        findings
    }
}

impl Default for OracleRisksDetector {
    fn default() -> Self { Self::new() }
}
