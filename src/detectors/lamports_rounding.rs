//! # V022 - Lamports Rounding Errors Detector
//!
//! Detects SOL transfers that may lose precision.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct LamportsRoundingDetector;

impl LamportsRoundingDetector {
    pub fn new() -> Self { Self }

    fn has_rounding_protection(&self, source: &str, line_num: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = line_num.saturating_sub(5);
        let end = (line_num + 5).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                if line.contains("saturating_")
                    || line.contains("checked_")
                    || line.contains("LAMPORTS_PER_SOL")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for LamportsRoundingDetector {
    fn id(&self) -> &'static str { "V022" }
    fn name(&self) -> &'static str { "Lamports Rounding Errors" }
    fn description(&self) -> &'static str {
        "Detects SOL transfers with potential precision loss."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-682") }
    fn remediation(&self) -> &'static str {
        "Use saturating_sub for lamport calculations to avoid dust loss."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"\.lamports\s*\(\s*\)\s*[+-]").unwrap(),
            Regex::new(r"\.lamports\s*=").unwrap(),
            Regex::new(r"transfer_lamports").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_rounding_protection(source, line_num) {
                    findings.push(Finding {
                        id: format!("V022-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "Lamport calculation without rounding protection".to_string(),
                        description: "SOL transfer may lose precision or overflow.".to_string(),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.65,
                    });
                    break;
                }
            }
        }
        findings
    }
}

impl Default for LamportsRoundingDetector {
    fn default() -> Self { Self::new() }
}
