//! # V019 - Loop Iteration Overflows Detector
//!
//! Detects unbounded loops on dynamic arrays without length limits.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct LoopOverflowDetector;

impl LoopOverflowDetector {
    pub fn new() -> Self { Self }

    fn has_bounds_check(&self, source: &str, loop_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = loop_line.saturating_sub(10);
        let end = loop_line;

        for i in start..end {
            if let Some(line) = lines.get(i) {
                if line.contains(".len() <=")
                    || line.contains(".len() <")
                    || line.contains("MAX_")
                    || line.contains("require!(")
                    || line.contains("take(")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for LoopOverflowDetector {
    fn id(&self) -> &'static str { "V019" }
    fn name(&self) -> &'static str { "Loop Iteration Overflows" }
    fn description(&self) -> &'static str {
        "Detects unbounded loops without length limits, causing DoS."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-834") }
    fn remediation(&self) -> &'static str {
        "Bound loop iterations: for item in items.iter().take(MAX_ITEMS)"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let pattern = Regex::new(r"for\s+\w+\s+in\s+\w+\.iter\(\)").unwrap();

        for (line_num, line) in source.lines().enumerate() {
            if pattern.is_match(line) && !self.has_bounds_check(source, line_num) {
                findings.push(Finding {
                    id: format!("V019-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "Unbounded loop iteration".to_string(),
                    description: "Loop over dynamic array without bounds check.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(line.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.70,
                });
            }
        }
        findings
    }
}

impl Default for LoopOverflowDetector {
    fn default() -> Self { Self::new() }
}
