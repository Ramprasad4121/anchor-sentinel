//! # V009 - Reentrancy via CPI Detector
//!
//! Detects potential reentrancy through CPI chains without state guards.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct CpiReentrancyDetector;

impl CpiReentrancyDetector {
    pub fn new() -> Self { Self }

    fn has_reentrancy_guard(&self, source: &str, cpi_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = cpi_line.saturating_sub(15);
        let end = cpi_line;

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("reentrancy")
                    || lower.contains("lock")
                    || lower.contains("processing = true")
                    || lower.contains("is_locked")
                    || lower.contains("mutex")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for CpiReentrancyDetector {
    fn id(&self) -> &'static str { "V009" }
    fn name(&self) -> &'static str { "Reentrancy via CPI" }
    fn description(&self) -> &'static str {
        "Detects CPI calls without reentrancy protection, enabling recursive drain attacks."
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-841") }
    fn remediation(&self) -> &'static str {
        "Add reentrancy guard before CPI:\n\
         ctx.accounts.state.is_processing = true;\n\
         // ... CPI call ...\n\
         ctx.accounts.state.is_processing = false;"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"invoke\s*\(").unwrap(),
            Regex::new(r"invoke_signed\s*\(").unwrap(),
            Regex::new(r"CpiContext::new").unwrap(),
            Regex::new(r"anchor_lang::solana_program::program::invoke").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_reentrancy_guard(source, line_num) {
                    findings.push(Finding {
                        id: format!("V009-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "CPI without reentrancy guard".to_string(),
                        description: "Cross-program invocation without reentrancy protection.".to_string(),
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
        }
        findings
    }
}

impl Default for CpiReentrancyDetector {
    fn default() -> Self { Self::new() }
}
