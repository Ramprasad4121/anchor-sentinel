//! # V018 - Error Handling Suppression Detector
//!
//! @title CPI Error Context Detector
//! @author Ramprasad
//!
//! Detects `?` operator on CPIs without custom error mapping,
//! which can hide failures and make debugging difficult.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // Less Ideal: Error context lost
//! invoke(&ix, &accounts)?;  // Generic ProgramError
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // Better: Custom error with context
//! invoke(&ix, &accounts).map_err(|e| {
//!     msg!("CPI failed: {:?}", e);
//!     MyError::CpiFailed
//! })?;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-755: Improper Handling of Exceptional Conditions

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for error handling suppression.
pub struct ErrorSuppressionDetector;

impl ErrorSuppressionDetector {
    pub fn new() -> Self { Self }
}

impl VulnerabilityDetector for ErrorSuppressionDetector {
    fn id(&self) -> &'static str { "V018" }
    fn name(&self) -> &'static str { "Error Handling Suppression" }
    fn description(&self) -> &'static str {
        "Detects ? on CPIs without custom errors, hiding failures."
    }
    fn severity(&self) -> Severity { Severity::Low }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-755") }
    fn remediation(&self) -> &'static str {
        "Handle errors explicitly: .map_err(|e| MyError::from(e))?"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        let pattern = Regex::new(r"invoke(_signed)?\s*\([^)]+\)\s*\?").unwrap();

        for (line_num, line) in source.lines().enumerate() {
            if pattern.is_match(line) && !line.contains("map_err") {
                findings.push(Finding {
                    id: format!("V018-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "CPI error propagated without context".to_string(),
                    description: "CPI uses ? operator without custom error mapping.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(line.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.55,
                });
            }
        }
        findings
    }
}

impl Default for ErrorSuppressionDetector {
    fn default() -> Self { Self::new() }
}
