//! # V011 - Weak Authority Delegation Detector
//!
//! Detects set_authority calls without proper revocation paths, leading to stuck funds.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct AuthorityDelegationDetector;

impl AuthorityDelegationDetector {
    pub fn new() -> Self { Self }

    fn has_revocation_path(&self, source: &str, line_num: usize) -> bool {
        let lower = source.to_lowercase();
        // Check if there's a corresponding revocation or owner reset
        lower.contains("set_authority") && lower.contains("authoritytype::accountowner")
            || lower.contains("revoke")
            || lower.contains("close_account")
    }
}

impl VulnerabilityDetector for AuthorityDelegationDetector {
    fn id(&self) -> &'static str { "V011" }
    fn name(&self) -> &'static str { "Weak Authority Delegation" }
    fn description(&self) -> &'static str {
        "Detects delegate/set_authority calls without revocation paths, risking stuck funds."
    }
    fn severity(&self) -> Severity { Severity::High }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-269") }
    fn remediation(&self) -> &'static str {
        "Ensure all authority delegations have corresponding revocation instructions."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"set_authority\s*\(").unwrap(),
            Regex::new(r"delegate\s*\(").unwrap(),
            Regex::new(r"approve\s*\(").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_revocation_path(source, line_num) {
                    findings.push(Finding {
                        id: format!("V011-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "Authority delegation without revocation path".to_string(),
                        description: "Authority is delegated but no revocation mechanism found.".to_string(),
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

impl Default for AuthorityDelegationDetector {
    fn default() -> Self { Self::new() }
}
