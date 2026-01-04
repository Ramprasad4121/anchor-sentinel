//! # V015 - Sequence Number Mismatch Detector
//!
//! Detects invoke_signed without nonce/blockhash validation, enabling replay attacks.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

pub struct ReplayAttackDetector;

impl ReplayAttackDetector {
    pub fn new() -> Self { Self }

    fn has_replay_protection(&self, source: &str, invoke_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = invoke_line.saturating_sub(20);
        let end = invoke_line;

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("nonce")
                    || lower.contains("recent_blockhash")
                    || lower.contains("sequence")
                    || lower.contains("tx_id")
                    || lower.contains("used_nonces")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for ReplayAttackDetector {
    fn id(&self) -> &'static str { "V015" }
    fn name(&self) -> &'static str { "Sequence Number Mismatch" }
    fn description(&self) -> &'static str {
        "Detects instructions without nonce/sequence protection, enabling replay attacks."
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-294") }
    fn remediation(&self) -> &'static str {
        "Use durable nonces or track used transaction IDs:\n\
         require!(!used_nonces.contains(&nonce), \"Replay detected\");\n\
         used_nonces.insert(nonce);"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        // Look for invoke_signed which often needs replay protection
        let pattern = Regex::new(r"invoke_signed\s*\(").unwrap();

        for (line_num, line) in source.lines().enumerate() {
            if pattern.is_match(line) && !self.has_replay_protection(source, line_num) {
                findings.push(Finding {
                    id: format!("V015-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "invoke_signed without replay protection".to_string(),
                    description: "Signed invocation without nonce/sequence check.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(line.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.60,
                });
            }
        }
        findings
    }
}

impl Default for ReplayAttackDetector {
    fn default() -> Self { Self::new() }
}
