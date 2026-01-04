//! # V008 - Missing PDA Bump Check Detector
//!
//! @title PDA Bump Verification Detector
//! @author Ramprasad
//!
//! Detects PDAs created with `find_program_address` or `create_program_address`
//! without proper bump verification. Missing bump checks allow seed grinding attacks.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for missing PDA bump verification.
pub struct PdaBumpDetector;

impl PdaBumpDetector {
    pub fn new() -> Self {
        Self
    }

    /// Checks if bump verification exists near a PDA derivation.
    fn has_bump_verification(&self, source: &str, pda_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = pda_line.saturating_sub(1);
        let end = (pda_line + 10).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("assert_eq!(bump")
                    || lower.contains("assert!(bump")
                    || lower.contains("require!(bump")
                    || lower.contains("require_eq!(bump")
                    || lower.contains("bump ==")
                    || lower.contains(".bump")
                    || lower.contains("bump:")
                {
                    return true;
                }
            }
        }
        false
    }

    fn extract_seeds(&self, line: &str) -> String {
        if let Some(start) = line.find("&[") {
            if let Some(end) = line[start..].find(']') {
                return line[start..start + end + 1].to_string();
            }
        }
        "unknown seeds".to_string()
    }
}

impl VulnerabilityDetector for PdaBumpDetector {
    fn id(&self) -> &'static str { "V008" }
    fn name(&self) -> &'static str { "Missing PDA Bump Check" }
    fn description(&self) -> &'static str {
        "Detects PDA derivations without bump verification, enabling seed grinding attacks."
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-330") }
    fn remediation(&self) -> &'static str {
        "Verify the PDA bump: store bump during init, use assert_eq!(bump, stored_bump)"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"find_program_address\s*\(").unwrap(),
            Regex::new(r"create_program_address\s*\(").unwrap(),
            Regex::new(r"Pubkey::find_program_address").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_bump_verification(source, line_num) {
                    let seeds = self.extract_seeds(line);
                    
                    findings.push(Finding {
                        id: format!("V008-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "PDA derivation without bump verification".to_string(),
                        description: format!(
                            "PDA derived with {} but bump is not verified. Attackers can \
                             perform seed grinding attacks.", seeds
                        ),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.85,
                    });
                }
            }
        }
        findings
    }
}

impl Default for PdaBumpDetector {
    fn default() -> Self { Self::new() }
}
