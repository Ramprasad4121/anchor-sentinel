//! # V015 - Sequence Number Mismatch Detector
//!
//! @title Replay Attack Prevention Detector
//! @author Ramprasad
//!
//! Detects `invoke_signed` calls without nonce or sequence number protection,
//! which can enable transaction replay attacks.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: No replay protection
//! invoke_signed(&ix, accounts, signer_seeds)?;
//! // Transaction can be replayed!
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Using nonces for replay protection
//! require!(!used_nonces.contains(&nonce), ErrorCode::ReplayAttack);
//! used_nonces.insert(nonce);
//! invoke_signed(&ix, accounts, signer_seeds)?;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-294: Authentication Bypass by Capture-replay

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for replay attack vulnerabilities.
///
/// Identifies `invoke_signed` calls that lack nonce or sequence protection,
/// which could allow transaction replay attacks.
pub struct ReplayAttackDetector;

impl ReplayAttackDetector {
    /// Creates a new replay attack detector instance.
    pub fn new() -> Self { 
        Self 
    }

    /// Checks if replay protection exists before an invoke_signed call.
    ///
    /// Searches the 20 lines preceding the call for nonce, sequence,
    /// or blockhash-related patterns.
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `invoke_line` - The line number where invoke_signed was found
    ///
    /// # Returns
    ///
    /// `true` if replay protection is present, `false` otherwise.
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

    /// Runs the replay attack detector.
    ///
    /// Scans for `invoke_signed` patterns and verifies that replay
    /// protection mechanisms exist.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

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
    fn default() -> Self { 
        Self::new() 
    }
}
