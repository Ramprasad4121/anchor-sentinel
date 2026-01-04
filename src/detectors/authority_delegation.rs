//! # V011 - Weak Authority Delegation Detector
//!
//! @title Authority Delegation Vulnerability Detector
//! @author Ramprasad
//!
//! Detects `set_authority`, `delegate`, or `approve` calls without corresponding
//! revocation mechanisms, which can lead to permanently stuck funds.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: No revocation path
//! token::approve(ctx, amount)?;  // Delegate approved but never revoked
//! token::set_authority(ctx, AuthorityType::MintTokens, new_authority)?;
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Has revocation mechanism
//! token::approve(ctx, amount)?;
//! // ... later in close instruction ...
//! token::revoke(ctx)?;
//! // OR
//! token::set_authority(ctx, AuthorityType::AccountOwner, original_owner)?;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-269: Improper Privilege Management

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for weak authority delegation patterns.
///
/// Identifies `set_authority`, `delegate`, and `approve` calls that lack
/// corresponding revocation mechanisms, which could permanently lock funds.
pub struct AuthorityDelegationDetector;

impl AuthorityDelegationDetector {
    /// Creates a new authority delegation detector instance.
    pub fn new() -> Self { 
        Self 
    }

    /// Checks if the source contains a revocation path for delegated authority.
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `line_num` - The line number where delegation was found (unused but kept for API consistency)
    ///
    /// # Returns
    ///
    /// `true` if a revocation mechanism exists, `false` otherwise.
    fn has_revocation_path(&self, source: &str, _line_num: usize) -> bool {
        let lower = source.to_lowercase();
        // Check if there's a corresponding revocation or owner reset
        (lower.contains("set_authority") && lower.contains("authoritytype::accountowner"))
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
        "Ensure all authority delegations have corresponding revocation instructions:\n\
         - Add token::revoke() in close or cleanup instructions\n\
         - Use set_authority to restore original owner when done"
    }

    /// Runs the weak authority delegation detector.
    ///
    /// Scans for `set_authority`, `delegate`, and `approve` patterns and
    /// checks if corresponding revocation mechanisms exist in the codebase.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each delegation without revocation.
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
    fn default() -> Self { 
        Self::new() 
    }
}
