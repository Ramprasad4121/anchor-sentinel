//! # V016 - Token Mint/Burn Without Supply Check Detector
//!
//! @title Token Supply Overflow Detector
//! @author Ramprasad
//!
//! Detects `mint_to` and `burn` operations without checked arithmetic,
//! which can lead to supply inflation or underflow vulnerabilities.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: Unchecked arithmetic on supply
//! token::mint_to(ctx, amount)?;
//! state.total_supply += amount;  // Could overflow!
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Using checked arithmetic
//! token::mint_to(ctx, amount)?;
//! state.total_supply = state.total_supply
//!     .checked_add(amount)
//!     .ok_or(ErrorCode::Overflow)?;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-190: Integer Overflow or Wraparound

use crate::detectors::VulnerabilityDetector;
use crate::detectors::utils::should_skip_line;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for token supply modification without overflow protection.
///
/// Identifies `mint_to` and `burn` operations that lack checked arithmetic,
/// which could allow supply manipulation attacks.
pub struct MintBurnDetector;

impl MintBurnDetector {
    /// Creates a new mint/burn detector instance.
    pub fn new() -> Self { 
        Self 
    }

    /// Checks if checked arithmetic is used near a mint/burn operation.
    ///
    /// Searches within ±5 lines of the operation for evidence of
    /// `checked_add`, `checked_sub`, `saturating_*`, or overflow handling.
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `line_num` - The line number where mint/burn was found
    ///
    /// # Returns
    ///
    /// `true` if checked arithmetic is present, `false` otherwise.
    fn has_checked_math(&self, source: &str, line_num: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = line_num.saturating_sub(5);
        let end = (line_num + 5).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                if line.contains("checked_add")
                    || line.contains("checked_sub")
                    || line.contains("saturating_")
                    || line.contains("overflow")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for MintBurnDetector {
    fn id(&self) -> &'static str { "V016" }
    
    fn name(&self) -> &'static str { "Token Mint/Burn Without Supply Check" }
    
    fn description(&self) -> &'static str {
        "Detects mint_to/burn without checked arithmetic, risking supply inflation/underflow."
    }
    
    fn severity(&self) -> Severity { Severity::High }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-190") }
    
    fn remediation(&self) -> &'static str {
        "Use checked arithmetic for supply modifications:\n\
         total_supply = total_supply.checked_add(amount).ok_or(ErrorCode::Overflow)?;\n\
         total_supply = total_supply.checked_sub(amount).ok_or(ErrorCode::Underflow)?;"
    }

    /// Runs the mint/burn supply check detector.
    ///
    /// Scans for `mint_to` and `burn` patterns and verifies that checked
    /// arithmetic is used for supply calculations.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each mint/burn without supply validation.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"mint_to\s*\(").unwrap(),
            Regex::new(r"burn\s*\(").unwrap(),
            Regex::new(r"token::mint_to").unwrap(),
            Regex::new(r"token::burn").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            // Skip non-code contexts (comments, imports, struct fields)
            if should_skip_line(line) {
                continue;
            }
            
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_checked_math(source, line_num) {
                    findings.push(Finding {
                        id: format!("V016-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "Mint/burn without supply validation".to_string(),
                        description: "Token supply modification without overflow/underflow check.".to_string(),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.80,
                    });
                }
            }
        }
        findings
    }
}

impl Default for MintBurnDetector {
    fn default() -> Self { 
        Self::new() 
    }
}
