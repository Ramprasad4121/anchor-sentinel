//! # V009 - Reentrancy via CPI Detector
//!
//! @title Cross-Program Invocation Reentrancy Detector
//! @author Ramprasad
//!
//! Detects potential reentrancy vulnerabilities through CPI chains without
//! proper state guards, which can enable recursive drain attacks.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: No reentrancy guard
//! pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//!     // External CPI call without state lock
//!     token::transfer(ctx.accounts.transfer_ctx(), amount)?;
//!     // State updated AFTER external call - classic reentrancy!
//!     ctx.accounts.vault.balance -= amount;
//!     Ok(())
//! }
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: State locked before CPI
//! pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//!     require!(!ctx.accounts.state.is_processing, ErrorCode::ReentrancyGuard);
//!     ctx.accounts.state.is_processing = true;
//!     
//!     // Update state BEFORE external call (Checks-Effects-Interactions)
//!     ctx.accounts.vault.balance -= amount;
//!     
//!     token::transfer(ctx.accounts.transfer_ctx(), amount)?;
//!     
//!     ctx.accounts.state.is_processing = false;
//!     Ok(())
//! }
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-841: Improper Enforcement of Behavioral Workflow

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for CPI reentrancy vulnerabilities.
///
/// Identifies cross-program invocations (`invoke`, `invoke_signed`, `CpiContext`)
/// that lack reentrancy protection, which could enable recursive exploit patterns.
pub struct CpiReentrancyDetector;

impl CpiReentrancyDetector {
    /// Creates a new CPI reentrancy detector instance.
    pub fn new() -> Self { 
        Self 
    }

    /// Checks if reentrancy protection exists before a CPI call.
    ///
    /// Searches the 15 lines preceding the CPI for evidence of reentrancy
    /// guards such as locks, processing flags, or mutex patterns.
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `cpi_line` - The line number where CPI was found
    ///
    /// # Returns
    ///
    /// `true` if reentrancy protection is present, `false` otherwise.
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
         1. Check lock: require!(!state.is_processing)\n\
         2. Set lock: state.is_processing = true\n\
         3. Update state BEFORE CPI (Checks-Effects-Interactions)\n\
         4. Make CPI call\n\
         5. Release lock: state.is_processing = false"
    }

    /// Runs the CPI reentrancy detector.
    ///
    /// Scans for `invoke`, `invoke_signed`, and `CpiContext` patterns and
    /// verifies that reentrancy guards are present before the call.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each CPI without reentrancy protection.
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
    fn default() -> Self { 
        Self::new() 
    }
}
