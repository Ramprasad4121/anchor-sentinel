//! # V010 - Unchecked Amount in Transfers Detector
//!
//! @title Transfer Amount Validation Detector
//! @author Ramprasad
//!
//! Detects token transfers without proper amount validation. Transfers without
//! balance checks or minimum amount validation can lead to partial drains,
//! underflows, or unexpected behavior with zero amounts.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: No validation before transfer
//! pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//!     token::transfer(ctx.accounts.transfer_ctx(), amount)?; // amount could be 0 or > balance!
//!     Ok(())
//! }
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Amount validated before transfer
//! pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//!     require!(amount > 0, ErrorCode::InvalidAmount);
//!     require!(amount <= ctx.accounts.vault.balance, ErrorCode::InsufficientBalance);
//!     token::transfer(ctx.accounts.transfer_ctx(), amount)?;
//!     Ok(())
//! }
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-129: Improper Validation of Array Index

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for unchecked transfer amounts.
///
/// Identifies token transfers that lack prior validation of the transfer
/// amount, which could lead to exploits or unexpected behavior.
pub struct UncheckedTransferDetector;

impl UncheckedTransferDetector {
    /// Creates a new unchecked transfer detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Checks if amount validation exists before a transfer.
    ///
    /// Searches the 10 lines preceding the transfer for validation patterns
    /// such as `require!(amount`, balance comparisons, or checked math.
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `transfer_line` - The line number where transfer was found
    ///
    /// # Returns
    ///
    /// `true` if amount validation is present, `false` otherwise.
    fn has_amount_validation(&self, source: &str, transfer_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = transfer_line.saturating_sub(10);
        let end = transfer_line;

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("require!(amount")
                    || lower.contains("require_gte!")
                    || lower.contains("require_gt!")
                    || lower.contains("amount >=")
                    || lower.contains("amount <=")
                    || lower.contains("amount >")
                    || lower.contains("amount <")
                    || lower.contains("balance >=")
                    || lower.contains("balance >")
                    || lower.contains(".checked_")
                    || lower.contains("min(amount")
                    || lower.contains("amount.min(")
                {
                    return true;
                }
            }
        }
        false
    }

    /// Extracts the transfer amount expression from the line.
    ///
    /// # Arguments
    ///
    /// * `line` - The source line containing the transfer
    ///
    /// # Returns
    ///
    /// The extracted amount variable name or "amount" if not found.
    fn extract_amount(&self, line: &str) -> String {
        let patterns = [
            Regex::new(r"amount:\s*(\w+)").unwrap(),
            Regex::new(r",\s*(\w+)\s*\)").unwrap(),
        ];
        
        for pattern in &patterns {
            if let Some(caps) = pattern.captures(line) {
                if let Some(m) = caps.get(1) {
                    return m.as_str().to_string();
                }
            }
        }
        "amount".to_string()
    }
}

impl VulnerabilityDetector for UncheckedTransferDetector {
    fn id(&self) -> &'static str { "V010" }
    
    fn name(&self) -> &'static str { "Unchecked Amount in Transfers" }
    
    fn description(&self) -> &'static str {
        "Detects token transfers without prior amount validation. Missing checks can enable \
         partial drains, underflows, or unexpected behavior with zero amounts."
    }
    
    fn severity(&self) -> Severity { Severity::High }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-129") }
    
    fn remediation(&self) -> &'static str {
        "Validate transfer amounts before execution:\n\
         require!(amount > 0, \"Amount must be positive\");\n\
         require!(amount <= balance, \"Insufficient balance\");\n\
         Use checked arithmetic for calculations."
    }

    /// Runs the unchecked transfer detector.
    ///
    /// Scans for `transfer`, `transfer_checked`, and related patterns and
    /// verifies that amount validation exists before each transfer.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each transfer without amount validation.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"transfer\s*\(").unwrap(),
            Regex::new(r"transfer_checked\s*\(").unwrap(),
            Regex::new(r"anchor_spl::token::transfer").unwrap(),
            Regex::new(r"token::transfer").unwrap(),
            Regex::new(r"transfer_lamports").unwrap(),
            Regex::new(r"\.transfer\(").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_amount_validation(source, line_num) {
                    let amount = self.extract_amount(line);
                    
                    findings.push(Finding {
                        id: format!("V010-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: format!("Transfer without amount validation: {}", amount),
                        description: format!(
                            "Transfer operation using '{}' without prior validation. \
                             Attackers may exploit missing bounds checks to drain funds \
                             or cause unexpected behavior.", amount
                        ),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.75,
                    });
                }
            }
        }
        findings
    }
}

impl Default for UncheckedTransferDetector {
    fn default() -> Self { 
        Self::new() 
    }
}
