//! # Arbitrary CPI Detector
//!
//! @title V025 - Arbitrary Cross-Program Invocation
//! @author Ramprasad
//!
//! Detects CPI calls where the `program_id` comes from an untrusted account
//! instead of a hardcoded known ID like TOKEN_PROGRAM_ID.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: Program ID from account, not verified
//! let program = ctx.accounts.some_program.to_account_info();
//! invoke(&ix, &[...], program.key)?; // Attacker controls program!
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Hardcoded known program ID
//! invoke(&ix, &[...], &spl_token::ID)?;
//! // OR verified against constant
//! require!(ctx.accounts.program.key() == known_program_id);
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-284: Improper Access Control

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for arbitrary CPI vulnerabilities.
pub struct ArbitraryCpiDetector;

impl ArbitraryCpiDetector {
    /// Creates a new arbitrary CPI detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Known safe program IDs that are acceptable in CPIs.
    fn is_safe_program_id(&self, id: &str) -> bool {
        let safe_ids = [
            "spl_token::ID",
            "TOKEN_PROGRAM_ID",
            "token_program::ID",
            "system_program::ID",
            "SYSTEM_PROGRAM_ID",
            "associated_token::ID",
            "ASSOCIATED_TOKEN_PROGRAM_ID",
            "anchor_spl::token::ID",
            "anchor_lang::system_program::ID",
            "token_2022::ID",
            "mpl_token_metadata::ID",
        ];
        
        safe_ids.iter().any(|safe| id.contains(safe))
    }

    /// Checks if a program ID variable is validated before use.
    fn is_program_validated(&self, source: &str, program_var: &str, invoke_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = invoke_line.saturating_sub(15);
        
        for i in start..invoke_line {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if (lower.contains("require!") || lower.contains("constraint"))
                    && lower.contains(&program_var.to_lowercase())
                    && (lower.contains("key") || lower.contains("id"))
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for ArbitraryCpiDetector {
    fn id(&self) -> &'static str { "V025" }
    
    fn name(&self) -> &'static str { "Arbitrary CPI Program ID" }
    
    fn description(&self) -> &'static str {
        "Detects CPI calls where program ID comes from untrusted source without validation."
    }
    
    fn severity(&self) -> Severity { Severity::Critical }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-284") }
    
    fn remediation(&self) -> &'static str {
        "Use hardcoded program IDs:\n\
         invoke(&ix, &accounts, &spl_token::ID)?;\n\
         Or validate before use:\n\
         require!(program.key() == EXPECTED_PROGRAM_ID);"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        
        // Pattern: invoke/invoke_signed with program_id from ctx.accounts
        let invoke_pattern = Regex::new(r"invoke(?:_signed)?\s*\([^)]*ctx\.accounts\.(\w+)").unwrap();
        let cpi_context_pattern = Regex::new(r"CpiContext::new\s*\([^,]*ctx\.accounts\.(\w+)\.to_account_info").unwrap();
        
        for (line_num, line) in source.lines().enumerate() {
            // Check invoke patterns
            if let Some(cap) = invoke_pattern.captures(line) {
                if let Some(m) = cap.get(1) {
                    let program_var = m.as_str();
                    
                    // Skip if it's a known safe program
                    if !line.contains("TOKEN_PROGRAM_ID") 
                        && !line.contains("spl_token::ID")
                        && !line.contains("system_program")
                        && !self.is_program_validated(source, program_var, line_num)
                    {
                        findings.push(Finding {
                            id: format!("V025-{}", line_num + 1),
                            detector_id: self.id().to_string(),
                            title: format!("Arbitrary CPI with unverified program '{}'", program_var),
                            description: format!(
                                "CPI invokes program from ctx.accounts.{} without verification. \
                                 Attacker could substitute a malicious program.",
                                program_var
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
            
            // Check CpiContext patterns
            if let Some(cap) = cpi_context_pattern.captures(line) {
                if let Some(m) = cap.get(1) {
                    let program_var = m.as_str();
                    
                    if !self.is_safe_program_id(line) 
                        && !self.is_program_validated(source, program_var, line_num)
                    {
                        findings.push(Finding {
                            id: format!("V025-{}", line_num + 1),
                            detector_id: self.id().to_string(),
                            title: format!("CpiContext with unverified program '{}'", program_var),
                            description: format!(
                                "CpiContext uses program from ctx.accounts.{} without verification.",
                                program_var
                            ),
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
        }
        
        findings
    }
}

impl Default for ArbitraryCpiDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_program_id() {
        let detector = ArbitraryCpiDetector::new();
        
        assert!(detector.is_safe_program_id("spl_token::ID"));
        assert!(detector.is_safe_program_id("TOKEN_PROGRAM_ID"));
        assert!(!detector.is_safe_program_id("ctx.accounts.program"));
    }
}
