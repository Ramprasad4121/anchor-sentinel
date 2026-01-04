//! # V012 - Rent Exemption Bypass Detector
//!
//! @title Account Rent Calculation Detector
//! @author Ramprasad
//!
//! Detects account creation without proper rent exemption calculation,
//! which can cause accounts to be garbage collected or DoS via underfunding.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: Hardcoded lamports
//! invoke(
//!     &system_instruction::create_account(payer, account, 1000000, space, program_id),
//!     &[payer, account],
//! )?;
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Dynamic rent calculation
//! let rent = Rent::get()?;
//! let lamports = rent.minimum_balance(space as usize);
//! invoke(
//!     &system_instruction::create_account(payer, account, lamports, space, program_id),
//!     &[payer, account],
//! )?;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-400: Uncontrolled Resource Consumption

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for rent exemption bypass vulnerabilities.
///
/// Identifies account creation that lacks proper rent calculation,
/// which could cause accounts to be garbage collected.
pub struct RentBypassDetector;

impl RentBypassDetector {
    /// Creates a new rent bypass detector instance.
    pub fn new() -> Self { 
        Self 
    }

    /// Checks if rent calculation exists near an account creation.
    fn has_rent_check(&self, source: &str, create_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = create_line.saturating_sub(10);
        let end = (create_line + 5).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                if line.contains("minimum_balance")
                    || line.contains("rent")
                    || line.contains("LAMPORTS_PER_SOL")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl VulnerabilityDetector for RentBypassDetector {
    fn id(&self) -> &'static str { "V012" }
    fn name(&self) -> &'static str { "Rent Exemption Bypass" }
    fn description(&self) -> &'static str {
        "Detects account creation without rent exemption calculation, causing DoS via underfunding."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-400") }
    fn remediation(&self) -> &'static str {
        "Calculate rent dynamically: Rent::get()?.minimum_balance(space)"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        let pattern = Regex::new(r"create_account\s*\(").unwrap();

        for (line_num, line) in source.lines().enumerate() {
            if pattern.is_match(line) && !self.has_rent_check(source, line_num) {
                findings.push(Finding {
                    id: format!("V012-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "Account creation without rent calculation".to_string(),
                    description: "create_account without rent exemption check.".to_string(),
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
        findings
    }
}

impl Default for RentBypassDetector {
    fn default() -> Self { Self::new() }
}
