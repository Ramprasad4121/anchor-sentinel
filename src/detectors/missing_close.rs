//! # V013 - Missing Close Account Detector
//!
//! @title Account Lifecycle Completion Detector
//! @author Ramprasad
//!
//! Detects account initialization without paired close instruction,
//! which can lead to rent theft or stuck lamports.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: Init without close
//! #[derive(Accounts)]
//! pub struct Initialize<'info> {
//!     #[account(init, payer = user, space = 8 + 32)]
//!     pub state: Account<'info, State>,
//! }
//! // No close instruction exists in the program!
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Has close instruction
//! #[derive(Accounts)]
//! pub struct CloseState<'info> {
//!     #[account(mut, close = destination)]
//!     pub state: Account<'info, State>,
//!     /// CHECK: Destination for rent
//!     #[account(mut)]
//!     pub destination: AccountInfo<'info>,
//! }
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-404: Improper Resource Shutdown or Release

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for missing close account instructions.
pub struct MissingCloseDetector;

impl MissingCloseDetector {
    pub fn new() -> Self { Self }
}

impl VulnerabilityDetector for MissingCloseDetector {
    fn id(&self) -> &'static str { "V013" }
    fn name(&self) -> &'static str { "Missing Close Account" }
    fn description(&self) -> &'static str {
        "Detects account initialization without close instruction, risking rent theft."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-404") }
    fn remediation(&self) -> &'static str {
        "Add close instruction: #[account(close = destination)]"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        let lower = source.to_lowercase();

        let has_init = lower.contains("#[account(init") || lower.contains("init_if_needed");
        let has_close = lower.contains("close =") || lower.contains("close_account");

        if has_init && !has_close {
            for (line_num, line) in source.lines().enumerate() {
                if line.to_lowercase().contains("#[account(init") {
                    findings.push(Finding {
                        id: format!("V013-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "Init without close instruction".to_string(),
                        description: "Account initialized but no close instruction found.".to_string(),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.60,
                    });
                    break;
                }
            }
        }
        findings
    }
}

impl Default for MissingCloseDetector {
    fn default() -> Self { Self::new() }
}
