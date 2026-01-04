//! # V021 - Unverified Seeds in Derived Accounts Detector
//!
//! @title PDA Seeds Verification Detector
//! @author Ramprasad
//!
//! Detects PDA accounts used without proper `#[account(seeds=...)]` constraint
//! verification, which can allow attackers to pass arbitrary accounts.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: PDA without seeds constraint
//! #[derive(Accounts)]
//! pub struct WithdrawAccounts<'info> {
//!     #[account(mut)]
//!     pub vault: Account<'info, Vault>,  // No seeds verification!
//! }
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: PDA with seeds constraint
//! #[derive(Accounts)]
//! pub struct WithdrawAccounts<'info> {
//!     #[account(
//!         mut,
//!         seeds = [b"vault", user.key().as_ref()],
//!         bump = vault.bump
//!     )]
//!     pub vault: Account<'info, Vault>,
//! }
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-345: Insufficient Verification of Data Authenticity

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for unverified PDA seeds.
///
/// Identifies PDA-like account fields that lack proper `seeds` constraint
/// verification in Anchor account structs.
pub struct UnverifiedSeedsDetector;

impl UnverifiedSeedsDetector {
    /// Creates a new unverified seeds detector instance.
    pub fn new() -> Self { 
        Self 
    }
}

impl VulnerabilityDetector for UnverifiedSeedsDetector {
    fn id(&self) -> &'static str { "V021" }
    
    fn name(&self) -> &'static str { "Unverified Seeds in Derived Accounts" }
    
    fn description(&self) -> &'static str {
        "Detects PDA accounts used without #[account(seeds=...)] constraint, risking collisions."
    }
    
    fn severity(&self) -> Severity { Severity::Critical }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-345") }
    
    fn remediation(&self) -> &'static str {
        "Use Anchor's seeds constraint:\n\
         #[account(seeds = [b\"prefix\", user.key().as_ref()], bump)]"
    }

    /// Runs the unverified seeds detector.
    ///
    /// Scans for PDA-like account names (vault, pda, state, config, etc.)
    /// in Anchor account structs that lack seeds constraints.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each PDA without seeds verification.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let mut in_accounts_struct = false;
        let mut struct_name = String::new();

        for (line_num, line) in source.lines().enumerate() {
            if line.contains("#[derive(Accounts)]") {
                in_accounts_struct = true;
                continue;
            }

            if in_accounts_struct {
                if line.contains("pub struct") {
                    if let Some(name) = line.split_whitespace().nth(2) {
                        struct_name = name.trim_end_matches('<').to_string();
                    }
                }

                let pda_names = ["pda", "vault", "state", "config", "pool", "escrow", "authority"];
                
                for pda_name in &pda_names {
                    if line.to_lowercase().contains(pda_name) 
                        && !line.contains("seeds")
                        && !line.contains("constraint")
                        && (line.contains("AccountInfo") || line.contains("Account<"))
                    {
                        findings.push(Finding {
                            id: format!("V021-{}", line_num + 1),
                            detector_id: self.id().to_string(),
                            title: format!("PDA '{}' without seeds verification", pda_name),
                            description: format!(
                                "Account appears to be a PDA but lacks #[account(seeds=...)] constraint. \
                                 Attackers could pass arbitrary accounts."
                            ),
                            severity: self.severity(),
                            file_path: context.file_path.clone(),
                            line: line_num + 1,
                            location: format!("{}::{}:{}", struct_name, pda_name, line_num + 1),
                            code_snippet: Some(line.trim().to_string()),
                            remediation: self.remediation().to_string(),
                            cwe: self.cwe().map(|s| s.to_string()),
                            confidence: 0.65,
                        });
                    }
                }

                if line.trim() == "}" {
                    in_accounts_struct = false;
                }
            }
        }
        findings
    }
}

impl Default for UnverifiedSeedsDetector {
    fn default() -> Self { 
        Self::new() 
    }
}
