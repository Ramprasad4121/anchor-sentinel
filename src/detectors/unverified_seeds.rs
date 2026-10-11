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
use crate::parser::{AccountType, AnalysisContext, ConstraintType};
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
        let pda_names = ["pda", "vault", "state", "config", "pool", "escrow", "authority"];

        // Use the parsed account structs so multi-line #[account(...)]
        // attributes (seeds on their own line) are understood.
        for account_struct in &context.accounts {
            for field in &account_struct.fields {
                let is_raw_or_typed = matches!(
                    field.ty,
                    AccountType::AccountInfo | AccountType::Account(_)
                );
                if !is_raw_or_typed {
                    continue;
                }
                let has_seeds_or_address = field.constraints.iter().any(|c| {
                    matches!(
                        c.constraint_type,
                        ConstraintType::Seeds(_)
                            | ConstraintType::Address(_)
                            | ConstraintType::Constraint(_)
                    )
                });
                if has_seeds_or_address {
                    continue;
                }
                let lower = field.name.to_lowercase();
                let Some(pda_name) = pda_names.iter().find(|n| lower.contains(*n)) else {
                    continue;
                };
                let line = field.line;
                let snippet = context
                    .source_code
                    .lines()
                    .nth(line.saturating_sub(1))
                    .map(|l| l.trim().to_string());

                findings.push(Finding {
                    id: format!("V021-{}", line),
                    detector_id: self.id().to_string(),
                    title: format!("PDA '{}' without seeds verification", pda_name),
                    description: "Account appears to be a PDA but lacks #[account(seeds=...)] constraint. \
                         Attackers could pass arbitrary accounts."
                        .to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line,
                    location: format!("{}::{}:{}", account_struct.name, field.name, line),
                    code_snippet: snippet,
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.65,
                });
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
