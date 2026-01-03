//! # V002: Missing Owner Check Detector
//!
//! @title V002 - Missing Owner Check
//! @author Ramprasad
//!
//! Detects accounts that are missing owner validation, which can allow
//! attackers to pass in accounts owned by malicious programs.
//!
//! ## Vulnerability Description
//!
//! When using raw `AccountInfo` or `UncheckedAccount` types, the Anchor
//! framework does not automatically verify the account's owner. An attacker
//! can create a fake account with crafted data and pass it to the program.
//!
//! ## Detection Strategy
//!
//! 1. Identify `AccountInfo` and `UncheckedAccount` fields
//! 2. Check for explicit `owner` constraint
//! 3. Check for `address` constraint (implies ownership)
//! 4. Exclude known system accounts
//!
//! ## CWE Reference
//!
//! - CWE-284: Improper Access Control

use super::{create_finding, VulnerabilityDetector};
use crate::parser::{AccountField, AccountType, AnalysisContext, ConstraintType};
use crate::report::{Finding, Severity};

/// Detector for missing owner check vulnerabilities.
pub struct MissingOwnerDetector;

impl VulnerabilityDetector for MissingOwnerDetector {
    fn id(&self) -> &'static str {
        "V002"
    }

    fn name(&self) -> &'static str {
        "Missing Owner Check"
    }

    fn description(&self) -> &'static str {
        "Detects accounts that lack owner validation. Without owner checks, \
         attackers can substitute accounts owned by different programs, \
         potentially leading to type confusion or unauthorized access."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-284")
    }

    fn remediation(&self) -> &'static str {
        "Ensure account ownership is validated:\n\
         - Use `Account<'info, T>` instead of `AccountInfo<'info>` when possible\n\
         - Add `#[account(owner = program_id)]` constraint\n\
         - Use `UncheckedAccount` only when necessary and manually verify owner"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account_struct in &context.accounts {
            for field in &account_struct.fields {
                if self.needs_owner_check(field) && !self.has_owner_check(field) {
                    let finding = create_finding(
                        self,
                        context,
                        format!(
                            "Account `{}` in `{}` lacks owner validation",
                            field.name, account_struct.name
                        ),
                        format!(
                            "The account `{}` uses `{}` which does not automatically \
                             verify the account owner. An attacker could pass an account \
                             owned by a malicious program, leading to type confusion or \
                             unauthorized data access.",
                            field.name,
                            self.type_name(&field.ty)
                        ),
                        format!("{}::{}", account_struct.name, field.name),
                        field.line,
                        Some(self.generate_code_context(field)),
                    );
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

impl MissingOwnerDetector {
    /// Determines if this account type requires an explicit owner check.
    ///
    /// # Arguments
    ///
    /// * `field` - The account field to analyze
    ///
    /// # Returns
    ///
    /// `true` if the type does not auto-verify owner.
    fn needs_owner_check(&self, field: &AccountField) -> bool {
        match &field.ty {
            AccountType::AccountInfo => true,
            AccountType::UncheckedAccount => true,
            AccountType::Account(_) => false,
            AccountType::Signer => false,
            AccountType::Program(_) => false,
            AccountType::SystemProgram => false,
            AccountType::SystemAccount => false,
            _ => false,
        }
    }

    /// Checks if the field has an owner validation constraint.
    ///
    /// # Arguments
    ///
    /// * `field` - The account field to check
    ///
    /// # Returns
    ///
    /// `true` if owner validation is present.
    fn has_owner_check(&self, field: &AccountField) -> bool {
        for constraint in &field.constraints {
            match &constraint.constraint_type {
                ConstraintType::Owner(_) => return true,
                ConstraintType::Constraint(expr) => {
                    if expr.contains("owner") || expr.contains("program_id") {
                        return true;
                    }
                }
                ConstraintType::Address(_) => {
                    return true;
                }
                _ => {}
            }
        }

        // Check if this is a known system account
        let name = field.name.to_lowercase();
        if name.contains("system_program")
            || name.contains("rent")
            || name.contains("clock")
            || name.contains("token_program")
        {
            return true;
        }

        false
    }

    /// Returns the display name for an account type.
    fn type_name(&self, ty: &AccountType) -> &'static str {
        match ty {
            AccountType::AccountInfo => "AccountInfo",
            AccountType::UncheckedAccount => "UncheckedAccount",
            _ => "Unknown",
        }
    }

    /// Generates a code snippet showing the vulnerable pattern.
    fn generate_code_context(&self, field: &AccountField) -> String {
        format!(
            "/// CHECK: Missing owner validation\npub {}: AccountInfo<'info>,",
            field.name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_code(source: &str) -> Vec<Finding> {
        let context = AnalysisContext::from_source("test.rs", source.to_string()).unwrap();
        let detector = MissingOwnerDetector;
        detector.detect(&context)
    }

    #[test]
    fn test_detect_missing_owner() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Process<'info> {
                /// CHECK: No owner check
                pub data_account: AccountInfo<'info>,
            }
        "#;

        let findings = analyze_code(source);
        assert!(!findings.is_empty(), "Should detect missing owner check");
    }

    #[test]
    fn test_no_false_positive_with_typed_account() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Process<'info> {
                pub data_account: Account<'info, MyData>,
            }
        "#;

        let findings = analyze_code(source);
        assert!(findings.is_empty(), "Account<T> auto-verifies owner");
    }
}
