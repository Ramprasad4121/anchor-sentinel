//! # V001: Missing Signer Check Detector
//!
//! @title V001 - Missing Signer Check
//! @author Ramprasad
//!
//! Detects accounts that should require signer authorization but lack
//! the proper constraint or type.
//!
//! ## Vulnerability Description
//!
//! When an account is intended to authorize an action (e.g., an authority
//! or owner account), it must be verified as a transaction signer. Without
//! this check, an attacker can pass any public key as the authority and
//! perform unauthorized actions.
//!
//! ## Detection Strategy
//!
//! 1. Identify accounts with authority-related names
//! 2. Check if they use `Signer<'info>` type or have `#[account(signer)]`
//! 3. Verify there's no external `has_one` constraint enforcing signature
//!
//! ## CWE Reference
//!
//! - CWE-862: Missing Authorization

use super::{create_finding, VulnerabilityDetector};
use crate::parser::{AccountField, AccountType, AnalysisContext, ConstraintType};
use crate::report::{Finding, Severity};

/// Detector for missing signer check vulnerabilities.
pub struct MissingSignerDetector;

impl VulnerabilityDetector for MissingSignerDetector {
    fn id(&self) -> &'static str {
        "V001"
    }

    fn name(&self) -> &'static str {
        "Missing Signer Check"
    }

    fn description(&self) -> &'static str {
        "Detects accounts that perform privileged operations without requiring \
         a signer constraint. This can allow unauthorized users to execute \
         sensitive actions."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-862")
    }

    fn remediation(&self) -> &'static str {
        "Add a signer constraint to the account:\n\
         - Use `Signer<'info>` type for explicit signers\n\
         - Add `#[account(signer)]` constraint\n\
         - For authority accounts, use `has_one = authority` with a signer"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account_struct in &context.accounts {
            for field in &account_struct.fields {
                if self.is_potential_authority(field) && !field.is_signer {
                    if !self.has_external_signer_check(context, &field.name) {
                        let finding = create_finding(
                            self,
                            context,
                            format!(
                                "Account `{}` in `{}` may require signer authorization",
                                field.name, account_struct.name
                            ),
                            format!(
                                "The account `{}` appears to be an authority or privileged account \
                                 (based on naming: '{}') but does not have a signer constraint. \
                                 This could allow unauthorized users to perform privileged operations.",
                                field.name, field.name
                            ),
                            format!("{}::{}", account_struct.name, field.name),
                            field.line,
                            Some(self.generate_code_context(field)),
                        );
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }
}

impl MissingSignerDetector {
    /// Determines if an account name suggests it should be a signer.
    ///
    /// Checks for common authority-related naming patterns and considers
    /// whether the account is mutable or uses AccountInfo type.
    ///
    /// # Arguments
    ///
    /// * `field` - The account field to analyze
    ///
    /// # Returns
    ///
    /// `true` if the account appears to be an authority that should sign.
    fn is_potential_authority(&self, field: &AccountField) -> bool {
        let name = field.name.to_lowercase();

        let authority_patterns = [
            "authority",
            "owner",
            "admin",
            "manager",
            "operator",
            "signer",
            "payer",
            "creator",
            "initializer",
            "controller",
            "governor",
        ];

        let has_authority_name = authority_patterns
            .iter()
            .any(|pattern| name.contains(pattern));

        let is_mutable = field.is_mutable;
        let is_account_info = matches!(field.ty, AccountType::AccountInfo);

        has_authority_name || (is_mutable && is_account_info)
    }

    /// Checks if there's an external signer verification for this field.
    ///
    /// Looks for `has_one` constraints or custom constraint expressions
    /// that reference this field's key.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context
    /// * `field_name` - Name of the field to check
    ///
    /// # Returns
    ///
    /// `true` if external verification exists.
    fn has_external_signer_check(&self, context: &AnalysisContext, field_name: &str) -> bool {
        for account_struct in &context.accounts {
            for other_field in &account_struct.fields {
                for constraint in &other_field.constraints {
                    if let ConstraintType::HasOne(ref target) = constraint.constraint_type {
                        if target == field_name {
                            return true;
                        }
                    }
                    if let ConstraintType::Constraint(ref expr) = constraint.constraint_type {
                        if expr.contains(field_name) && expr.contains("key") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Generates a code snippet showing the vulnerable code pattern.
    ///
    /// # Arguments
    ///
    /// * `field` - The account field
    ///
    /// # Returns
    ///
    /// A formatted code snippet string.
    fn generate_code_context(&self, field: &AccountField) -> String {
        let ty_str = match &field.ty {
            AccountType::Account(inner) => format!("Account<'info, {}>", inner),
            AccountType::AccountInfo => "AccountInfo<'info>".to_string(),
            AccountType::Signer => "Signer<'info>".to_string(),
            AccountType::UncheckedAccount => "UncheckedAccount<'info>".to_string(),
            _ => "Unknown".to_string(),
        };

        let constraints: Vec<_> = field.constraints.iter().map(|c| c.raw.clone()).collect();
        let constraint_str = if constraints.is_empty() {
            "// No constraints".to_string()
        } else {
            format!("#[account({})]", constraints.join(", "))
        };

        format!("{}\npub {}: {},", constraint_str.trim(), field.name, ty_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_code(source: &str) -> Vec<Finding> {
        let context =
            AnalysisContext::from_source("test.rs", source.to_string()).unwrap();
        let detector = MissingSignerDetector;
        detector.detect(&context)
    }

    #[test]
    fn test_detect_missing_signer() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                /// CHECK: This should be a signer
                pub authority: AccountInfo<'info>,
            }
        "#;

        let findings = analyze_code(source);
        assert!(!findings.is_empty(), "Should detect missing signer");
        assert!(findings[0].title.contains("authority"));
    }

    #[test]
    fn test_no_false_positive_with_signer() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }
        "#;

        let findings = analyze_code(source);
        assert!(
            findings.iter().all(|f| !f.title.contains("authority")),
            "Should not flag Signer types"
        );
    }
}
