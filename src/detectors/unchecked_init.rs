//! # V005: Unchecked Account Initialization Detector
//!
//! @title V005 - Unchecked Account Initialization
//! @author Ramprasad
//!
//! Detects accounts that are initialized without proper validation or
//! with reinitialization vulnerabilities.
//!
//! ## Vulnerability Description
//!
//! The `init_if_needed` constraint allows accounts to be initialized on
//! any call, which can lead to reinitialization attacks where an attacker
//! resets account state or changes ownership.
//!
//! ## Detection Strategy
//!
//! 1. Identify `init` and `init_if_needed` constraints
//! 2. Check for missing `space` constraint
//! 3. Verify space includes discriminator (8 bytes)
//! 4. Check for missing `payer` constraint
//!
//! ## CWE Reference
//!
//! - CWE-665: Improper Initialization

use super::{create_finding, VulnerabilityDetector};
use crate::parser::{AccountField, AccountStruct, AnalysisContext, ConstraintType};
use crate::report::{Finding, Severity};

/// Detector for unchecked account initialization vulnerabilities.
pub struct UncheckedInitDetector;

impl VulnerabilityDetector for UncheckedInitDetector {
    fn id(&self) -> &'static str {
        "V005"
    }

    fn name(&self) -> &'static str {
        "Unchecked Account Initialization"
    }

    fn description(&self) -> &'static str {
        "Detects account initialization issues including missing space validation, \
         potential reinitialization attacks, and improper initialization patterns."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-665")
    }

    fn remediation(&self) -> &'static str {
        "Ensure proper account initialization:\n\
         - Always specify `space` with proper calculation\n\
         - Use `init` instead of `init_if_needed` when possible\n\
         - Verify account is not already initialized before init\n\
         - Include discriminator size (8 bytes) in space calculation"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account_struct in &context.accounts {
            for field in &account_struct.fields {
                if field.is_init {
                    findings.extend(self.check_init_issues(context, account_struct, field));
                }
            }
        }

        findings
    }
}

impl UncheckedInitDetector {
    /// Checks for various initialization issues.
    ///
    /// # Arguments
    ///
    /// * `context` - Analysis context
    /// * `account_struct` - The account struct
    /// * `field` - The field being initialized
    ///
    /// # Returns
    ///
    /// Vector of findings for any issues detected.
    fn check_init_issues(
        &self,
        context: &AnalysisContext,
        account_struct: &AccountStruct,
        field: &AccountField,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for init_if_needed
        if self.has_init_if_needed(field) {
            let finding = create_finding(
                self,
                context,
                format!(
                    "Use of `init_if_needed` for `{}` in `{}`",
                    field.name, account_struct.name
                ),
                format!(
                    "The account `{}` uses `init_if_needed` which can lead to \
                     reinitialization vulnerabilities if not carefully handled. \
                     An attacker might be able to reinitialize an account with \
                     malicious data or reset important state.",
                    field.name
                ),
                format!("{}::{}", account_struct.name, field.name),
                field.line,
                Some(self.generate_init_if_needed_example(field)),
            );
            findings.push(finding);
        }

        // Check for missing space constraint
        if !self.has_space_constraint(field) {
            let finding = create_finding(
                self,
                context,
                format!(
                    "Missing `space` constraint for init on `{}`",
                    field.name
                ),
                format!(
                    "The account `{}` is initialized but doesn't have an explicit \
                     `space` constraint. This could lead to undersized accounts \
                     or wasted rent.",
                    field.name
                ),
                format!("{}::{}", account_struct.name, field.name),
                field.line,
                None,
            );
            findings.push(finding);
        }

        // Check for discriminator in space calculation
        if let Some(space_expr) = self.get_space_expression(field) {
            if !space_expr.contains("8") && !space_expr.contains("DISCRIMINATOR") {
                let finding = create_finding(
                    self,
                    context,
                    format!(
                        "Space calculation may miss discriminator for `{}`",
                        field.name
                    ),
                    format!(
                        "The space expression `{}` may not include the 8-byte \
                         Anchor discriminator. This could cause serialization errors \
                         or account corruption.",
                        space_expr
                    ),
                    format!("{}::{}", account_struct.name, field.name),
                    field.line,
                    Some(format!("space = 8 + {}", space_expr)),
                );
                findings.push(finding);
            }
        }

        // Check for missing payer constraint
        if !self.has_payer_constraint(field) {
            let finding = create_finding(
                self,
                context,
                format!(
                    "Missing `payer` constraint for init on `{}`",
                    field.name
                ),
                format!(
                    "The account `{}` is initialized but doesn't specify a payer. \
                     This will cause a compilation error or may use an unintended payer.",
                    field.name
                ),
                format!("{}::{}", account_struct.name, field.name),
                field.line,
                None,
            );
            findings.push(finding);
        }

        findings
    }

    /// Checks if field has `init_if_needed` constraint.
    fn has_init_if_needed(&self, field: &AccountField) -> bool {
        field
            .constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::InitIfNeeded))
    }

    /// Checks if field has `space` constraint.
    fn has_space_constraint(&self, field: &AccountField) -> bool {
        field
            .constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Space(_)))
    }

    /// Checks if field has `payer` constraint.
    fn has_payer_constraint(&self, field: &AccountField) -> bool {
        field
            .constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Payer(_)))
    }

    /// Extracts space expression from constraints.
    fn get_space_expression(&self, field: &AccountField) -> Option<String> {
        for constraint in &field.constraints {
            if let ConstraintType::Space(expr) = &constraint.constraint_type {
                return Some(expr.clone());
            }
        }
        None
    }

    /// Generates example code showing vulnerable vs. safe patterns.
    fn generate_init_if_needed_example(&self, field: &AccountField) -> String {
        format!(
            r#"// Vulnerable pattern:
#[account(init_if_needed, ...)]
pub {}: Account<'info, T>,

// Safer alternative - use separate initialize instruction:
// In initializer:
#[account(init, payer = user, space = 8 + T::INIT_SPACE)]
pub {}: Account<'info, T>,

// In other instructions:
#[account(mut, has_one = authority)]
pub {}: Account<'info, T>,"#,
            field.name, field.name, field.name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_code(source: &str) -> Vec<Finding> {
        let context = AnalysisContext::from_source("test.rs", source.to_string()).unwrap();
        let detector = UncheckedInitDetector;
        detector.detect(&context)
    }

    #[test]
    fn test_detect_init_if_needed() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Process<'info> {
                #[account(init_if_needed, payer = user, space = 100)]
                pub data: Account<'info, Data>,
                #[account(mut)]
                pub user: Signer<'info>,
            }
        "#;

        let findings = analyze_code(source);
        assert!(
            findings.iter().any(|f| f.title.contains("init_if_needed")),
            "Should warn about init_if_needed"
        );
    }
}
