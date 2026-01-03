//! # V004: PDA Seed Collision Detector
//!
//! @title V004 - PDA Seed Collision
//! @author Ramprasad
//!
//! Detects Program Derived Addresses (PDAs) with weak or potentially
//! colliding seeds.
//!
//! ## Vulnerability Description
//!
//! PDAs derive their address from a set of seeds. If seeds are too generic
//! or lack user-specific data, different logical entities may resolve to
//! the same address, causing account confusion attacks.
//!
//! ## Detection Strategy
//!
//! 1. Extract seeds from `#[account(seeds = [...])]` constraints
//! 2. Check for dynamic data (user keys, IDs) vs. static strings only
//! 3. Compare seeds across PDAs for potential collisions
//! 4. Verify bump constraint presence
//!
//! ## CWE Reference
//!
//! - CWE-330: Use of Insufficiently Random Values

use super::{create_finding, VulnerabilityDetector};
use crate::parser::{AccountField, AccountStruct, AnalysisContext, ConstraintType};
use crate::report::{Finding, Severity};

/// Detector for PDA seed collision vulnerabilities.
pub struct PdaCollisionDetector;

impl VulnerabilityDetector for PdaCollisionDetector {
    fn id(&self) -> &'static str {
        "V004"
    }

    fn name(&self) -> &'static str {
        "PDA Seed Collision/Weakness"
    }

    fn description(&self) -> &'static str {
        "Detects PDAs with insufficient or predictable seeds that could lead \
         to seed collision attacks. Weak seeds can allow attackers to derive \
         the same PDA for different logical entities."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-330")
    }

    fn remediation(&self) -> &'static str {
        "Ensure PDA seeds are unique and specific:\n\
         - Include user-specific data (e.g., user public key)\n\
         - Add program-specific discriminators\n\
         - Use unique identifiers for different account types\n\
         - Avoid using only static strings as seeds"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Track PDAs with their init status: (struct_name, field_name, seeds, is_init)
        let mut all_pdas: Vec<(String, String, Vec<String>, bool, usize)> = Vec::new();

        for account_struct in &context.accounts {
            for field in &account_struct.fields {
                if let Some(seeds) = self.extract_seeds(field) {
                    // Check for weak seeds (static-only, missing bump, etc.)
                    if let Some(finding) =
                        self.check_weak_seeds(context, account_struct, field, &seeds)
                    {
                        findings.push(finding);
                    }

                    // Track this PDA with its init status
                    all_pdas.push((
                        account_struct.name.clone(),
                        field.name.clone(),
                        seeds,
                        field.is_init,  // Is this PDA being initialized?
                        field.line,
                    ));
                }
            }
        }

        // Only check for TRUE collisions (multiple init on same seeds)
        findings.extend(self.check_init_collisions(context, &all_pdas));

        findings
    }
}

impl PdaCollisionDetector {
    /// Extracts seeds from account field constraints.
    ///
    /// # Arguments
    ///
    /// * `field` - The account field to analyze
    ///
    /// # Returns
    ///
    /// Seeds vector if present, `None` otherwise.
    fn extract_seeds(&self, field: &AccountField) -> Option<Vec<String>> {
        for constraint in &field.constraints {
            if let ConstraintType::Seeds(seeds) = &constraint.constraint_type {
                return Some(seeds.clone());
            }
        }
        None
    }

    /// Checks if seeds are weak or insufficiently specific.
    ///
    /// # Arguments
    ///
    /// * `context` - Analysis context
    /// * `account_struct` - The account struct containing the field
    /// * `field` - The PDA field
    /// * `seeds` - The seed expressions
    ///
    /// # Returns
    ///
    /// A finding if seeds are weak, `None` otherwise.
    fn check_weak_seeds(
        &self,
        context: &AnalysisContext,
        account_struct: &AccountStruct,
        field: &AccountField,
        seeds: &[String],
    ) -> Option<Finding> {
        let mut issues = Vec::new();

        // Check for dynamic data
        let has_dynamic = seeds.iter().any(|s| {
            s.contains(".key()")
                || s.contains(".as_ref()")
                || s.contains("to_le_bytes")
                || s.contains("&")
                || s.contains("ctx.")
        });

        if !has_dynamic {
            issues.push("Only static seeds - no user/transaction-specific data");
        }

        if seeds.len() == 1 {
            issues.push("Single seed - consider adding more specificity");
        }

        let has_bump = field
            .constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Bump));

        if !has_bump {
            issues.push("Missing bump constraint - should verify canonical bump");
        }

        // Check for generic seed patterns
        for seed in seeds {
            let lower = seed.to_lowercase();
            if lower.contains("\"admin\"")
                || lower.contains("\"config\"")
                || lower.contains("\"state\"")
            {
                if seeds.len() == 1 || !has_dynamic {
                    issues.push("Generic seed without unique identifier");
                    break;
                }
            }
        }

        if !issues.is_empty() {
            Some(create_finding(
                self,
                context,
                format!(
                    "Weak PDA seeds for `{}` in `{}`",
                    field.name, account_struct.name
                ),
                format!(
                    "The PDA `{}` has potentially weak seeds: [{}]. Issues found:\n{}",
                    field.name,
                    seeds.join(", "),
                    issues
                        .iter()
                        .map(|i| format!("- {}", i))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
                format!("{}::{}", account_struct.name, field.name),
                field.line,
                Some(format!(
                    "#[account(\n    seeds = [{}],\n    bump\n)]",
                    seeds.join(", ")
                )),
            ))
        } else {
            None
        }
    }

    /// Checks for TRUE PDA collisions (multiple contexts trying to INIT same seeds).
    ///
    /// This is the correct detection logic. We only flag when:
    /// 1. Two different contexts have PDAs with identical seeds
    /// 2. BOTH contexts are trying to INITIALIZE the PDA (have init constraint)
    ///
    /// Cross-context references to the same PDA are NORMAL in Anchor programs
    /// and should NOT be flagged.
    ///
    /// # Arguments
    ///
    /// * `context` - Analysis context
    /// * `all_pdas` - Collection of (struct, field, seeds, is_init, line) tuples
    ///
    /// # Returns
    ///
    /// Findings for any detected TRUE collisions.
    fn check_init_collisions(
        &self,
        context: &AnalysisContext,
        all_pdas: &[(String, String, Vec<String>, bool, usize)],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Group PDAs by their normalized seed pattern
        let mut pda_registry: std::collections::HashMap<String, Vec<&(String, String, Vec<String>, bool, usize)>> = 
            std::collections::HashMap::new();

        for pda in all_pdas {
            let seed_key = self.normalize_seed_pattern(&pda.2);
            pda_registry.entry(seed_key).or_default().push(pda);
        }

        // Check each seed pattern for multiple INIT contexts
        for (seed_key, pdas) in &pda_registry {
            // Count how many contexts are trying to INIT this PDA
            let init_contexts: Vec<_> = pdas.iter().filter(|p| p.3).collect();
            
            if init_contexts.len() > 1 {
                // TRUE COLLISION: Multiple contexts trying to init same PDA!
                let locations: Vec<String> = init_contexts
                    .iter()
                    .map(|p| format!("{}::{}", p.0, p.1))
                    .collect();

                let finding = create_finding(
                    self,
                    context,
                    format!(
                        "Multiple contexts initialize PDA with identical seeds"
                    ),
                    format!(
                        "The following contexts all try to INITIALIZE a PDA with seeds [{}]:\n{}\n\n\
                         This is a real collision vulnerability. Only ONE context should \
                         initialize this PDA; others should reference it without init.",
                        seed_key,
                        locations.iter().map(|l| format!("- {}", l)).collect::<Vec<_>>().join("\n")
                    ),
                    locations.join(" & "),
                    init_contexts.first().map(|p| p.4).unwrap_or(0),
                    Some(format!(
                        "// Only ONE context should init this PDA:\n\
                         #[account(init, seeds = [{}], bump, payer = user, space = SIZE)]\n\n\
                         // Other contexts should reference without init:\n\
                         #[account(seeds = [{}], bump)]",
                        seed_key, seed_key
                    )),
                );
                findings.push(finding);
            }
            // If only 0 or 1 contexts have init, it's NORMAL - don't report
        }

        findings
    }

    /// Normalizes seed pattern to a string key for comparison.
    fn normalize_seed_pattern(&self, seeds: &[String]) -> String {
        seeds
            .iter()
            .map(|s| {
                s.trim()
                    .trim_matches('"')
                    .replace("b\"", "")
                    .replace("\"", "")
                    .to_lowercase()
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Compares two seed sets for potential collision.
    fn seeds_match(&self, seeds1: &[String], seeds2: &[String]) -> bool {
        if seeds1.len() != seeds2.len() {
            return false;
        }

        let normalize = |s: &str| -> String {
            s.trim()
                .trim_matches('"')
                .replace("b\"", "")
                .replace("\"", "")
                .to_lowercase()
        };

        seeds1
            .iter()
            .zip(seeds2.iter())
            .all(|(s1, s2)| normalize(s1) == normalize(s2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_code(source: &str) -> Vec<Finding> {
        let context = AnalysisContext::from_source("test.rs", source.to_string()).unwrap();
        let detector = PdaCollisionDetector;
        detector.detect(&context)
    }

    #[test]
    fn test_detect_weak_seeds() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Initialize<'info> {
                #[account(
                    init,
                    seeds = [b"config"],
                    payer = user,
                    space = 100
                )]
                pub config: Account<'info, Config>,
            }
        "#;

        let findings = analyze_code(source);
        assert!(!findings.is_empty(), "Should detect weak single static seed");
    }
}
