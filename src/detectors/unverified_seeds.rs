//! # V021 - Unverified Seeds in Derived Accounts Detector
//!
//! Detects PDAs used without full seed re-derivation, enabling collision exploits.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

pub struct UnverifiedSeedsDetector;

impl UnverifiedSeedsDetector {
    pub fn new() -> Self { Self }
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
        "Use Anchor's seeds constraint: #[account(seeds = [b\"seed\", user.key().as_ref()], bump)]"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        // Look for AccountInfo with PDA-like names but no seeds constraint
        let mut in_accounts_struct = false;
        let mut struct_name = String::new();

        for (line_num, line) in source.lines().enumerate() {
            // Track when we're inside a #[derive(Accounts)] struct
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

                // PDA-like names: vault, pda, state, config, pool, etc.
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

                // Exit struct on closing brace
                if line.trim() == "}" {
                    in_accounts_struct = false;
                }
            }
        }
        findings
    }
}

impl Default for UnverifiedSeedsDetector {
    fn default() -> Self { Self::new() }
}
