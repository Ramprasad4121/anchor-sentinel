//! # V007: Token-2022 Security Detector
//!
//! @title V007 - Token-2022 Security
//! @author Anchor-Sentinel
//!
//! Detects security risks specific to the SPL Token-2022 standard, including
//! reentrancy in transfer hooks and dangerous extension usage.
//!
//! ## Vulnerability Description
//!
//! Token-2022 introduces extensions that add power but also risk:
//! - **Transfer Hooks**: Can call back into the program, enabling reentrancy attacks.
//! - **Permanent Delegate**: Gives an authority absolute control over token accounts.
//! - **Confidential Transfers**: Can obscure amounts, complicating accounting.
//!
//! ## Detection Strategy
//!
//! 1. Detect `transfer_hook` attribute or interface implementation.
//! 2. Check for missing `#[reentrancy_guard]` or unchecked external calls in hooks.
//! 3. Detect initialization of `PermanentDelegate` extension.
//!
//! ## CWE Reference
//!
//! - CWE-841: Improper Enforcement of Behavioral Workflow
//! - CWE-284: Improper Access Control

use super::{create_finding, VulnerabilityDetector};
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

pub struct Token2022Detector;

impl VulnerabilityDetector for Token2022Detector {
    fn id(&self) -> &'static str {
        "V007"
    }

    fn name(&self) -> &'static str {
        "Token-2022 Security Risk"
    }

    fn description(&self) -> &'static str {
        "Detects potentially unsafe usage of Token-2022 extensions like \
         Transfer Hooks (reentrancy risk) and Permanent Delegate."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-841")
    }

    fn remediation(&self) -> &'static str {
        "For Transfer Hooks: Ensure proper reentrancy guards are used.\n\
         For Permanent Delegate: Verify this powerful authority is strictly controlled."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for Transfer Hook without reentrancy protection (heuristic)
        // Look for the transfer_hook attribute or interface
        // This is a simplified check - in a real AST traversal we'd check the method body
        let hook_pattern = regex::Regex::new(r"#\[interface\(spl_transfer_hook_interface::\w+\)\]").unwrap();
        
        for (line_num, line) in context.source_code.lines().enumerate() {
            let line_num = line_num + 1;
            
            // 1. Permanent Delegate Detection
            if line.contains("ExtensionType::PermanentDelegate") || line.contains("spl_token_2022::extension::permanent_delegate") {
                 let finding = create_finding(
                    self,
                    context,
                    "Token-2022 Permanent Delegate Usage".to_string(),
                    "The Permanent Delegate extension allows an authority to transfer or burn tokens \
                     from any account without the owner's signature. This is a high-privilege role \
                     that essentially creates a 'god mode' for the token. Ensure this is intentional \
                     and the authority is properly secured (e.g., multisig or DAO).".to_string(),
                    format!("Line {}", line_num),
                    line_num,
                    Some(line.trim().to_string()),
                );
                findings.push(finding);
            }

            // 2. Transfer Hook Detection (Basic Heuristic)
            // If we see transfer hook interface implementation but no reentrancy guard nearby
            if (line.contains("transfer_hook") || hook_pattern.is_match(line)) 
                && !context.source_code.contains("#[reentrancy_guard]") { // Check globally for now, ideally per function
                
                 // Only flag if we are fairly sure it's defining a hook
                 if line.contains("fn transfer_hook") || line.contains("execute") {
                     let finding = create_finding(
                        self,
                        context,
                        "Token-2022 Transfer Hook Reentrancy Risk".to_string(),
                        "Transfer hooks are invoked during token transfers and can call back into \
                         your program. If your program implements a transfer hook, it MUST be \
                         protected against reentrancy attacks. Consider using a `reentrancy_guard`.".to_string(),
                        format!("Line {}", line_num),
                        line_num,
                        Some(line.trim().to_string()),
                    );
                    findings.push(finding);
                 }
            }
        }

        findings
    }
}
