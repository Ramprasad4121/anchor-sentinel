//! # Scope Validation Validator
//!
//! @title V027 - Scope-Limited Validation
//! @author Ramprasad
//!
//! Uses CFG/Scope analysis to detect when variables are validated inside a narrow
//! scope (like an `if` block) but used in a broader scope or different branch.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! if some_condition {
//!     // Validation only protecting this block
//!     require!(amount <= max_limit);
//! }
//!
//! // Usage outside the protected block
//! // 'amount' is treated as safe, but logic might skip the check!
//! token::transfer(ctx, amount)?; 
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-670: Always-Incorrect Control Flow Implementation

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use crate::analysis::cfg::ScopeTracker;

/// Detector for scope validation violations.
pub struct ScopeValidationDetector;

impl ScopeValidationDetector {
    /// Creates a new scope validation detector instance.
    pub fn new() -> Self {
        Self
    }
}

impl VulnerabilityDetector for ScopeValidationDetector {
    fn id(&self) -> &'static str { "V027" }
    
    fn name(&self) -> &'static str { "Scope-Limited Validation" }
    
    fn description(&self) -> &'static str {
        "Detects validations that define safety constraints inside a block but are relied upon outside that block."
    }
    
    fn severity(&self) -> Severity { Severity::High }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-670") }
    
    fn remediation(&self) -> &'static str {
        "Move the validation to the outer scope to ensure it always executes, \
         or handle the else case securely."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        
        // Use pre-parsed AST from context
        let mut tracker = ScopeTracker::new();
        tracker.analyze(&context.ast);
        
        let violations = tracker.find_scope_violations();
        
        for (var, _line_placeholder, msg) in violations {
            // Determine line number from string search (approximation since AST stripped span)
            // In a deeper integration we would keep spans, but here we scan for usage
            // We'll approximate by finding the variable usage that looks suspicious
            
            // For report loop
            let mut line_num = 0;
            for (i, line) in source.lines().enumerate() {
                // Primitive matching to find safe usages
                if line.contains(&var) && (line.contains("transfer") || line.contains("invoke")) {
                    line_num = i + 1;
                    break;
                }
            }
            
            if line_num == 0 { line_num = 1; } // Fallback

            findings.push(Finding {
                id: format!("V027-{}", line_num),
                detector_id: self.id().to_string(),
                title: format!("Validation scope leak for '{}'", var),
                description: msg,
                severity: self.severity(),
                file_path: context.file_path.clone(),
                line: line_num,
                location: format!("{}:{}", context.file_path, line_num),
                code_snippet: source.lines().nth(line_num.saturating_sub(1))
                    .map(|s| s.trim().to_string()),
                remediation: self.remediation().to_string(),
                cwe: self.cwe().map(|s| s.to_string()),
                confidence: 0.80,
            });
        }
        
        findings
    }
}

impl Default for ScopeValidationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_leak_detection() {
        let detector = ScopeValidationDetector::new();
        let source = r#"
            pub fn dangerous(ctx: Context<Ctx>, amount: u64) -> Result<()> {
                if amount > 100 {
                    require!(amount < 1000); 
                }
                // Bug: amount could be 50 vs 5000 (if >100 skipped)
                // actually wait, the logic is:
                // if cond { check(var) } use(var)
                // if cond is false, check skipped, var used unsafe.
                token::transfer(ctx.accounts.to, amount)?;
                Ok(())
            }
        "#;
        
        let ast = syn::parse_str(source).unwrap();
        
        let context = AnalysisContext {
            file_path: "test.rs".to_string(),
            source_code: source.to_string(),
            ast,
            accounts: Vec::new(),
            instructions: Vec::new(),
            state_accounts: Vec::new(),
            error_codes: Vec::new(),
            program_name: None,
            program_id: None,
            program_context: None,
        };
        
        let findings = detector.detect(&context);
        assert!(!findings.is_empty());
        assert!(findings[0].description.contains("amount"));
    }
}
