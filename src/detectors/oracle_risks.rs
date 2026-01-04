//! # V014 - Oracle Dependency Risks Detector
//!
//! @title Oracle Price Feed Validation Detector
//! @author Ramprasad
//!
//! Detects oracle price feed usage without proper staleness or validity checks.
//! Using stale or invalid oracle data can lead to price manipulation exploits.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: No validation of oracle data
//! let price = oracle.get_price()?;
//! let value = amount * price;  // Could be stale or zero!
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Oracle data validated
//! let price_data = oracle.get_price_no_older_than(clock.slot, MAX_STALENESS)?;
//! require!(price_data.price > 0, ErrorCode::InvalidPrice);
//! require!(clock.slot - price_data.publish_slot < MAX_AGE, ErrorCode::StalePrice);
//! let value = amount.checked_mul(price_data.price).ok_or(ErrorCode::Overflow)?;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-829: Inclusion of Functionality from Untrusted Control Sphere

use crate::detectors::VulnerabilityDetector;
use crate::detectors::utils::{should_skip_line, is_error_context};
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for oracle dependency risks.
///
/// Identifies oracle price feed usage without staleness or validity checks,
/// which could enable price manipulation attacks.
///
/// This detector uses context-aware filtering to reduce false positives:
/// - Skips imports, comments, struct definitions
/// - Only flags actual function calls, not keyword mentions
/// - Avoids flagging error message definitions
pub struct OracleRisksDetector;

impl OracleRisksDetector {
    /// Creates a new oracle risks detector instance.
    pub fn new() -> Self { 
        Self 
    }

    /// Checks if staleness/validity checks exist after oracle usage.
    ///
    /// Searches within +15 lines of the oracle call for validation patterns
    /// such as timestamp checks, price > 0, or staleness assertions.
    fn has_staleness_check(&self, source: &str, oracle_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = oracle_line;
        let end = (oracle_line + 15).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("timestamp")
                    || lower.contains("staleness")
                    || lower.contains("stale")
                    || lower.contains("price > 0")
                    || lower.contains("price != 0")
                    || lower.contains("price.is_positive")
                    || lower.contains("updated_at")
                    || lower.contains("publish_time")
                    || lower.contains("publish_slot")
                    || lower.contains("clock.slot")
                    || lower.contains("clock.unix_timestamp")
                    || lower.contains("no_older_than")
                    || lower.contains("max_age")
                    || lower.contains("require!(") && (lower.contains("price") || lower.contains("slot"))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if this is an actual oracle method call, not just a keyword mention.
    ///
    /// Returns true only for patterns like:
    /// - `get_price(`
    /// - `get_current_price(`
    /// - `.price(`
    /// - `oracle.load(`
    fn is_actual_oracle_call(&self, line: &str) -> bool {
        let lower = line.to_lowercase();
        
        // These are actual oracle consumption patterns
        lower.contains("get_price(")
            || lower.contains("get_current_price(")
            || lower.contains("get_asset_price(")
            || lower.contains(".price(")
            || lower.contains("oracle.load(")
            || lower.contains("price_feed.load(")
            || lower.contains("get_price_no_older_than(")
            || lower.contains("get_ema_price(")
            // Pyth-specific
            || lower.contains("price_account.get_price_unchecked(")
            || lower.contains("price_update.get_price_")
            // Switchboard-specific  
            || lower.contains("aggregator.get_result(")
            || lower.contains("feed.get_result(")
    }
}

impl VulnerabilityDetector for OracleRisksDetector {
    fn id(&self) -> &'static str { "V014" }
    
    fn name(&self) -> &'static str { "Oracle Dependency Risks" }
    
    fn description(&self) -> &'static str {
        "Detects oracle price feeds without staleness or validity checks."
    }
    
    fn severity(&self) -> Severity { Severity::High }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-829") }
    
    fn remediation(&self) -> &'static str {
        "Validate oracle data before use:\n\
         1. require!(price > 0, \"Invalid price\");\n\
         2. require!(clock.slot - last_update < MAX_STALENESS, \"Stale price\");\n\
         3. Use oracle's built-in staleness checks if available"
    }

    /// Runs the oracle risks detector with context-aware filtering.
    ///
    /// Key improvements to reduce false positives:
    /// - Skips comments, imports, struct definitions
    /// - Only flags actual oracle method calls, not keyword mentions
    /// - Skips error message definitions
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        for (line_num, line) in source.lines().enumerate() {
            // Skip non-code contexts (comments, imports, struct fields)
            if should_skip_line(line) {
                continue;
            }
            
            // Skip error enum definitions
            if is_error_context(source, line_num) {
                continue;
            }

            // Only flag actual oracle method calls
            if self.is_actual_oracle_call(line) && !self.has_staleness_check(source, line_num) {
                findings.push(Finding {
                    id: format!("V014-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "Oracle price consumed without validation".to_string(),
                    description: "Oracle price is read without checking staleness or validity.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(line.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.80, // Higher confidence now
                });
            }
        }
        findings
    }
}

impl Default for OracleRisksDetector {
    fn default() -> Self { 
        Self::new() 
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_actual_oracle_call() {
        let detector = OracleRisksDetector::new();
        
        // Should match actual oracle calls
        assert!(detector.is_actual_oracle_call("let price = oracle.get_price()?;"));
        assert!(detector.is_actual_oracle_call("let p = price_feed.get_current_price()?;"));
        assert!(detector.is_actual_oracle_call("aggregator.get_result()?"));
        
        // Should NOT match imports or struct fields
        assert!(!detector.is_actual_oracle_call("use pyth_sdk::Price;"));
        assert!(!detector.is_actual_oracle_call("pub oracle: Pubkey,"));
    }

    #[test]
    fn test_has_staleness_check() {
        let detector = OracleRisksDetector::new();
        
        // Source with validation
        let validated = r#"
let price = oracle.get_price()?;
require!(price > 0, ErrorCode::InvalidPrice);
"#;
        assert!(detector.has_staleness_check(validated, 0));
        
        // Source without validation
        let unvalidated = "let price = oracle.get_price()?;";
        assert!(!detector.has_staleness_check(unvalidated, 0));
    }
}
