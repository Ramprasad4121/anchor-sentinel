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
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for oracle dependency risks.
///
/// Identifies oracle price feed usage without staleness or validity checks,
/// which could enable price manipulation attacks.
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
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `oracle_line` - The line number where oracle usage was found
    ///
    /// # Returns
    ///
    /// `true` if validation is present, `false` otherwise.
    fn has_staleness_check(&self, source: &str, oracle_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = oracle_line;
        let end = (oracle_line + 15).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("timestamp")
                    || lower.contains("staleness")
                    || lower.contains("price > 0")
                    || lower.contains("price != 0")
                    || lower.contains("updated_at")
                    || lower.contains("clock")
                    || lower.contains("slot")
                {
                    return true;
                }
            }
        }
        false
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

    /// Runs the oracle risks detector.
    ///
    /// Scans for oracle-related patterns (Pyth, Switchboard, Chainlink, etc.)
    /// and verifies that staleness/validity checks exist.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each oracle usage without validation.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"pyth").unwrap(),
            Regex::new(r"switchboard").unwrap(),
            Regex::new(r"chainlink").unwrap(),
            Regex::new(r"oracle").unwrap(),
            Regex::new(r"price_feed").unwrap(),
            Regex::new(r"get_price").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            let lower = line.to_lowercase();
            for pattern in &patterns {
                if pattern.is_match(&lower) && !self.has_staleness_check(source, line_num) {
                    findings.push(Finding {
                        id: format!("V014-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "Oracle usage without staleness check".to_string(),
                        description: "Price feed used without validating freshness or value.".to_string(),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.65,
                    });
                    break;
                }
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
