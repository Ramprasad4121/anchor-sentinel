//! # Precision Loss Detector
//!
//! @title V026 - Precision Loss in Division Before Multiplication
//! @author Ramprasad
//!
//! Detects arithmetic patterns like `(a / b) * c` that should be `(a * c) / b`
//! to avoid precision loss from integer division.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: Division before multiplication loses precision
//! let fee = (amount / 10000) * fee_bps; // Loses precision!
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Multiply first, then divide
//! let fee = (amount * fee_bps) / 10000; // Maintains precision
//! // Even better: Use checked math
//! let fee = amount.checked_mul(fee_bps).ok_or(ErrorCode::Overflow)? / 10000;
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-682: Incorrect Calculation

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for precision loss vulnerabilities.
pub struct PrecisionLossDetector;

impl PrecisionLossDetector {
    /// Creates a new precision loss detector instance.
    pub fn new() -> Self {
        Self
    }
}

impl VulnerabilityDetector for PrecisionLossDetector {
    fn id(&self) -> &'static str { "V026" }
    
    fn name(&self) -> &'static str { "Precision Loss" }
    
    fn description(&self) -> &'static str {
        "Detects division before multiplication patterns that cause precision loss."
    }
    
    fn severity(&self) -> Severity { Severity::Medium }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-682") }
    
    fn remediation(&self) -> &'static str {
        "Reorder operations to multiply before dividing:\n\
         BAD:  (a / b) * c\n\
         GOOD: (a * c) / b"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        
        // Pattern: (x / y) * z - division followed by multiplication
        // This pattern catches: var / number * number or (expr / expr) * expr
        let div_mul_pattern = Regex::new(r"\)?\s*/\s*\w+\s*\)\s*\*|\w+\s*/\s*\w+\s*\*").unwrap();
        
        for (line_num, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            
            // Skip comments and imports
            if trimmed.starts_with("//") || trimmed.starts_with("use ") {
                continue;
            }
            
            // Check for division before multiplication pattern
            if div_mul_pattern.is_match(line) {
                // Skip if already using checked_div (likely intentional)
                if line.contains("checked_div") {
                    continue;
                }
                
                findings.push(Finding {
                    id: format!("V026-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "Division before multiplication may cause precision loss".to_string(),
                    description: "Integer division truncates before multiplication, causing precision \
                                  loss. Reorder to multiply first, then divide.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(trimmed.to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.70,
                });
            }
        }
        
        findings
    }
}

impl Default for PrecisionLossDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precision_loss_pattern() {
        let detector = PrecisionLossDetector::new();
        
        // Pattern detection is done via regex in detect()
        // Just verify detector instantiation
        assert_eq!(detector.id(), "V026");
    }
}
