//! # V003: Integer Overflow/Underflow Detector
//!
//! @title V003 - Integer Overflow/Underflow
//! @author Ramprasad
//!
//! Detects arithmetic operations that could overflow or underflow without
//! proper checked or saturating math.
//!
//! ## Vulnerability Description
//!
//! Rust's default arithmetic operators (`+`, `-`, `*`, `/`) can overflow
//! in release builds, wrapping around silently. In financial calculations,
//! this can lead to incorrect balances, stolen funds, or broken invariants.
//!
//! ## Detection Strategy
//!
//! 1. Parse instruction handler bodies for binary arithmetic expressions
//! 2. Identify unchecked operators vs. checked methods
//! 3. Flag operations in financial contexts (balance, amount, etc.)
//!
//! ## CWE Reference
//!
//! - CWE-190: Integer Overflow or Wraparound

use super::{create_finding, VulnerabilityDetector};
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for integer overflow/underflow vulnerabilities.
pub struct IntegerOverflowDetector;

impl VulnerabilityDetector for IntegerOverflowDetector {
    fn id(&self) -> &'static str {
        "V003"
    }

    fn name(&self) -> &'static str {
        "Integer Overflow/Underflow"
    }

    fn description(&self) -> &'static str {
        "Detects arithmetic operations that may overflow or underflow. \
         Unchecked arithmetic in financial calculations can lead to \
         loss of funds or incorrect state."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-190")
    }

    fn remediation(&self) -> &'static str {
        "Use checked or saturating arithmetic:\n\
         - Replace `a + b` with `a.checked_add(b).ok_or(ErrorCode::Overflow)?`\n\
         - Use `saturating_add`, `saturating_sub` for clamped values\n\
         - Consider using `u128` for intermediate calculations\n\
         - Use the `checked_math` macro if available"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for handler in &context.instructions {
            let unchecked_ops: Vec<_> = handler
                .arithmetic_ops
                .iter()
                .filter(|op| !op.is_checked)
                .collect();

            for op in unchecked_ops {
                let finding = create_finding(
                    self,
                    context,
                    format!(
                        "Unchecked `{}` operation in `{}`",
                        op.operation, handler.name
                    ),
                    format!(
                        "The instruction `{}` contains an unchecked `{}` operation: `{}`. \
                         This could overflow/underflow with malicious inputs, potentially \
                         leading to incorrect calculations or exploitable behavior.",
                        handler.name, op.operation, op.expression
                    ),
                    format!("{}::{}", handler.name, op.operation),
                    op.line,
                    Some(format!(
                        "// Vulnerable:\n{}\n\n// Recommended:\nvalue.checked_{}(...).ok_or(ErrorCode::MathError)?",
                        op.expression, op.operation
                    )),
                );
                findings.push(finding);
            }
        }

        // Add precision loss detection
        findings.extend(self.detect_precision_loss(context));
        
        findings.extend(self.scan_source_patterns(context));

        findings
    }
}

impl IntegerOverflowDetector {
    /// Checks if a line uses safe arithmetic operations.
    ///
    /// Safe patterns include:
    /// - checked_add, checked_sub, checked_mul, checked_div
    /// - saturating_add, saturating_sub, saturating_mul
    /// - overflowing_add, overflowing_sub, overflowing_mul
    /// - wrapping_add, wrapping_sub (intentional wrapping)
    fn is_safe_operation(&self, line: &str) -> bool {
        let safe_patterns = [
            "checked_",       // checked_add, checked_sub, etc.
            "saturating_",    // saturating_add, saturating_mul, etc.
            "overflowing_",   // overflowing_add - returns (result, bool)
            "wrapping_",      // wrapping_add - intentional wrapping
            ".ok_or(",        // Pattern: x.checked_add(y).ok_or(Error)?
            "try_from",       // Safe conversion
        ];
        
        safe_patterns.iter().any(|p| line.contains(p))
    }

    /// Scans source code directly for arithmetic patterns.
    ///
    /// Supplements AST-based detection by looking for compound assignment
    /// operators in financial contexts.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context
    ///
    /// # Returns
    ///
    /// Additional findings from source pattern matching.
    fn scan_source_patterns(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let dangerous_patterns = [
            (r"\+\s*=", "addition assignment (+=)"),
            (r"-\s*=", "subtraction assignment (-=)"),
            (r"\*\s*=", "multiplication assignment (*=)"),
            (r"/\s*=", "division assignment (/=)"),
        ];

        for (line_num, line) in context.source_code.lines().enumerate() {
            let line_num = line_num + 1;

            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Skip lines using safe arithmetic operations
            if self.is_safe_operation(line) {
                continue;
            }

            let is_financial_context = line.to_lowercase().contains("amount")
                || line.to_lowercase().contains("balance")
                || line.to_lowercase().contains("token")
                || line.to_lowercase().contains("lamport")
                || line.to_lowercase().contains("supply")
                || line.to_lowercase().contains("price");

            if is_financial_context {
                for (pattern, name) in &dangerous_patterns {
                    let re = regex::Regex::new(pattern).unwrap();
                    if re.is_match(line) {
                        let finding = create_finding(
                            self,
                            context,
                            format!("Unchecked {} in financial calculation", name),
                            format!(
                                "Line contains unchecked {} which could overflow in a \
                                 financial context. This is especially dangerous when \
                                 dealing with token amounts or balances.",
                                name
                            ),
                            format!("Line {}", line_num),
                            line_num,
                            Some(line.trim().to_string()),
                        );
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    /// Detects precision loss patterns (division before multiplication).
    ///
    /// Pattern: `a / b * c` causes integer truncation before multiplication,
    /// leading to precision loss and potential funds loss.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context
    ///
    /// # Returns
    ///
    /// Findings for any detected precision loss patterns.
    fn detect_precision_loss(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Regex to detect division followed by multiplication: a / b * c
        let div_mul_pattern = regex::Regex::new(r"\w+\s*/\s*\w+\s*\*\s*\w+").unwrap();
        
        // Also check for patterns like (a / b) * c
        let paren_pattern = regex::Regex::new(r"\([^)]*\s*/\s*[^)]*\)\s*\*").unwrap();

        for (line_num, line) in context.source_code.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for division before multiplication
            if div_mul_pattern.is_match(line) || paren_pattern.is_match(line) {
                let finding = create_finding(
                    self,
                    context,
                    "Precision loss: division before multiplication".to_string(),
                    "The expression performs division before multiplication, which causes \
                     integer truncation and precision loss. For example, `a / b * c` should \
                     be rewritten as `a * c / b` to preserve precision.".to_string(),
                    format!("Line {}", line_num),
                    line_num,
                    Some(format!(
                        "// Vulnerable:\n{}\n\n// Recommended:\n// Reorder: (a * c) / b",
                        trimmed
                    )),
                );
                findings.push(finding);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_code(source: &str) -> Vec<Finding> {
        let context = AnalysisContext::from_source("test.rs", source.to_string()).unwrap();
        let detector = IntegerOverflowDetector;
        detector.detect(&context)
    }

    #[test]
    fn test_detect_unchecked_addition() {
        let source = r#"
            pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
                let total = ctx.accounts.from.balance + amount;
                ctx.accounts.to.balance = total;
                Ok(())
            }
        "#;

        let findings = analyze_code(source);
        assert!(!findings.is_empty(), "Should detect unchecked addition");
    }
}
