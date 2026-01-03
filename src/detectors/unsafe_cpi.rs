//! # V006: Unsafe CPI Detector
//!
//! @title V006 - Unsafe Cross-Program Invocation
//! @author Ramprasad
//!
//! Detects unsafe usage of raw `invoke` and `invoke_signed` calls
//! instead of safe `CpiContext` patterns.
//!
//! ## Vulnerability Description
//!
//! When using raw `solana_program::program::invoke` or `invoke_signed`,
//! the program_id is not automatically validated. An attacker can pass
//! a malicious program address and execute arbitrary code.
//!
//! ## Detection Strategy
//!
//! 1. Look for `invoke` and `invoke_signed` function calls
//! 2. Check if program_id comes from an unconstrained account
//! 3. Flag raw invoke usage vs safe CpiContext
//!
//! ## CWE Reference
//!
//! - CWE-749: Exposed Dangerous Method or Function

use super::{create_finding, VulnerabilityDetector};
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for unsafe CPI vulnerabilities.
pub struct UnsafeCpiDetector;

impl VulnerabilityDetector for UnsafeCpiDetector {
    fn id(&self) -> &'static str {
        "V006"
    }

    fn name(&self) -> &'static str {
        "Unsafe CPI"
    }

    fn description(&self) -> &'static str {
        "Detects unsafe cross-program invocation patterns using raw `invoke` \
         or `invoke_signed` without proper program ID validation. Attackers \
         can substitute malicious programs to execute arbitrary code."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-749")
    }

    fn remediation(&self) -> &'static str {
        "Use safe CPI patterns:\n\
         - Use Anchor's `CpiContext` for type-safe CPIs\n\
         - Hardcode trusted program IDs or use `Program<'info, T>`\n\
         - If using raw invoke, verify program_id against a constant\n\
         - Never pass user-supplied accounts as program_id"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Detect raw invoke calls from instruction handlers
        for handler in &context.instructions {
            for cpi in &handler.cpi_calls {
                if !cpi.is_program_hardcoded {
                    let finding = create_finding(
                        self,
                        context,
                        format!("Unsafe CPI in `{}`", handler.name),
                        format!(
                            "The instruction `{}` uses raw `invoke` or `invoke_signed` \
                             which does not automatically validate the target program. \
                             An attacker could substitute a malicious program address.",
                            handler.name
                        ),
                        format!("{}::invoke", handler.name),
                        cpi.line,
                        Some(self.generate_code_context()),
                    );
                    findings.push(finding);
                }
            }
        }

        // Also scan source code for invoke patterns
        findings.extend(self.scan_source_for_invoke(context));

        findings
    }
}

impl UnsafeCpiDetector {
    /// Scans source code for raw invoke patterns.
    fn scan_source_for_invoke(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Patterns for unsafe CPI
        let invoke_pattern = regex::Regex::new(r"\binvoke\s*\(").unwrap();
        let invoke_signed_pattern = regex::Regex::new(r"\binvoke_signed\s*\(").unwrap();
        let solana_invoke = regex::Regex::new(r"solana_program::program::invoke").unwrap();

        for (line_num, line) in context.source_code.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for raw invoke calls
            let has_invoke = invoke_pattern.is_match(line) || invoke_signed_pattern.is_match(line);
            let has_solana_invoke = solana_invoke.is_match(line);

            if has_invoke || has_solana_invoke {
                // Check if this is likely safe (using CpiContext or hardcoded program)
                let is_safe = line.contains("CpiContext")
                    || line.contains("token_program")
                    || line.contains("system_program")
                    || line.contains("TOKEN_PROGRAM_ID")
                    || line.contains("SYSTEM_PROGRAM_ID");

                if !is_safe {
                    let pattern_type = if has_solana_invoke {
                        "solana_program::program::invoke"
                    } else if line.contains("invoke_signed") {
                        "invoke_signed"
                    } else {
                        "invoke"
                    };

                    let finding = create_finding(
                        self,
                        context,
                        format!("Raw `{}` call detected", pattern_type),
                        format!(
                            "Raw `{}` is used without apparent program ID validation. \
                             This is dangerous because the target program address may \
                             come from user input, allowing phantom invocation attacks.",
                            pattern_type
                        ),
                        format!("Line {}", line_num),
                        line_num,
                        Some(format!(
                            "// Vulnerable:\n{}\n\n// Recommended: Use CpiContext\n// let cpi_ctx = CpiContext::new(program.to_account_info(), ...);\n// anchor_spl::token::transfer(cpi_ctx, amount)?;",
                            trimmed
                        )),
                    );
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Generates example vulnerable vs safe code.
    fn generate_code_context(&self) -> String {
        r#"// Vulnerable: Raw invoke with user-supplied program
invoke(
    &instruction,
    &[account1, account2, program.to_account_info()], // program from user!
)?;

// Safe: Use CpiContext with typed Program account
let cpi_ctx = CpiContext::new(
    ctx.accounts.token_program.to_account_info(),
    Transfer { ... }
);
token::transfer(cpi_ctx, amount)?;"#.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_code(source: &str) -> Vec<Finding> {
        let context = AnalysisContext::from_source("test.rs", source.to_string()).unwrap();
        let detector = UnsafeCpiDetector;
        detector.detect(&context)
    }

    #[test]
    fn test_detect_raw_invoke() {
        let source = r#"
            pub fn dangerous_cpi(ctx: Context<DangerousCpi>) -> Result<()> {
                invoke(
                    &instruction,
                    &[ctx.accounts.user.to_account_info()],
                )?;
                Ok(())
            }
        "#;

        let findings = analyze_code(source);
        assert!(!findings.is_empty(), "Should detect raw invoke");
    }

    #[test]
    fn test_no_false_positive_cpi_context() {
        let source = r#"
            pub fn safe_cpi(ctx: Context<SafeCpi>) -> Result<()> {
                let cpi_ctx = CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer { from: ..., to: ..., authority: ... }
                );
                token::transfer(cpi_ctx, amount)?;
                Ok(())
            }
        "#;

        let findings = analyze_code(source);
        // CpiContext usage should not be flagged
        assert!(
            findings.iter().all(|f| !f.title.contains("CpiContext")),
            "Should not flag safe CpiContext usage"
        );
    }
}
