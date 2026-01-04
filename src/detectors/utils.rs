//! # Detector Utilities
//!
//! @title Context-Aware Detection Utilities
//! @author Ramprasad
//!
//! Shared utility functions for reducing false positives by filtering
//! non-code contexts like comments, imports, and struct definitions.

use std::collections::HashSet;
use crate::report::Finding;

/// Returns true if the line should be skipped (not actual vulnerable code).
///
/// Filters out:
/// - Comments (`//`, `/*`, `*`)
/// - Import statements (`use`, `pub use`, `mod`, `pub mod`)
/// - Error code macros (`#[msg(`, `#[error_code`)
/// - Struct field definitions (lines ending with `,` containing `:` but no `=`)
/// - Doc comments (`///`, `//!`)
///
/// # Arguments
///
/// * `line` - The source line to check
///
/// # Returns
///
/// `true` if the line should be skipped, `false` if it should be analyzed.
///
/// # Example
///
/// ```rust,ignore
/// // These return true (skip):
/// should_skip_line("use pyth_sdk::Price;")     // Import
/// should_skip_line("    /// Oracle price data") // Doc comment
/// should_skip_line("    pub oracle: Pubkey,")   // Struct field
///
/// // These return false (analyze):
/// should_skip_line("let price = oracle.get_price()?;")  // Actual code
/// ```
pub fn should_skip_line(line: &str) -> bool {
    let trimmed = line.trim();
    
    // Skip empty lines
    if trimmed.is_empty() {
        return true;
    }
    
    // Skip comments
    if trimmed.starts_with("//") 
        || trimmed.starts_with("/*") 
        || trimmed.starts_with("*")
        || trimmed.starts_with("///")
        || trimmed.starts_with("//!") 
    {
        return true;
    }
    
    // Skip use/mod statements (imports)
    if trimmed.starts_with("use ") 
        || trimmed.starts_with("pub use ") 
        || trimmed.starts_with("mod ") 
        || trimmed.starts_with("pub mod ")
        || trimmed.starts_with("extern crate ")
    {
        return true;
    }
    
    // Skip error_code/msg macros
    if trimmed.contains("#[msg(") 
        || trimmed.contains("#[error_code")
        || trimmed.contains("#[error(")
    {
        return true;
    }
    
    // Skip attribute lines
    if trimmed.starts_with("#[") && !trimmed.contains("account(") {
        return true;
    }
    
    // Skip struct field definitions (not assignments)
    // Pattern: "pub field_name: Type," or "field_name: Type,"
    if trimmed.ends_with(',') 
        && trimmed.contains(':') 
        && !trimmed.contains('=')
        && !trimmed.contains("seeds")
    {
        return true;
    }
    
    // Skip type definitions
    if trimmed.starts_with("pub struct ") 
        || trimmed.starts_with("struct ")
        || trimmed.starts_with("pub enum ")
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("pub type ")
        || trimmed.starts_with("type ")
    {
        return true;
    }
    
    // Skip trait implementations and declarations
    if trimmed.starts_with("impl ") || trimmed.starts_with("pub trait ") {
        return true;
    }
    
    false
}

/// Checks if a line is inside an error enum definition.
///
/// This helps filter out error message definitions that might contain
/// keywords like "oracle", "signer", etc.
pub fn is_error_context(source: &str, line_num: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let start = line_num.saturating_sub(10);
    
    for i in start..line_num {
        if let Some(line) = lines.get(i) {
            if line.contains("#[error_code]") || line.contains("pub enum") && line.contains("Error") {
                return true;
            }
        }
    }
    false
}

/// Deduplicates findings that point to the same location with the same detector.
///
/// Removes duplicate findings based on file_path, line number, and detector_id.
///
/// # Arguments
///
/// * `findings` - Vector of findings to deduplicate
///
/// # Returns
///
/// A new vector with duplicates removed.
pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    findings.into_iter()
        .filter(|f| {
            let key = format!("{}:{}:{}", f.file_path, f.line, f.detector_id);
            seen.insert(key)
        })
        .collect()
}

/// Checks if a line appears to be part of an Anchor account constraint.
///
/// Lines with account constraints like `#[account(seeds = [...])]` should
/// receive special handling in certain detectors.
pub fn has_account_constraint(line: &str) -> bool {
    line.contains("#[account(")
}

/// Checks if an account appears to be a PDA based on surrounding context.
///
/// Returns true if the account has seeds constraint or CHECK comment.
pub fn is_pda_account(source: &str, line_num: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let start = line_num.saturating_sub(5);
    let end = (line_num + 1).min(lines.len());
    
    for i in start..end {
        if let Some(line) = lines.get(i) {
            // Check for seeds constraint
            if line.contains("seeds") && line.contains("[") {
                return true;
            }
            // Check for CHECK comment (intentionally unchecked)
            if line.contains("/// CHECK") || line.contains("// CHECK") {
                return true;
            }
            // Check for bump constraint
            if line.contains("bump") && line.contains("#[account(") {
                return true;
            }
        }
    }
    false
}

/// Checks if an account type is intentionally unchecked.
///
/// Returns true for UncheckedAccount and similar types.
pub fn is_unchecked_account_type(line: &str) -> bool {
    line.contains("UncheckedAccount")
        || line.contains("AccountInfo")
        || line.contains("/// CHECK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_comments() {
        assert!(should_skip_line("// This is a comment"));
        assert!(should_skip_line("/// Doc comment"));
        assert!(should_skip_line("/* Block comment"));
        assert!(should_skip_line("* Continued block"));
    }

    #[test]
    fn test_skip_imports() {
        assert!(should_skip_line("use pyth_sdk::Price;"));
        assert!(should_skip_line("pub use crate::oracle;"));
        assert!(should_skip_line("mod oracle;"));
    }

    #[test]
    fn test_skip_struct_fields() {
        assert!(should_skip_line("    pub oracle: Pubkey,"));
        assert!(should_skip_line("    price_feed: Account<'info, PriceFeed>,"));
    }

    #[test]
    fn test_analyze_actual_code() {
        assert!(!should_skip_line("let price = oracle.get_price()?;"));
        assert!(!should_skip_line("invoke(&ix, accounts)?;"));
        assert!(!should_skip_line("token::transfer(ctx, amount)?;"));
    }

    #[test]
    fn test_is_pda_account() {
        let source = r#"
#[derive(Accounts)]
pub struct MyAccounts<'info> {
    #[account(seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}
"#;
        assert!(is_pda_account(source, 4));
    }
}
