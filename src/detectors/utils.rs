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

/// Removes all whitespace and line comments so manual checks can be matched
/// regardless of formatting.
fn normalize_code(source: &str) -> String {
    source
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Returns true if handler code checks `is_signer` on the named account,
/// e.g. `if !ctx.accounts.authority.is_signer { return Err(..) }`.
pub fn has_manual_signer_check(source: &str, field_name: &str) -> bool {
    let code = normalize_code(source);
    code.contains(&format!("accounts.{}.is_signer", field_name))
        || code.contains(&format!("!{}.is_signer", field_name))
}

/// Returns true if handler code compares the owner of the named account,
/// e.g. `if ctx.accounts.token.owner != &spl_token::ID { .. }`.
/// Only `ctx.accounts.<name>.owner` (the AccountInfo owner) counts, not a
/// deserialized struct field that happens to be called `owner`.
pub fn has_manual_owner_check(source: &str, field_name: &str) -> bool {
    let code = normalize_code(source);
    let needle = format!("accounts.{}.owner", field_name);
    let mut rest = code.as_str();
    while let Some(i) = rest.find(&needle) {
        let after = &rest[i + needle.len()..];
        let before = &rest[..i];
        if after.starts_with("!=")
            || after.starts_with("==")
            || before.ends_with("!=ctx.")
            || before.ends_with("==ctx.")
            || before.ends_with("!=&ctx.")
            || before.ends_with("==&ctx.")
        {
            return true;
        }
        rest = after;
    }
    code.contains(&format!("require_keys_eq!(*ctx.accounts.{}.owner", field_name))
        || code.contains(&format!("require_keys_eq!(ctx.accounts.{}.owner", field_name))
}

/// Returns true if the code compares a `ctx.accounts.<x>.key` against a
/// hardcoded program ID (`spl_token::ID`, `system_program::ID`, `id()`),
/// which is the manual fix for arbitrary CPI.
pub fn has_program_id_check(source: &str) -> bool {
    let code = normalize_code(source);
    let id_then_key = regex::Regex::new(
        r"(::ID|::id\(\))(!=|==)\*?&?ctx\.accounts\.\w+\.key",
    )
    .unwrap();
    let key_then_id = regex::Regex::new(
        r"ctx\.accounts\.\w+\.key(\(\))?(!=|==)\*?&?[\w:]*(::ID|::id\(\))",
    )
    .unwrap();
    id_then_key.is_match(&code)
        || key_then_id.is_match(&code)
        || code.contains("require_keys_eq!(ctx.accounts.")
        || code.contains("require_keys_eq!(*ctx.accounts.")
}

/// Returns the source text between two 1-indexed lines (inclusive).
pub fn source_range(source: &str, start: usize, end: usize) -> String {
    if start == 0 || end < start {
        return source.to_string();
    }
    source
        .lines()
        .skip(start - 1)
        .take(end - start + 1)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod manual_check_tests {
    use super::*;

    #[test]
    fn signer_check_detected() {
        let src = "if !ctx.accounts.authority.is_signer {\n return Err(e); }";
        assert!(has_manual_signer_check(src, "authority"));
        assert!(!has_manual_signer_check(src, "admin"));
    }

    #[test]
    fn owner_check_ignores_unpacked_struct_field() {
        // `token.owner` here is the SPL token owner field, not AccountInfo owner.
        let insecure = "if ctx.accounts.authority.key != &token.owner { return Err(e); }";
        assert!(!has_manual_owner_check(insecure, "token"));
        let secure = "if ctx.accounts.token.owner != &spl_token::ID { return Err(e); }";
        assert!(has_manual_owner_check(secure, "token"));
    }

    #[test]
    fn program_id_check_detected() {
        assert!(has_program_id_check(
            "if &spl_token::ID != ctx.accounts.token_program.key { return Err(e); }"
        ));
        assert!(!has_program_id_check("invoke(&ix, &accounts)?;"));
    }
}
