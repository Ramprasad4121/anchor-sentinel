//! # Used-But-Not-Checked Account Detector
//!
//! @title V024 - Account Usage Without Validation
//! @author Ramprasad
//!
//! Detects accounts that are used in sensitive operations (CPIs, transfers)
//! but never validated with require! or if conditions.
//!
//! ## Logic Bug Pattern
//!
//! The most common logic bug in Solana isn't "Missing Signer" - it's checking
//! the wrong account. This detector identifies:
//!
//! 1. Track `CheckedAccounts` - accounts in require!/if conditions
//! 2. Track `UsedAccounts` - accounts passed to CPIs or modified
//! 3. Vulnerability: `UsedAccounts - CheckedAccounts != 0`
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // Developer creates accounts a and b
//! // Developer checks if a.key() == owner
//! // Developer uses b in sensitive operation (WRONG!)
//! if ctx.accounts.account_a.key() == owner {
//!     token::transfer(ctx.accounts.account_b, amount)?; // BUG!
//! }
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-284: Improper Access Control

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use std::collections::HashSet;
use regex::Regex;

/// Detector for accounts used without being checked.
pub struct AccountUsageDetector;

impl AccountUsageDetector {
    /// Creates a new account usage detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Extracts accounts mentioned in require!/if conditions.
    ///
    /// These are considered "checked" accounts.
    fn extract_checked_accounts(&self, context: &AnalysisContext) -> HashSet<String> {
        let source = &context.source_code;
        let mut checked = HashSet::new();
        
        // Pattern: require!(account_name.key() or ctx.accounts.name
        let require_pattern = Regex::new(r"require!\s*\([^)]*?(ctx\.accounts\.(\w+)|(\w+)\.key\(\))").unwrap();
        let if_pattern = Regex::new(r"if\s+[^{]*?(ctx\.accounts\.(\w+)|(\w+)\.key\(\))").unwrap();
        let constraint_pattern = Regex::new(r"constraint\s*=\s*[^,]*?(ctx\.accounts\.(\w+)|(\w+)\.key)").unwrap();
        
        for cap in require_pattern.captures_iter(source) {
            if let Some(m) = cap.get(2).or(cap.get(3)) {
                checked.insert(m.as_str().to_string());
            }
        }
        
        for cap in if_pattern.captures_iter(source) {
            if let Some(m) = cap.get(2).or(cap.get(3)) {
                checked.insert(m.as_str().to_string());
            }
        }
        
        for cap in constraint_pattern.captures_iter(source) {
            if let Some(m) = cap.get(2).or(cap.get(3)) {
                checked.insert(m.as_str().to_string());
            }
        }
        
        // Also add accounts with has_one constraint (implicitly checked)
        let has_one_pattern = Regex::new(r"has_one\s*=\s*(\w+)").unwrap();
        for cap in has_one_pattern.captures_iter(source) {
            if let Some(m) = cap.get(1) {
                checked.insert(m.as_str().to_string());
            }
        }
        
        // Add signer accounts (implicitly checked)
        // 1. Local Regex check (fallback)
        let signer_pattern = Regex::new(r"pub\s+(\w+)\s*:\s*Signer").unwrap();
        for cap in signer_pattern.captures_iter(source) {
            if let Some(m) = cap.get(1) {
                checked.insert(m.as_str().to_string());
            }
        }

        // 2. Global Semantic Context check
        if let Some(program_ctx) = &context.program_context {
            // Find the Context struct name used in this file
            // Pattern: fn func(ctx: Context<StructName>, ...)
            let context_pattern = Regex::new(r"Context\s*<\s*(\w+)\s*>").unwrap();
            
            for cap in context_pattern.captures_iter(source) {
                if let Some(struct_name) = cap.get(1) {
                    let name = struct_name.as_str();
                    // Look up struct in global context
                    if let Some(struct_info) = program_ctx.as_ref().resolve_struct(name) {
                        for (field, type_name) in &struct_info.fields {
                            let f: &String = field;
                            let t: &String = type_name;
                            if t.contains("Signer") {
                                checked.insert(f.clone());
                            }
                        }
                    }
                }
            }
        }
        
        checked
    }

    /// Extracts accounts used in sensitive operations (CPIs, transfers).
    ///
    /// Returns a set of (account_name, line_number, operation_type) tuples.
    /// 
    /// ## Sensitive Operations Tracked:
    /// - Token transfers (transfer, transfer_checked)
    /// - CPIs (invoke, invoke_signed, CpiContext)
    /// - Account mutations (borrow_mut, data assignment)
    /// - Lamport modifications
    fn extract_used_accounts(&self, source: &str) -> Vec<(String, usize, String)> {
        let mut used = Vec::new();
        
        // Patterns for ctx.accounts.name usage in sensitive operations
        let patterns = [
            // Token transfers
            (Regex::new(r"(?:transfer|transfer_checked)\s*\([^)]*ctx\.accounts\.(\w+)").unwrap(), "Token Transfer"),
            // CPI invocations
            (Regex::new(r"invoke(?:_signed)?\s*\([^)]*ctx\.accounts\.(\w+)").unwrap(), "CPI Call"),
            // CpiContext creation
            (Regex::new(r"CpiContext::(?:new|new_with_signer)\s*\([^)]*ctx\.accounts\.(\w+)").unwrap(), "CPI Context"),
            // General ctx.accounts access after sensitive keywords
            (Regex::new(r"(?:mint_to|burn|close_account|set_authority)\s*\([^)]*ctx\.accounts\.(\w+)").unwrap(), "Token Operation"),
        ];
        
        // Direct account access pattern
        let ctx_pattern = Regex::new(r"ctx\.accounts\.(\w+)").unwrap();
        
        for (line_num, line) in source.lines().enumerate() {
            // Skip comments
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }
            
            // Check specific sensitive patterns
            for (pattern, op_type) in &patterns {
                for cap in pattern.captures_iter(line) {
                    if let Some(m) = cap.get(1) {
                        used.push((m.as_str().to_string(), line_num + 1, op_type.to_string()));
                    }
                }
            }
            
            // Check for account mutations (state modification)
            if line.contains("ctx.accounts.") {
                // Borrow mut patterns
                if line.contains(".borrow_mut()") 
                    || line.contains(".try_borrow_mut()")
                    || line.contains(".data.borrow_mut()")
                {
                    for cap in ctx_pattern.captures_iter(line) {
                        if let Some(m) = cap.get(1) {
                            used.push((m.as_str().to_string(), line_num + 1, "State Modification".to_string()));
                        }
                    }
                }
                
                // Direct assignment patterns (account.field = value)
                if line.contains(" = ") && !line.contains("==") && !line.contains("let ") {
                    for cap in ctx_pattern.captures_iter(line) {
                        if let Some(m) = cap.get(1) {
                            used.push((m.as_str().to_string(), line_num + 1, "State Assignment".to_string()));
                        }
                    }
                }
                
                // Lamports modification
                if line.contains("lamports") && (line.contains("+=") || line.contains("-=") || line.contains(" = ")) {
                    for cap in ctx_pattern.captures_iter(line) {
                        if let Some(m) = cap.get(1) {
                            used.push((m.as_str().to_string(), line_num + 1, "Lamports Modification".to_string()));
                        }
                    }
                }
            }
        }
        
        // Deduplicate by (account, line)
        let mut seen = std::collections::HashSet::new();
        used.retain(|(acc, line, _)| seen.insert((acc.clone(), *line)));
        
        used
    }
}

impl VulnerabilityDetector for AccountUsageDetector {
    fn id(&self) -> &'static str { "V024" }
    
    fn name(&self) -> &'static str { "Account Used Without Validation" }
    
    fn description(&self) -> &'static str {
        "Detects accounts used in sensitive operations without being validated first."
    }
    
    fn severity(&self) -> Severity { Severity::High }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-284") }
    
    fn remediation(&self) -> &'static str {
        "Validate accounts before use:\n\
         require!(ctx.accounts.target.key() == expected_key, ErrorCode::Unauthorized);"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        
        // Get checked and used accounts
        let checked_accounts = self.extract_checked_accounts(context);
        let used_accounts = self.extract_used_accounts(source);
        
        // Find accounts that are used but not checked
        for (account_name, line, operation) in used_accounts {
            // Skip common safe accounts
            if account_name == "payer" 
                || account_name == "system_program"
                || account_name == "token_program"
                || account_name == "rent"
                || account_name == "clock"
            {
                continue;
            }
            
            if !checked_accounts.contains(&account_name) {
                findings.push(Finding {
                    id: format!("V024-{}", line),
                    detector_id: self.id().to_string(),
                    title: format!("Account '{}' used without validation", account_name),
                    description: format!(
                        "Account '{}' is used in a {} operation but was never \
                         validated with require!, if-condition, or has_one constraint. \
                         This could allow unauthorized account substitution.",
                        account_name, operation
                    ),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line,
                    location: format!("{}:{}", context.file_path, line),
                    code_snippet: source.lines().nth(line.saturating_sub(1))
                        .map(|s| s.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.75,
                });
            }
        }
        
        findings
    }
}

impl Default for AccountUsageDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock analysis context helper
    fn create_context(source: &str) -> AnalysisContext {
        AnalysisContext {
            file_path: "test.rs".to_string(),
            source_code: source.to_string(),
            ast: syn::parse_str(source).unwrap_or_else(|_| syn::parse_str("").unwrap()),
            accounts: Vec::new(),
            instructions: Vec::new(),
            state_accounts: Vec::new(),
            error_codes: Vec::new(),
            program_name: None,
            program_id: None,
            program_context: None,
        }
    }

    #[test]
    fn test_extract_checked_accounts() {
        let detector = AccountUsageDetector::new();
        let source = r#"
            require!(ctx.accounts.authority.key() == owner);
            if ctx.accounts.vault.is_initialized {
                // do something
            }
        "#;
        
        let context = create_context(source);
        let checked = detector.extract_checked_accounts(&context);
        assert!(checked.contains("authority"));
        assert!(checked.contains("vault"));
    }

    #[test]
    fn test_detect_unchecked_usage() {
        let detector = AccountUsageDetector::new();
        let source = r#"
            require!(ctx.accounts.authority.key() == owner);
            token::transfer(ctx.accounts.target_vault, amount)?;
        "#;
        
        let used = detector.extract_used_accounts(source);
        // target_vault is used but not in checked accounts
        assert!(!used.is_empty());
    }

    #[test]
    fn test_trail_of_bits_pattern() {
        // The exact pattern from Trail of Bits:
        // "Developer checks if a.key() == owner"
        // "Developer uses b in a sensitive spot"
        let detector = AccountUsageDetector::new();
        
        let source = r#"
            // Check account_a
            if ctx.accounts.account_a.key() == owner {
                // But use account_b in transfer - BUG!
                token::transfer(ctx.accounts.account_b, amount)?;
            }
        "#;
        
        let context = create_context(source);
        let checked = detector.extract_checked_accounts(&context);
        let used = detector.extract_used_accounts(source);
        
        // account_a is checked
        assert!(checked.contains("account_a"));
        // account_b is NOT checked
        assert!(!checked.contains("account_b"));
        // account_b IS used
        assert!(used.iter().any(|(name, _, _)| name == "account_b"));
        
        // This is the vulnerability: UsedAccounts - CheckedAccounts != empty
        let unchecked_usage: Vec<_> = used.iter()
            .filter(|(name, _, _)| !checked.contains(name))
            .collect();
        assert!(!unchecked_usage.is_empty(), "Should detect unchecked usage");
    }
}
