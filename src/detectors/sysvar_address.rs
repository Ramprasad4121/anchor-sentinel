//! # V029 - Unchecked Sysvar Address
//!
//! @title Sysvar Address Checking Detector
//! @author Ramprasad
//!
//! Finds raw `AccountInfo` or `UncheckedAccount` fields that are named like a
//! sysvar (`rent`, `clock`, `instructions`, ...) and are never tied to the real
//! sysvar address.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! #[derive(Accounts)]
//! pub struct Check<'info> {
//!     rent: AccountInfo<'info>,
//! }
//! ```
//!
//! A raw account is whatever the caller passes. If the program reads rent, clock
//! or instruction data from it, the caller can pass a fake account with crafted
//! bytes. The Wormhole bridge loss on Solana (2022) came from a forged
//! instructions sysvar.
//!
//! ## Not flagged
//!
//! - `Sysvar<'info, Rent>` typed fields
//! - fields with an `address = ...` constraint
//! - fields whose key is compared to a `sysvar::...::ID` value in a constraint or handler
//! - fields passed to `from_account_info`, `load_instruction_at_checked`,
//!   `load_current_index_checked` or `get_instruction_relative`, which check the address
//!
//! ## CWE Reference
//!
//! - CWE-345: Insufficient Verification of Data Authenticity

use crate::detectors::VulnerabilityDetector;
use crate::parser::{AccountField, AccountType, AnalysisContext, ConstraintType};
use crate::report::{Finding, Severity};

/// Detector for unchecked sysvar accounts.
pub struct SysvarAddressDetector;

impl SysvarAddressDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Short names that are exactly a sysvar.
    const EXACT: [&'static str; 9] = [
        "rent",
        "clock",
        "instructions",
        "recent_blockhashes",
        "slot_hashes",
        "slot_history",
        "stake_history",
        "epoch_schedule",
        "epoch_rewards",
    ];

    fn is_raw(field: &AccountField) -> bool {
        matches!(
            field.ty,
            AccountType::AccountInfo | AccountType::UncheckedAccount
        )
    }

    /// True when the field name says it is a sysvar.
    fn is_sysvar_name(name: &str) -> bool {
        let n = name.trim_start_matches("r#").to_lowercase();
        Self::EXACT.contains(&n.as_str()) || n.contains("sysvar")
    }

    /// The instructions sysvar is the one that decides who may do what, so it ranks higher.
    fn is_instructions(name: &str) -> bool {
        let n = name.to_lowercase();
        n.contains("instruction") || n == "ix_sysvar" || n.starts_with("ix_")
    }

    fn has_address(field: &AccountField) -> bool {
        field
            .constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Address(_)))
    }

    /// True when `name` appears as a whole identifier in `stmt`.
    fn mentions(stmt: &str, name: &str) -> bool {
        let mut start = 0;
        while let Some(pos) = stmt[start..].find(name) {
            let abs = start + pos;
            let before_ok = abs == 0
                || !stmt[..abs]
                    .chars()
                    .next_back()
                    .map(|c| c.is_alphanumeric() || c == '_')
                    .unwrap_or(false);
            let after = &stmt[abs + name.len()..];
            let after_ok = !after
                .chars()
                .next()
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false);
            if before_ok && after_ok {
                return true;
            }
            start = abs + name.len();
        }
        false
    }

    /// True when the field is checked against the sysvar address, or read through a
    /// helper that does that check itself.
    fn is_checked(name: &str, statements: &[String]) -> bool {
        statements.iter().any(|s| {
            if !Self::mentions(s, name) {
                return false;
            }
            let names_sysvar_id = s.contains("sysvar::")
                || s.contains("::ID")
                || s.contains("::id()")
                || s.contains("check_id");
            let compares = s.contains("==")
                || s.contains("!=")
                || s.contains("require_keys_eq!")
                || s.contains("require_eq!")
                || s.contains("assert_eq!")
                || s.contains("assert!")
                || s.contains("check_id");
            let address_compare = names_sysvar_id && compares;
            let key_read = s.contains(&format!("{name}.key"))
                || s.contains(&format!("{name}.unsigned_key"));
            let checked_reader = s.contains("from_account_info")
                || s.contains("_checked(")
                || s.contains("get_instruction_relative");
            (address_compare && key_read) || checked_reader
        })
    }
}

impl VulnerabilityDetector for SysvarAddressDetector {
    fn id(&self) -> &'static str {
        "V029"
    }

    fn name(&self) -> &'static str {
        "Unchecked Sysvar Address"
    }

    fn description(&self) -> &'static str {
        "Detects raw accounts named like a sysvar (rent, clock, instructions) whose address is never checked."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-345")
    }

    fn remediation(&self) -> &'static str {
        "Use `Sysvar<'info, Rent>` or `Sysvar<'info, Clock>`, or add \
         `address = anchor_lang::solana_program::sysvar::instructions::ID` to the field. \
         Read the instructions sysvar with the `_checked` helpers."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // One statement per `;`, whitespace removed, so multi-line checks still match.
        let mut statements: Vec<String> = context
            .source_code
            .split(';')
            .map(|s| {
                s.chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
                    .replace("ctx.accounts.", "")
                    .replace("self.", "")
            })
            .collect();

        for acc_struct in &context.accounts {
            let mut local = statements.clone();
            for f in &acc_struct.fields {
                for c in &f.constraints {
                    local.push(c.raw.chars().filter(|ch| !ch.is_whitespace()).collect());
                }
            }
            for field in &acc_struct.fields {
                if !Self::is_raw(field)
                    || !Self::is_sysvar_name(&field.name)
                    || Self::has_address(field)
                    || Self::is_checked(&field.name, &local)
                {
                    continue;
                }
                let line = field.line;
                let high = Self::is_instructions(&field.name);
                let (severity, confidence, why) = if high {
                    (
                        Severity::High,
                        0.7,
                        "A fake instructions account lets a caller forge which instructions \
                         ran earlier in the transaction.",
                    )
                } else {
                    (
                        self.severity(),
                        0.6,
                        "A fake account lets a caller feed the program made-up values.",
                    )
                };
                findings.push(Finding {
                    id: format!("V029-{}", line),
                    detector_id: self.id().to_string(),
                    title: format!("`{}` looks like a sysvar but its address is not checked", field.name),
                    description: format!(
                        "`{}` in `{}` is a raw account named like a sysvar. Nothing compares its key \
                         to the real sysvar address. {}",
                        field.name, acc_struct.name, why
                    ),
                    severity,
                    file_path: context.file_path.clone(),
                    line,
                    location: format!("{}:{}", context.file_path, line),
                    code_snippet: context.get_source_line(line).map(|s| s.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence,
                });
            }
        }
        statements.clear();
        findings
    }
}

impl Default for SysvarAddressDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<Finding> {
        let ctx = AnalysisContext::from_source("t.rs", source.to_string()).unwrap();
        SysvarAddressDetector::new().detect(&ctx)
    }

    const HEADER: &str = "use anchor_lang::prelude::*;\n";

    #[test]
    fn flags_raw_rent_account() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Check<'info> {{
    rent: AccountInfo<'info>,
}}
"
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector_id, "V029");
        assert_eq!(f[0].line, 5);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn instructions_sysvar_is_high() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Verify<'info> {{
    /// CHECK: read by hand
    pub instructions: UncheckedAccount<'info>,
}}
"
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn ignores_typed_sysvar_and_address_constraint() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Ok1<'info> {{
    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
    /// CHECK: address is pinned
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_handler_address_check() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Check<'info> {{
    rent: AccountInfo<'info>,
}}
pub fn handler(ctx: Context<Check>) -> Result<()> {{
    require_eq!(ctx.accounts.rent.key(), sysvar::rent::ID);
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_checked_readers() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Check<'info> {{
    rent: AccountInfo<'info>,
    ix_sysvar: AccountInfo<'info>,
}}
pub fn handler(ctx: Context<Check>) -> Result<()> {{
    let r = Rent::from_account_info(&ctx.accounts.rent)?;
    let i = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn handler_name_with_sysvar_is_not_a_check() {
        // The real sealevel-attacks example: the handler is called check_sysvar_address
        // and only logs the key. That must not count as an address check.
        let src = format!(
            "{HEADER}
#[program]
pub mod insecure {{
    use super::*;
    pub fn check_sysvar_address(ctx: Context<CheckSysvarAddress>) -> Result<()> {{
        msg!(\"Rent Key -> {{}}\", ctx.accounts.rent.key().to_string());
        Ok(())
    }}
}}
#[derive(Accounts)]
pub struct CheckSysvarAddress<'info> {{
    rent: AccountInfo<'info>,
}}
"
        );
        assert_eq!(run(&src).len(), 1);
    }

    #[test]
    fn ignores_unrelated_names_and_lookalike_checks() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Other<'info> {{
    pub rent_payer: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
}}
"
        );
        assert!(run(&src).is_empty());

        // A key comparison to something that is not a sysvar does not count.
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Check<'info> {{
    clock: AccountInfo<'info>,
}}
pub fn handler(ctx: Context<Check>) -> Result<()> {{
    require_keys_eq!(ctx.accounts.clock.key(), other.key());
    Ok(())
}}
"
        );
        assert_eq!(run(&src).len(), 1);
    }
}
