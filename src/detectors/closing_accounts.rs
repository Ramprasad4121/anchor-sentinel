//! # V031 - Manual Account Close Without Cleanup
//!
//! @title Closing Accounts Detector
//! @author Ramprasad
//!
//! Finds handlers that close an account by hand: they set its lamports to zero
//! (or subtract all of them) but never clear the data, reassign the owner or
//! shrink the account. Until the transaction ends the account keeps its old
//! owner and data. A later instruction in the same transaction can refund the
//! rent, and the program then trusts a "closed" account again (a revival
//! attack, sealevel-attacks lesson 9).
//!
//! ## Not flagged
//!
//! - accounts closed with the `close = target` constraint
//! - handlers that also zero the data, `assign` the owner, `realloc` to 0,
//!   call `.close(...)`, or write `CLOSED_ACCOUNT_DISCRIMINATOR`
//! - partial lamport transfers (no zeroing)
//!
//! ## CWE Reference
//!
//! - CWE-672: Operation on a Resource after Expiration or Release

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for hand-rolled account closing that leaves data and owner intact.
pub struct ClosingAccountsDetector;

impl ClosingAccountsDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self
    }

    fn stmts(source: &str) -> Vec<String> {
        source
            .split([';', '{', '}'])
            .map(|s| {
                s.chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
                    .replace("ctx.accounts.", "")
                    .replace("self.", "")
            })
            .collect()
    }

    /// True when `name` appears in `stmt` as a whole identifier.
    fn mentions(stmt: &str, name: &str) -> bool {
        let is_id = |c: char| c.is_alphanumeric() || c == '_';
        stmt.match_indices(name).any(|(i, _)| {
            let before = stmt[..i].chars().next_back();
            let after = stmt[i + name.len()..].chars().next();
            !before.is_some_and(is_id) && !after.is_some_and(is_id)
        })
    }

    /// Names that refer to the same account: the field and `let a = field.to_account_info()` style aliases.
    fn aliases(stmts: &[String], name: &str) -> Vec<String> {
        let mut out = vec![name.to_string()];
        for s in stmts {
            let Some(rest) = s.strip_prefix("let") else { continue };
            let rest = rest.strip_prefix("mut").unwrap_or(rest);
            let Some((alias, rhs)) = rest.split_once('=') else { continue };
            let rhs = rhs.trim_start_matches('&').trim_start_matches("mut");
            if alias.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !alias.is_empty()
                && (rhs.starts_with(&format!("{name}.to_account_info()"))
                    || rhs.starts_with(&format!("{name}.as_ref()"))
                    || rhs == name
                    || rhs.starts_with(&format!("{name}.clone()")))
            {
                out.push(alias.to_string());
            }
        }
        out
    }

    fn drains_to_zero(stmt: &str, names: &[String]) -> bool {
        let lamports_zero = stmt.starts_with("**")
            && stmt.ends_with("=0")
            && (stmt.contains(".lamports.borrow_mut()") || stmt.contains(".try_borrow_mut_lamports()"));
        let sub_all = names
            .iter()
            .any(|n| stmt.contains(&format!("sub_lamports({n}.lamports())")));
        (lamports_zero || sub_all) && names.iter().any(|n| Self::mentions(stmt, n))
    }

    fn cleans_up(stmts: &[String], names: &[String]) -> bool {
        let cleanup = [
            "try_borrow_mut_data",
            ".data.borrow_mut",
            "borrow_mut_data",
            ".assign(",
            ".realloc(",
            ".resize(",
            ".close(",
            "CLOSED_ACCOUNT_DISCRIMINATOR",
            "sol_memset",
            ".fill(0)",
            "close_account",
        ];
        stmts.iter().any(|s| {
            cleanup.iter().any(|c| s.contains(c)) && names.iter().any(|n| Self::mentions(s, n))
        }) || stmts.iter().any(|s| s.contains("CLOSED_ACCOUNT_DISCRIMINATOR"))
    }
}

impl VulnerabilityDetector for ClosingAccountsDetector {
    fn id(&self) -> &'static str {
        "V031"
    }

    fn name(&self) -> &'static str {
        "Manual Close Without Cleanup"
    }

    fn description(&self) -> &'static str {
        "Detects accounts closed by zeroing lamports only, leaving the data and owner in place."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-672")
    }

    fn remediation(&self) -> &'static str {
        "Use `#[account(mut, close = destination)]`. If you must close by hand, also zero or \
         shrink the data and assign the account to the system program."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let stmts = Self::stmts(&context.source_code);
        for acc_struct in &context.accounts {
            for field in &acc_struct.fields {
                let name = field.name.trim_start_matches("r#");
                let names = Self::aliases(&stmts, name);
                if !stmts.iter().any(|s| Self::drains_to_zero(s, &names)) {
                    continue;
                }
                if Self::cleans_up(&stmts, &names) {
                    continue;
                }
                let line = field.line;
                findings.push(Finding {
                    id: format!("V031-{}", line),
                    detector_id: self.id().to_string(),
                    title: format!("`{}` is closed by hand without clearing its data", name),
                    description: format!(
                        "`{}` in `{}` has its lamports set to zero but the data and owner are left \
                         as they were. Until the transaction ends, a later instruction can refund \
                         the rent and the account looks alive again.",
                        name, acc_struct.name
                    ),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line,
                    location: format!("{}:{}", context.file_path, line),
                    code_snippet: context.get_source_line(line).map(|s| s.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.7,
                });
            }
        }
        findings
    }
}

impl Default for ClosingAccountsDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<Finding> {
        let ctx = AnalysisContext::from_source("t.rs", source.to_string()).unwrap();
        ClosingAccountsDetector::new().detect(&ctx)
    }

    const H: &str = "use anchor_lang::prelude::*;\n";

    #[test]
    fn flags_lamport_drain_without_cleanup() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Close<'info> {{
    account: Account<'info, Data>,
    destination: AccountInfo<'info>,
}}
pub fn close(ctx: Context<Close>) -> Result<()> {{
    let dest = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.lamports.borrow_mut() = dest
        .checked_add(ctx.accounts.account.to_account_info().lamports())
        .unwrap();
    **ctx.accounts.account.to_account_info().lamports.borrow_mut() = 0;
    Ok(())
}}
"
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector_id, "V031");
        assert_eq!(f[0].line, 5);
    }

    #[test]
    fn flags_alias_drain() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Close<'info> {{
    vault: Account<'info, Data>,
}}
pub fn close(ctx: Context<Close>) -> Result<()> {{
    let info = ctx.accounts.vault.to_account_info();
    **info.try_borrow_mut_lamports()? = 0;
    Ok(())
}}
"
        );
        assert_eq!(run(&src).len(), 1);
    }

    #[test]
    fn ignores_close_constraint() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Close<'info> {{
    #[account(mut, close = destination)]
    account: Account<'info, Data>,
    #[account(mut)]
    destination: AccountInfo<'info>,
}}
pub fn close(_ctx: Context<Close>) -> Result<()> {{
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_drain_with_data_zeroing() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Close<'info> {{
    account: Account<'info, Data>,
}}
pub fn close(ctx: Context<Close>) -> Result<()> {{
    let account = ctx.accounts.account.to_account_info();
    **account.lamports.borrow_mut() = 0;
    let mut data = account.try_borrow_mut_data()?;
    for byte in data.iter_mut() {{ *byte = 0; }}
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_drain_with_assign_and_realloc() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Close<'info> {{
    account: Account<'info, Data>,
}}
pub fn close(ctx: Context<Close>) -> Result<()> {{
    let info = ctx.accounts.account.to_account_info();
    **info.lamports.borrow_mut() = 0;
    info.assign(&system_program::ID);
    info.realloc(0, false)?;
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_partial_withdraw() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Withdraw<'info> {{
    vault: Account<'info, Data>,
}}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {{
    **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }
}
