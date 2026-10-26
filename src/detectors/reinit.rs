//! # V034 - Reinitialization of a Raw Account
//!
//! @title Reinitialization Detector
//! @author Ramprasad
//!
//! Finds raw `AccountInfo` or `UncheckedAccount` fields that a handler reads
//! with Borsh and then writes back through `try_borrow_mut_data` (or
//! `.data.borrow_mut()`), with no sign that the account was checked for being
//! uninitialized first. Anyone can call the handler again and overwrite the
//! stored authority (sealevel-attacks class 4).
//!
//! ## Not flagged
//!
//! - typed `Account<'info, T>` fields and `#[account(init)]` fields
//! - handlers that mention `is_initialized`, `initialized`, `discriminator`,
//!   `is_empty()`, `data_is_empty()`, `data_len() == 0` or `lamports() == 0`
//! - handlers that only read the account
//!
//! ## CWE Reference
//!
//! - CWE-665: Improper Initialization

use crate::detectors::VulnerabilityDetector;
use crate::parser::{AccountType, AnalysisContext};
use crate::report::{Finding, Severity};

/// Detector for raw accounts that can be initialized more than once.
pub struct ReinitDetector;

const GUARDS: [&str; 9] = [
    "is_initialized",
    "initialized",
    "discriminator",
    "discriminant",
    "is_empty()",
    "data_is_empty()",
    "data_len()==0",
    "lamports()==0",
    "isuninitialized",
];

impl ReinitDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self
    }

    fn stmts(source: &str) -> Vec<String> {
        source
            .split(';')
            .map(|s| {
                s.chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
                    .replace("ctx.accounts.", "")
                    .replace("self.", "")
            })
            .collect()
    }

    fn reads(stmt: &str, name: &str) -> bool {
        let borsh = stmt.contains("try_from_slice(") || stmt.contains("::deserialize(");
        borsh && (stmt.contains(&format!("{name}.data")) || stmt.contains(&format!("{name}.try_borrow_data")))
    }

    fn writes(stmt: &str, name: &str) -> bool {
        stmt.contains(&format!("{name}.try_borrow_mut_data"))
            || stmt.contains(&format!("{name}.data.borrow_mut"))
    }

    fn guarded(stmts: &[String]) -> bool {
        stmts.iter().any(|s| {
            let l = s.to_lowercase();
            GUARDS.iter().any(|g| l.contains(g))
        })
    }
}

impl VulnerabilityDetector for ReinitDetector {
    fn id(&self) -> &'static str {
        "V034"
    }

    fn name(&self) -> &'static str {
        "Reinitialization"
    }

    fn description(&self) -> &'static str {
        "Detects raw accounts read and rewritten by hand with no check that they were not already initialized."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-665")
    }

    fn remediation(&self) -> &'static str {
        "Use `#[account(init)]`, which fails if the account exists. For manual setup, store an \
         initialized flag or discriminator and reject the call when it is already set."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let stmts = Self::stmts(&context.source_code);
        if Self::guarded(&stmts) {
            return findings;
        }
        for acc_struct in &context.accounts {
            for field in &acc_struct.fields {
                if !matches!(
                    field.ty,
                    AccountType::AccountInfo | AccountType::UncheckedAccount
                ) {
                    continue;
                }
                let name = field.name.trim_start_matches("r#");
                let read = stmts.iter().any(|s| Self::reads(s, name));
                let write = stmts.iter().any(|s| Self::writes(s, name));
                if !(read && write) {
                    continue;
                }
                let line = field.line;
                findings.push(Finding {
                    id: format!("V034-{}", line),
                    detector_id: self.id().to_string(),
                    title: format!("`{}` can be initialized again", name),
                    description: format!(
                        "`{}` in `{}` is read and rewritten by hand, and nothing checks that it \
                         was empty or flagged uninitialized first. A second call overwrites the \
                         stored state, including the authority.",
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

impl Default for ReinitDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<Finding> {
        let ctx = AnalysisContext::from_source("t.rs", source.to_string()).unwrap();
        ReinitDetector::new().detect(&ctx)
    }

    const H: &str = "use anchor_lang::prelude::*;\n";

    fn program(body: &str) -> String {
        format!(
            "{H}
#[derive(Accounts)]
pub struct Initialize<'info> {{
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}}
pub fn initialize(ctx: Context<Initialize>) -> ProgramResult {{
{body}
    Ok(())
}}
"
        )
    }

    const SETUP: &str = "    let mut user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();\n";
    const WRITE: &str = "    user.authority = ctx.accounts.authority.key();\n    let mut storage = ctx.accounts.user.try_borrow_mut_data()?;\n    user.serialize(storage.deref_mut()).unwrap();\n";

    #[test]
    fn flags_sealevel_insecure_shape() {
        let f = run(&program(&format!("{SETUP}{WRITE}")));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector_id, "V034");
        assert_eq!(f[0].line, 5);
    }

    #[test]
    fn ignores_flag_check() {
        let body = format!(
            "{SETUP}    if user.is_initialized {{ return Err(ProgramError::AccountAlreadyInitialized); }}\n{WRITE}"
        );
        assert!(run(&program(&body)).is_empty());
    }

    #[test]
    fn ignores_sealevel_discriminator_variant() {
        let body = format!(
            "{SETUP}    if !user.discriminator {{ return Err(ProgramError::InvalidAccountData); }}\n{WRITE}"
        );
        assert!(run(&program(&body)).is_empty());
    }

    #[test]
    fn ignores_empty_data_check() {
        let body = format!(
            "    require!(ctx.accounts.user.data_is_empty(), ErrorCode::Used);\n{SETUP}{WRITE}"
        );
        assert!(run(&program(&body)).is_empty());
    }

    #[test]
    fn ignores_read_only_handler() {
        assert!(run(&program(SETUP)).is_empty());
    }

    #[test]
    fn ignores_typed_account() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Initialize<'info> {{
    #[account(init, payer = authority, space = 8 + 32)]
    user: Account<'info, User>,
    #[account(mut)]
    authority: Signer<'info>,
    system_program: Program<'info, System>,
}}
"
        );
        assert!(run(&src).is_empty());
    }
}
