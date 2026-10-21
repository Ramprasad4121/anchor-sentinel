//! # V030 - Type Cosplay (Unchecked Account Deserialization)
//!
//! @title Type Cosplay Detector
//! @author Ramprasad
//!
//! Finds raw `AccountInfo` or `UncheckedAccount` fields whose data is read with
//! Borsh (`try_from_slice`, `deserialize`) by hand. Borsh does not check the
//! 8 byte Anchor discriminator, so an account of a different type with the same
//! layout is accepted as the expected type.
//!
//! ## Not flagged
//!
//! - typed `Account<'info, T>` fields
//! - fields read through `try_deserialize`, `Account::try_from`, `AccountLoader`
//! - handlers that mention `discriminator` or a custom `discriminant` enum next to the field
//!
//! ## CWE Reference
//!
//! - CWE-843: Access of Resource Using Incompatible Type

use crate::detectors::VulnerabilityDetector;
use crate::parser::{AccountType, AnalysisContext};
use crate::report::{Finding, Severity};

/// Detector for hand deserialization without a discriminator check.
pub struct TypeCosplayDetector;

impl TypeCosplayDetector {
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

    fn reads_data(stmt: &str, name: &str) -> bool {
        let borsh = stmt.contains("try_from_slice(")
            || stmt.contains("::deserialize(")
            || stmt.contains("deserialize_reader(");
        let touches = stmt.contains(&format!("{name}.data"))
            || stmt.contains(&format!("{name}.try_borrow_data"))
            || stmt.contains(&format!("{name}.try_borrow_mut_data"));
        borsh && touches
    }

    fn checks_type(stmts: &[String], name: &str) -> bool {
        stmts.iter().any(|s| {
            s.contains(name)
                && (s.contains("discriminator")
                    || s.contains("discriminant")
                    || s.contains("DISCRIMINATOR")
                    || s.contains("try_deserialize")
                    || s.contains("Account::try_from")
                    || s.contains("AccountLoader::try_from")
                    || s.contains("load()"))
        })
    }
}

impl VulnerabilityDetector for TypeCosplayDetector {
    fn id(&self) -> &'static str {
        "V030"
    }

    fn name(&self) -> &'static str {
        "Type Cosplay"
    }

    fn description(&self) -> &'static str {
        "Detects raw accounts deserialized with Borsh by hand, with no discriminator check."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-843")
    }

    fn remediation(&self) -> &'static str {
        "Use `Account<'info, T>` so Anchor checks the owner and the discriminator, or \
         call `T::try_deserialize(&mut &data[..])` which checks the discriminator."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let stmts = Self::stmts(&context.source_code);
        for acc_struct in &context.accounts {
            for field in &acc_struct.fields {
                if !matches!(
                    field.ty,
                    AccountType::AccountInfo | AccountType::UncheckedAccount
                ) {
                    continue;
                }
                let name = field.name.trim_start_matches("r#");
                let read = stmts.iter().any(|s| Self::reads_data(s, name));
                if !read || Self::checks_type(&stmts, name) {
                    continue;
                }
                let line = field.line;
                findings.push(Finding {
                    id: format!("V030-{}", line),
                    detector_id: self.id().to_string(),
                    title: format!("`{}` is deserialized by hand without a discriminator check", name),
                    description: format!(
                        "`{}` in `{}` is a raw account read with Borsh. Borsh does not check the \
                         discriminator, so another account type with the same layout is accepted.",
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

impl Default for TypeCosplayDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<Finding> {
        let ctx = AnalysisContext::from_source("t.rs", source.to_string()).unwrap();
        TypeCosplayDetector::new().detect(&ctx)
    }

    const H: &str = "use anchor_lang::prelude::*;\n";

    #[test]
    fn flags_borsh_read_of_raw_account() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Update<'info> {{
    user: AccountInfo<'info>,
}}
pub fn update(ctx: Context<Update>) -> Result<()> {{
    let user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
    Ok(())
}}
"
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector_id, "V030");
        assert_eq!(f[0].line, 5);
    }

    #[test]
    fn ignores_discriminator_checked_and_typed() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Update<'info> {{
    user: AccountInfo<'info>,
    typed: Account<'info, User>,
}}
pub fn update(ctx: Context<Update>) -> Result<()> {{
    let data = ctx.accounts.user.try_borrow_data()?;
    let user = User::try_deserialize(&mut &data[..])?;
    let t = User::try_from_slice(&ctx.accounts.typed.to_account_info().data.borrow());
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_manual_discriminator_compare() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Update<'info> {{
    user: AccountInfo<'info>,
}}
pub fn update(ctx: Context<Update>) -> Result<()> {{
    require!(ctx.accounts.user.data.borrow()[..8] == User::DISCRIMINATOR, E::Bad);
    let u = User::try_from_slice(&ctx.accounts.user.data.borrow()[8..])?;
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_custom_discriminant_enum_check() {
        let src = format!(
            "{H}
#[derive(Accounts)]
pub struct Update<'info> {{
    user: AccountInfo<'info>,
}}
pub fn update(ctx: Context<Update>) -> Result<()> {{
    let user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
    if user.discriminant != AccountDiscriminant::User {{
        return Err(ProgramError::InvalidAccountData.into());
    }}
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }
}
