//! # V028 - Duplicate Mutable Accounts
//!
//! @title Duplicate Mutable Account Detector
//! @author Ramprasad
//!
//! Finds `#[derive(Accounts)]` structs that take two mutable accounts of the same
//! data type and never make sure they are different accounts.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! #[derive(Accounts)]
//! pub struct Update<'info> {
//!     #[account(mut)]
//!     pub user_a: Account<'info, User>,
//!     #[account(mut)]
//!     pub user_b: Account<'info, User>,
//! }
//! ```
//!
//! If the caller passes the same account twice, the handler holds two copies of one
//! account. Both are serialized on exit and the last write wins, so the first
//! update is silently lost.
//!
//! ## Anchor version note
//!
//! Anchor 1.0 rejects duplicate mutable `Account` fields at runtime unless the field
//! has `dup`. Older Anchor versions do not. So a finding without `dup` matters for
//! programs on Anchor 0.x, and a finding with `dup` means the program opted out of
//! the framework check on purpose and must guard it by hand.
//!
//! ## Not flagged
//!
//! - `init` fields, token `Account<TokenAccount>` and `Account<Mint>` pairs
//! - pairs with different static seed prefixes
//! - pairs where a constraint or the handler compares the two keys
//!
//! ## CWE Reference
//!
//! - CWE-694: Use of Multiple Resources with Duplicate Identifier

use crate::detectors::VulnerabilityDetector;
use crate::parser::{AccountField, AccountType, AnalysisContext, ConstraintType};
use crate::report::{Finding, Severity};

/// Detector for duplicate mutable accounts.
pub struct DuplicateMutableDetector;

impl DuplicateMutableDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Account data types that are normally paired (from and to) without risk.
    fn is_token_type(ty: &str) -> bool {
        let last = ty.rsplit("::").next().unwrap_or(ty);
        matches!(last, "TokenAccount" | "Mint" | "Token" | "Unknown")
    }

    fn data_type(field: &AccountField) -> Option<&str> {
        match &field.ty {
            AccountType::Account(inner) => Some(inner.as_str()),
            _ => None,
        }
    }

    fn has_dup(field: &AccountField) -> bool {
        field.constraints.iter().any(|c| {
            let raw: String = c.raw.chars().filter(|ch| !ch.is_whitespace()).collect();
            raw == "dup" || raw.starts_with("dup@") || raw.starts_with("unsafe(dup")
        })
    }

    fn first_seed(field: &AccountField) -> Option<String> {
        field.constraints.iter().find_map(|c| match &c.constraint_type {
            ConstraintType::Seeds(seeds) => seeds.first().cloned(),
            _ => None,
        })
    }

    fn has_address(field: &AccountField) -> bool {
        field
            .constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Address(_)))
    }

    /// True when a seed is a static literal such as `b"vault"`.
    fn is_static_seed(seed: &str) -> bool {
        let s = seed.trim();
        s.starts_with("b\"") || s.starts_with('"')
    }

    /// True when the two fields are told apart by a constraint or handler check.
    fn keys_compared(a: &AccountField, b: &AccountField, compact_text: &str) -> bool {
        let (n1, n2) = (&a.name, &b.name);
        let pats = [
            format!("{n1}.key()!={n2}.key()"),
            format!("{n2}.key()!={n1}.key()"),
            format!("{n1}.key()=={n2}.key()"),
            format!("{n2}.key()=={n1}.key()"),
            format!("{n1}.key!={n2}.key"),
            format!("{n2}.key!={n1}.key"),
            format!("{n1}.key()!=&{n2}.key()"),
            format!("{n2}.key()!=&{n1}.key()"),
        ];
        // Strip `ctx.accounts.` so handler comparisons match field-level ones.
        let text = compact_text.replace("ctx.accounts.", "");
        if pats.iter().any(|p| text.contains(p.as_str())) {
            return true;
        }
        // require_keys_neq!(a.key(), b.key()) in either order
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("require_keys_neq!(") {
            let tail = &rest[pos..];
            let end = tail.find(");").unwrap_or(tail.len());
            let call = &tail[..end];
            if call.contains(n1.as_str()) && call.contains(n2.as_str()) {
                return true;
            }
            rest = &tail[end.min(tail.len())..];
            if rest.is_empty() {
                break;
            }
        }
        false
    }
}

impl VulnerabilityDetector for DuplicateMutableDetector {
    fn id(&self) -> &'static str {
        "V028"
    }

    fn name(&self) -> &'static str {
        "Duplicate Mutable Accounts"
    }

    fn description(&self) -> &'static str {
        "Detects two mutable accounts of the same type in one instruction with no check that they are different accounts."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-694")
    }

    fn remediation(&self) -> &'static str {
        "Add `constraint = a.key() != b.key()` to one of the accounts, or call \
         `require_keys_neq!` in the handler. On Anchor 1.0 and later, remove `dup` unless \
         the handler is written for aliased accounts."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let compact_source: String = context
            .source_code
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        for acc_struct in &context.accounts {
            // Only look at constraints in this struct plus the whole file for handler checks.
            let mut constraint_text = String::new();
            for f in &acc_struct.fields {
                for c in &f.constraints {
                    constraint_text.extend(c.raw.chars().filter(|ch| !ch.is_whitespace()));
                    constraint_text.push(';');
                }
            }
            let text = format!("{constraint_text}{compact_source}");

            let muts: Vec<&AccountField> = acc_struct
                .fields
                .iter()
                .filter(|f| f.is_mutable && !f.is_init)
                .filter(|f| {
                    Self::data_type(f)
                        .map(|t| !Self::is_token_type(t))
                        .unwrap_or(false)
                })
                .collect();

            for (i, a) in muts.iter().enumerate() {
                for b in muts.iter().skip(i + 1) {
                    if Self::data_type(a) != Self::data_type(b) {
                        continue;
                    }
                    if Self::has_address(a) || Self::has_address(b) {
                        continue;
                    }
                    if let (Some(sa), Some(sb)) = (Self::first_seed(a), Self::first_seed(b)) {
                        if Self::is_static_seed(&sa) && Self::is_static_seed(&sb) && sa != sb {
                            continue;
                        }
                    }
                    if Self::keys_compared(a, b, &text) {
                        continue;
                    }

                    let opted_out = Self::has_dup(a) || Self::has_dup(b);
                    let ty = Self::data_type(a).unwrap_or("account");
                    let line = b.line;
                    let (title, description, confidence) = if opted_out {
                        (
                            format!("`{}` and `{}` may alias (dup opt-out)", a.name, b.name),
                            format!(
                                "`{}` and `{}` are both mutable `{}` accounts and one is marked `dup`, \
                                 so Anchor will not stop the same account being passed twice. Nothing \
                                 in `{}` compares their keys. Both are written back on exit and the \
                                 last write wins.",
                                a.name, b.name, ty, acc_struct.name
                            ),
                            0.75,
                        )
                    } else {
                        (
                            format!("`{}` and `{}` can be the same account", a.name, b.name),
                            format!(
                                "`{}` and `{}` are both mutable `{}` accounts in `{}` and nothing \
                                 checks they are different. If a caller passes one account twice, \
                                 both are written back on exit and the last write wins. Anchor 1.0 \
                                 and later rejects this at runtime, older versions do not.",
                                a.name, b.name, ty, acc_struct.name
                            ),
                            0.6,
                        )
                    };

                    findings.push(Finding {
                        id: format!("V028-{}", line),
                        detector_id: self.id().to_string(),
                        title,
                        description,
                        severity: self.severity(),
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
        }

        findings
    }
}

impl Default for DuplicateMutableDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<Finding> {
        let ctx = AnalysisContext::from_source("t.rs", source.to_string()).unwrap();
        DuplicateMutableDetector::new().detect(&ctx)
    }

    const HEADER: &str = "use anchor_lang::prelude::*;\n";

    #[test]
    fn flags_two_mut_accounts_of_same_type() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Update<'info> {{
    #[account(mut)]
    pub user_a: Account<'info, User>,
    #[account(mut)]
    pub user_b: Account<'info, User>,
}}
"
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector_id, "V028");
        assert_eq!(f[0].line, 8);
        assert!(f[0].title.contains("user_a"));
    }

    #[test]
    fn flags_dup_opt_out_with_higher_confidence() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Update<'info> {{
    #[account(mut)]
    pub a: Account<'info, Counter>,
    #[account(mut, dup)]
    pub b: Account<'info, Counter>,
}}
"
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert!(f[0].confidence > 0.7);
        assert!(f[0].title.contains("dup"));
    }

    #[test]
    fn ignores_key_constraint() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Update<'info> {{
    #[account(mut)]
    pub user_a: Account<'info, User>,
    #[account(mut, constraint = user_a.key() != user_b.key())]
    pub user_b: Account<'info, User>,
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_handler_key_check() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Update<'info> {{
    #[account(mut)]
    pub user_a: Account<'info, User>,
    #[account(mut)]
    pub user_b: Account<'info, User>,
}}
pub fn handler(ctx: Context<Update>) -> Result<()> {{
    require_keys_neq!(ctx.accounts.user_a.key(), ctx.accounts.user_b.key());
    Ok(())
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_different_types_readonly_and_token_pairs() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Mixed<'info> {{
    #[account(mut)]
    pub a: Account<'info, User>,
    #[account(mut)]
    pub b: Account<'info, Pool>,
    pub c: Account<'info, User>,
}}
#[derive(Accounts)]
pub struct Tokens<'info> {{
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
}}
"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_init_and_distinct_static_seeds() {
        let src = format!(
            "{HEADER}
#[derive(Accounts)]
pub struct Create<'info> {{
    #[account(init, payer = p, space = 8 + 8)]
    pub a: Account<'info, Data>,
    #[account(init, payer = p, space = 8 + 8)]
    pub b: Account<'info, Data>,
    #[account(mut)]
    pub p: Signer<'info>,
}}
#[derive(Accounts)]
pub struct Seeded<'info> {{
    #[account(mut, seeds = [b\"left\", x.key().as_ref()], bump)]
    pub a: Account<'info, Data>,
    #[account(mut, seeds = [b\"right\", x.key().as_ref()], bump)]
    pub b: Account<'info, Data>,
    pub x: Signer<'info>,
}}
"
        );
        assert!(run(&src).is_empty());
    }
}
