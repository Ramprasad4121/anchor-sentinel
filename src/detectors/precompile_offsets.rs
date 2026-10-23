//! # V032 - Precompile Offsets Not Checked
//!
//! @title Ed25519 / Secp256k1 Precompile Offset Detector
//! @author Ramprasad
//!
//! Finds programs that read the Ed25519 or Secp256k1 precompile instruction back
//! from the instructions sysvar and trust the keys, signatures or messages it names,
//! without checking the instruction index fields in each offsets entry.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! let ix = load_instruction_at_checked(idx, &ctx.accounts.instructions)?;
//! require_keys_eq!(ix.program_id, ed25519_program::ID);
//! let pubkey = &ix.data[16..48]; // key the entry names
//! approvals.push(Pubkey::try_from(pubkey)?);
//! ```
//!
//! The precompile verifies the bytes its offsets point at. Each entry carries a
//! `signature_instruction_index`, a `public_key_instruction_index` and a
//! `message_instruction_index`. Any value other than `u16::MAX` (or the precompile's
//! own index) sends the runtime to a different instruction in the transaction. If the
//! program counts the key named in entry two but the runtime verified a signature held
//! by entry one, one real signature satisfies two approvals. This is how the Rain card
//! program lost about $1.1M on Solana in August 2026.
//!
//! ## Not flagged
//!
//! - files that never read an instruction back from the instructions sysvar
//! - files that mention all three index fields by name
//! - files with three or more compares against `u16::MAX`, `0xFFFF` or `65535`
//!
//! ## References
//!
//! - <https://solana.com/docs/core/programs/precompiles>
//! - <https://blog.verichains.io/p/rain-hack-analysis-ed25519-signature>
//!
//! ## CWE Reference
//!
//! - CWE-347: Improper Verification of Cryptographic Signature

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Detector for precompile instruction data trusted without index checks.
pub struct PrecompileOffsetsDetector;

impl PrecompileOffsetsDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Markers that the file deals with a signature precompile.
    const PRECOMPILE: [&'static str; 6] = [
        "ed25519_program",
        "Ed25519Program",
        "ED25519_ID",
        "secp256k1_program",
        "Secp256k1Program",
        "SECP256K1_ID",
    ];

    /// Calls that read a sibling instruction back from the instructions sysvar.
    const READERS: [&'static str; 3] = [
        "load_instruction_at_checked(",
        "load_instruction_at(",
        "get_instruction_relative(",
    ];

    /// Field name fragments for each of the three index fields.
    const INDEX_KINDS: [&'static [&'static str]; 3] = [
        &["signature_instruction_index", "sig_instruction_index", "signature_ix_index", "sig_ix_index"],
        &["public_key_instruction_index", "pubkey_instruction_index", "pk_instruction_index", "pubkey_ix_index", "public_key_ix_index"],
        &["message_instruction_index", "msg_instruction_index", "message_ix_index", "msg_ix_index"],
    ];

    fn all_indexes_named(compact: &str) -> bool {
        Self::INDEX_KINDS
            .iter()
            .all(|names| names.iter().any(|n| compact.contains(n)))
    }

    fn some_index_named(compact: &str) -> bool {
        Self::INDEX_KINDS
            .iter()
            .any(|names| names.iter().any(|n| compact.contains(n)))
    }

    fn sentinel_compares(compact: &str) -> usize {
        ["u16::MAX", "0xFFFF", "0xffff", "65535"]
            .iter()
            .map(|p| compact.matches(p).count())
            .sum()
    }
}

impl VulnerabilityDetector for PrecompileOffsetsDetector {
    fn id(&self) -> &'static str {
        "V032"
    }

    fn name(&self) -> &'static str {
        "Precompile Offsets Not Checked"
    }

    fn description(&self) -> &'static str {
        "Detects programs that trust keys read from an Ed25519 or Secp256k1 precompile instruction without checking its instruction index fields."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cwe(&self) -> Option<&'static str> {
        Some("CWE-347")
    }

    fn remediation(&self) -> &'static str {
        "For every entry in the precompile instruction, require signature_instruction_index, \
         public_key_instruction_index and message_instruction_index to equal u16::MAX (or the \
         precompile's own index), and bind the key you count to the offsets you checked. \
         Count distinct keys, not entries."
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let src = &context.source_code;
        if !Self::PRECOMPILE.iter().any(|m| src.contains(m)) {
            return Vec::new();
        }
        let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
        let Some(reader) = Self::READERS.iter().find(|r| compact.contains(*r)) else {
            return Vec::new();
        };
        if Self::all_indexes_named(&compact) || Self::sentinel_compares(&compact) >= 3 {
            return Vec::new();
        }

        // Report at the first read of a sibling instruction.
        let needle = reader.trim_end_matches('(');
        let line = src
            .lines()
            .position(|l| {
                let t = l.trim_start();
                l.contains(needle) && !t.starts_with("//") && !t.starts_with("use ")
            })
            .map(|i| i + 1)
            .unwrap_or(1);
        let partial = Self::some_index_named(&compact) || Self::sentinel_compares(&compact) > 0;
        let confidence = if partial { 0.5 } else { 0.7 };
        let detail = if partial {
            "Some index checks exist, but not one for each of signature, public key and message."
        } else {
            "No index field is checked."
        };

        vec![Finding {
            id: format!("V032-{}", line),
            detector_id: self.id().to_string(),
            title: "Signature precompile data is trusted without index checks".to_string(),
            description: format!(
                "This file reads an Ed25519 or Secp256k1 precompile instruction back from the \
                 instructions sysvar. Each entry has signature, public key and message instruction \
                 indexes that can point at other instructions in the transaction. {detail} A forged \
                 entry can name an approver while the runtime verified someone else's signature, \
                 so one real signature can count as several approvals."
            ),
            severity: self.severity(),
            file_path: context.file_path.clone(),
            line,
            location: format!("{}:{}", context.file_path, line),
            code_snippet: context.get_source_line(line).map(|s| s.trim().to_string()),
            remediation: self.remediation().to_string(),
            cwe: self.cwe().map(|s| s.to_string()),
            confidence,
        }]
    }
}

impl Default for PrecompileOffsetsDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(source: &str) -> Vec<Finding> {
        let ctx = AnalysisContext::from_source("t.rs", source.to_string()).unwrap();
        PrecompileOffsetsDetector::new().detect(&ctx)
    }

    const VULN: &str = r#"
use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;

pub fn submit(ctx: Context<Submit>, idx: u16) -> Result<()> {
    let ix = load_instruction_at_checked(idx as usize, &ctx.accounts.instructions)?;
    require_keys_eq!(ix.program_id, ed25519_program::ID);
    let n = ix.data[0] as usize;
    for i in 0..n {
        let base = 2 + i * 14;
        let pk_off = u16::from_le_bytes([ix.data[base + 4], ix.data[base + 5]]) as usize;
        let key = Pubkey::try_from(&ix.data[pk_off..pk_off + 32]).unwrap();
        ctx.accounts.state.approvals.push(key);
    }
    Ok(())
}
"#;

    #[test]
    fn flags_unchecked_precompile_parse() {
        let f = run(VULN);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector_id, "V032");
        assert_eq!(f[0].line, 7);
        assert!(f[0].confidence > 0.6);
    }

    #[test]
    fn quiet_when_all_three_indexes_are_checked() {
        let src = VULN.replace(
            "ctx.accounts.state.approvals.push(key);",
            "let o = Ed25519SignatureOffsets::unpack(&ix.data[base..base + 14])?;\n        require!(o.signature_instruction_index == u16::MAX, E::Bad);\n        require!(o.public_key_instruction_index == u16::MAX, E::Bad);\n        require!(o.message_instruction_index == u16::MAX, E::Bad);\n        ctx.accounts.state.approvals.push(key);",
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn quiet_with_three_raw_sentinel_compares() {
        let src = VULN.replace(
            "ctx.accounts.state.approvals.push(key);",
            "for off in [2usize, 6, 12] {\n            let v = u16::from_le_bytes([ix.data[base + off], ix.data[base + off + 1]]);\n            require!(v == u16::MAX, E::Bad);\n        }\n        require!(0xFFFFu16 == u16::MAX, E::Bad);\n        require!(65535u16 == u16::MAX, E::Bad);\n        ctx.accounts.state.approvals.push(key);",
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn lower_confidence_when_only_some_indexes_checked() {
        let src = VULN.replace(
            "ctx.accounts.state.approvals.push(key);",
            "require!(o.signature_instruction_index == u16::MAX, E::Bad);\n        ctx.accounts.state.approvals.push(key);",
        );
        let f = run(&src);
        assert_eq!(f.len(), 1);
        assert!(f[0].confidence < 0.6);
    }

    #[test]
    fn quiet_without_instruction_readback() {
        let src = "use anchor_lang::solana_program::ed25519_program;\npub fn client() { let _id = ed25519_program::ID; }\n";
        assert!(run(src).is_empty());
    }

    #[test]
    fn quiet_for_unrelated_program() {
        let src = "use anchor_lang::prelude::*;\npub fn go() { let ix = load_instruction_at_checked(0, &sysvar); }\n";
        assert!(run(src).is_empty());
    }
}
