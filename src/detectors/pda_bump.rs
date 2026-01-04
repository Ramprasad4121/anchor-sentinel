//! # V008 - Missing PDA Bump Check Detector
//!
//! @title PDA Bump Verification Detector
//! @author Ramprasad
//!
//! Detects PDAs created with `find_program_address` or `create_program_address`
//! without proper bump verification. Missing bump checks allow seed grinding
//! attacks where attackers derive valid PDAs with different bump values.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // VULNERABLE: No bump verification
//! let (pda, bump) = Pubkey::find_program_address(&[b"seed"], program_id);
//! // Bump never checked - attacker can grind seeds!
//! invoke_signed(&ix, &[pda], &[&[b"seed", &[bump]]])?;
//! ```
//!
//! ## Secure Pattern
//!
//! ```rust,ignore
//! // SECURE: Bump is stored and verified
//! let (pda, bump) = Pubkey::find_program_address(&[b"seed"], program_id);
//! assert_eq!(bump, ctx.accounts.my_pda.bump, "Invalid bump");
//! // OR use Anchor's bump constraint:
//! // #[account(seeds = [b"seed"], bump = my_pda.bump)]
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-330: Use of Insufficiently Random Values

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use regex::Regex;

/// Detector for missing PDA bump verification.
///
/// PDAs without bump verification are vulnerable to seed grinding attacks
/// where attackers derive valid PDAs with different bump values.
pub struct PdaBumpDetector;

impl PdaBumpDetector {
    /// Creates a new PDA bump detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Checks if bump verification exists near a PDA derivation.
    ///
    /// Searches within +10 lines of the derivation for patterns like:
    /// - `assert_eq!(bump`
    /// - `require!(bump`
    /// - `bump ==`
    /// - `.bump`
    ///
    /// # Arguments
    ///
    /// * `source` - The complete source code to analyze
    /// * `pda_line` - The line number where PDA derivation was found
    ///
    /// # Returns
    ///
    /// `true` if bump verification is present, `false` otherwise.
    fn has_bump_verification(&self, source: &str, pda_line: usize) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let start = pda_line.saturating_sub(1);
        let end = (pda_line + 10).min(lines.len());

        for i in start..end {
            if let Some(line) = lines.get(i) {
                let lower = line.to_lowercase();
                if lower.contains("assert_eq!(bump")
                    || lower.contains("assert!(bump")
                    || lower.contains("require!(bump")
                    || lower.contains("require_eq!(bump")
                    || lower.contains("bump ==")
                    || lower.contains(".bump")
                    || lower.contains("bump:")
                {
                    return true;
                }
            }
        }
        false
    }

    /// Extracts the seeds array from a PDA derivation line.
    ///
    /// # Arguments
    ///
    /// * `line` - The source line containing the PDA derivation
    ///
    /// # Returns
    ///
    /// The extracted seeds string or "unknown seeds" if not found.
    fn extract_seeds(&self, line: &str) -> String {
        if let Some(start) = line.find("&[") {
            if let Some(end) = line[start..].find(']') {
                return line[start..start + end + 1].to_string();
            }
        }
        "unknown seeds".to_string()
    }
}

impl VulnerabilityDetector for PdaBumpDetector {
    fn id(&self) -> &'static str { "V008" }
    
    fn name(&self) -> &'static str { "Missing PDA Bump Check" }
    
    fn description(&self) -> &'static str {
        "Detects PDA derivations without bump verification, enabling seed grinding attacks."
    }
    
    fn severity(&self) -> Severity { Severity::Critical }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-330") }
    
    fn remediation(&self) -> &'static str {
        "Verify the PDA bump:\n\
         1. Store bump in account data during initialization\n\
         2. Use assert_eq!(bump, stored_bump) after derivation\n\
         3. Or use Anchor's bump constraint: #[account(seeds=[...], bump)]"
    }

    /// Runs the PDA bump verification detector.
    ///
    /// Scans for `find_program_address` and `create_program_address` patterns
    /// and verifies that bump verification exists near each derivation.
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context containing parsed source code
    ///
    /// # Returns
    ///
    /// A vector of findings for each PDA derivation without bump verification.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        let patterns = [
            Regex::new(r"find_program_address\s*\(").unwrap(),
            Regex::new(r"create_program_address\s*\(").unwrap(),
            Regex::new(r"Pubkey::find_program_address").unwrap(),
        ];

        for (line_num, line) in source.lines().enumerate() {
            for pattern in &patterns {
                if pattern.is_match(line) && !self.has_bump_verification(source, line_num) {
                    let seeds = self.extract_seeds(line);
                    
                    findings.push(Finding {
                        id: format!("V008-{}", line_num + 1),
                        detector_id: self.id().to_string(),
                        title: "PDA derivation without bump verification".to_string(),
                        description: format!(
                            "PDA derived with {} but bump is not verified. Attackers can \
                             perform seed grinding attacks.", seeds
                        ),
                        severity: self.severity(),
                        file_path: context.file_path.clone(),
                        line: line_num + 1,
                        location: format!("{}:{}", context.file_path, line_num + 1),
                        code_snippet: Some(line.trim().to_string()),
                        remediation: self.remediation().to_string(),
                        cwe: self.cwe().map(|s| s.to_string()),
                        confidence: 0.85,
                    });
                }
            }
        }
        findings
    }
}

impl Default for PdaBumpDetector {
    fn default() -> Self { 
        Self::new() 
    }
}
