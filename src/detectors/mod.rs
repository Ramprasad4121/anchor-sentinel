//! # Vulnerability Detector Module
//!
//! @title Vulnerability Detection Framework
//! @author Ramprasad
//!
//! This module provides the framework for vulnerability detection and contains
//! implementations of all security detectors.
//!
//! ## Architecture
//!
//! All detectors implement the [`VulnerabilityDetector`] trait, which provides
//! a consistent interface for detection, severity classification, and remediation
//! guidance.
//!
//! ## Available Detectors
//!
//! | ID | Name | Severity |
//! |----|------|----------|
//! | V001 | Missing Signer Check | Critical |
//! | V002 | Missing Owner Check | High |
//! | V003 | Integer Overflow/Underflow | High |
//! | V004 | PDA Seed Collision | High |
//! | V005 | Unchecked Initialization | High |
//! | V006 | Unsafe CPI | Critical |

mod integer_overflow;
mod missing_owner;
mod missing_signer;
mod pda_collision;
mod pda_bump;
mod unchecked_transfer;
mod authority_delegation;
mod mint_burn;
mod unverified_seeds;
mod cpi_reentrancy;
mod oracle_risks;
mod replay_attack;
mod rent_bypass;
mod missing_close;
mod upgrade_gaps;
mod error_suppression;
mod loop_overflow;
mod lamports_rounding;
mod unchecked_init;
mod unsafe_cpi;
mod token_2022;
pub mod utils;

pub use integer_overflow::IntegerOverflowDetector;
pub use missing_owner::MissingOwnerDetector;
pub use missing_signer::MissingSignerDetector;
pub use pda_collision::PdaCollisionDetector;
pub use pda_bump::PdaBumpDetector;
pub use unchecked_transfer::UncheckedTransferDetector;
pub use authority_delegation::AuthorityDelegationDetector;
pub use mint_burn::MintBurnDetector;
pub use unverified_seeds::UnverifiedSeedsDetector;
pub use cpi_reentrancy::CpiReentrancyDetector;
pub use oracle_risks::OracleRisksDetector;
pub use replay_attack::ReplayAttackDetector;
pub use rent_bypass::RentBypassDetector;
pub use missing_close::MissingCloseDetector;
pub use upgrade_gaps::UpgradeGapsDetector;
pub use error_suppression::ErrorSuppressionDetector;
pub use loop_overflow::LoopOverflowDetector;
pub use lamports_rounding::LamportsRoundingDetector;
pub use unchecked_init::UncheckedInitDetector;
pub use unsafe_cpi::UnsafeCpiDetector;
pub use token_2022::Token2022Detector;

use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

/// Trait for implementing vulnerability detectors.
///
/// All detectors must implement this trait to be registered with the
/// [`DetectorRegistry`]. The trait provides a consistent interface for
/// detection, classification, and remediation guidance.
///
/// # Example Implementation
///
/// ```rust,ignore
/// pub struct MyDetector;
///
/// impl VulnerabilityDetector for MyDetector {
///     fn id(&self) -> &'static str { "V999" }
///     fn name(&self) -> &'static str { "My Vulnerability" }
///     fn description(&self) -> &'static str { "Detects my vulnerability" }
///     fn severity(&self) -> Severity { Severity::High }
///     fn remediation(&self) -> &'static str { "Fix the issue" }
///     
///     fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
///         // Detection logic
///         Vec::new()
///     }
/// }
/// ```
pub trait VulnerabilityDetector: Send + Sync {
    /// Returns the unique identifier for this detector.
    ///
    /// Format: "Vnnn" where nnn is a zero-padded number (e.g., "V001").
    fn id(&self) -> &'static str;

    /// Returns the human-readable name of the vulnerability.
    fn name(&self) -> &'static str;

    /// Returns a detailed description of what this detector looks for.
    fn description(&self) -> &'static str;

    /// Returns the default severity level for findings from this detector.
    fn severity(&self) -> Severity;

    /// Runs the detector against the given analysis context.
    ///
    /// # Arguments
    ///
    /// * `context` - The parsed program context to analyze
    ///
    /// # Returns
    ///
    /// A vector of findings discovered during analysis.
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding>;

    /// Returns the CWE (Common Weakness Enumeration) ID if applicable.
    ///
    /// # Returns
    ///
    /// An optional CWE identifier string (e.g., "CWE-862").
    fn cwe(&self) -> Option<&'static str> {
        None
    }

    /// Returns remediation advice for addressing this vulnerability.
    fn remediation(&self) -> &'static str;
}

/// Registry containing all available vulnerability detectors.
///
/// The registry manages the collection of detectors and provides methods
/// to run them against analysis contexts.
///
/// # Example
///
/// ```rust,ignore
/// let registry = DetectorRegistry::new();
/// let findings = registry.run_all(&context);
/// ```
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn VulnerabilityDetector>>,
}

impl DetectorRegistry {
    /// Creates a new registry with all default detectors.
    ///
    /// Initializes the registry with all built-in vulnerability detectors:
    /// V001 through V006.
    pub fn new() -> Self {
        let detectors: Vec<Box<dyn VulnerabilityDetector>> = vec![
            // Original detectors (V001-V007)
            Box::new(MissingSignerDetector),
            Box::new(MissingOwnerDetector),
            Box::new(IntegerOverflowDetector),
            Box::new(PdaCollisionDetector),
            Box::new(UncheckedInitDetector),
            Box::new(UnsafeCpiDetector),
            Box::new(Token2022Detector),
            // Phase 1: V008, V010, V011, V016, V021
            Box::new(PdaBumpDetector::new()),
            Box::new(UncheckedTransferDetector::new()),
            Box::new(AuthorityDelegationDetector::new()),
            Box::new(MintBurnDetector::new()),
            Box::new(UnverifiedSeedsDetector::new()),
            // Phase 2: V009, V014, V015
            Box::new(CpiReentrancyDetector::new()),
            Box::new(OracleRisksDetector::new()),
            Box::new(ReplayAttackDetector::new()),
            // Phase 3: V012, V013, V018, V022
            Box::new(RentBypassDetector::new()),
            Box::new(MissingCloseDetector::new()),
            Box::new(ErrorSuppressionDetector::new()),
            Box::new(LamportsRoundingDetector::new()),
            // Phase 4: V017, V019
            Box::new(UpgradeGapsDetector::new()),
            Box::new(LoopOverflowDetector::new()),
        ];

        Self { detectors }
    }

    /// Returns a reference to all registered detectors.
    pub fn detectors(&self) -> &[Box<dyn VulnerabilityDetector>] {
        &self.detectors
    }

    /// Runs all detectors against the given context.
    ///
    /// Executes each registered detector and aggregates findings,
    /// sorted by severity in descending order (Critical first).
    ///
    /// # Arguments
    ///
    /// * `context` - The analysis context to scan
    ///
    /// # Returns
    ///
    /// A sorted vector of all findings.
    pub fn run_all(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        for detector in &self.detectors {
            let findings = detector.detect(context);
            all_findings.extend(findings);
        }

        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        all_findings
    }

    /// Runs a specific detector by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The detector ID (e.g., "V001")
    /// * `context` - The analysis context to scan
    ///
    /// # Returns
    ///
    /// Findings from the specified detector, or empty if not found.
    pub fn run_by_id(&self, id: &str, context: &AnalysisContext) -> Vec<Finding> {
        for detector in &self.detectors {
            if detector.id() == id {
                return detector.detect(context);
            }
        }
        Vec::new()
    }

    /// Retrieves a detector by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The detector ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the detector if found.
    pub fn get_detector(&self, id: &str) -> Option<&dyn VulnerabilityDetector> {
        for detector in &self.detectors {
            if detector.id() == id {
                return Some(detector.as_ref());
            }
        }
        None
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create a finding from a detector.
///
/// Standardizes the creation of findings with consistent formatting.
///
/// # Arguments
///
/// * `detector` - The detector creating the finding
/// * `context` - The analysis context
/// * `title` - Short title describing the finding
/// * `description` - Detailed description of the vulnerability
/// * `location` - Code location identifier
/// * `line` - Line number in the source file
/// * `code_snippet` - Optional code snippet showing vulnerable code
///
/// # Returns
///
/// A fully populated [`Finding`] instance.
pub fn create_finding(
    detector: &dyn VulnerabilityDetector,
    context: &AnalysisContext,
    title: String,
    description: String,
    location: String,
    line: usize,
    code_snippet: Option<String>,
) -> Finding {
    Finding {
        id: format!("{}-{}", detector.id(), uuid_simple()),
        detector_id: detector.id().to_string(),
        title,
        description,
        severity: detector.severity(),
        file_path: context.file_path.clone(),
        line,
        location,
        code_snippet,
        remediation: detector.remediation().to_string(),
        cwe: detector.cwe().map(|s| s.to_string()),
        confidence: 1.0,
    }
}

/// Generates a simple unique identifier for findings.
///
/// Uses the current timestamp to create a reasonably unique suffix.
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}", duration.as_nanos() % 0xFFFFFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = DetectorRegistry::new();
        assert!(!registry.detectors().is_empty());
    }

    #[test]
    fn test_detector_ids_unique() {
        let registry = DetectorRegistry::new();
        let mut ids: Vec<_> = registry.detectors().iter().map(|d| d.id()).collect();
        let len_before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Detector IDs must be unique");
    }
}
