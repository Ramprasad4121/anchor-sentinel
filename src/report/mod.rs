//! # Report Generation Module
//!
//! @title Security Report Generator
//! @author Ramprasad
//!
//! Generates security reports in multiple formats including terminal output,
//! Markdown documents, JSON, and SARIF for CI/CD integration.
//!
//! ## Key Types
//!
//! - [`Report`] - Complete security analysis report
//! - [`Finding`] - Individual vulnerability finding
//! - [`Severity`] - Severity classification for findings

mod finding;
mod formatter;

pub use finding::{Finding, Severity};
pub use formatter::*;

use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete security analysis report.
///
/// Contains metadata about the scan, all findings, and summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Metadata about the scan operation.
    pub metadata: ReportMetadata,

    /// All findings from the analysis.
    pub findings: Vec<Finding>,

    /// Summary statistics by severity.
    pub summary: ReportSummary,
}

/// Metadata about the scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Tool version used for the scan.
    pub version: String,

    /// Timestamp when the scan was performed.
    pub timestamp: String,

    /// Path that was scanned.
    pub scanned_path: String,

    /// Number of files analyzed.
    pub files_analyzed: usize,
}

/// Summary of findings by severity level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Count of critical severity findings.
    pub critical: usize,

    /// Count of high severity findings.
    pub high: usize,

    /// Count of medium severity findings.
    pub medium: usize,

    /// Count of low severity findings.
    pub low: usize,

    /// Count of informational findings.
    pub info: usize,

    /// Total count of all findings.
    pub total: usize,
}

impl Report {
    /// Creates a new report from a collection of findings.
    ///
    /// Automatically calculates summary statistics from the findings.
    ///
    /// # Arguments
    ///
    /// * `findings` - Vector of security findings
    /// * `scanned_path` - Path that was analyzed
    ///
    /// # Returns
    ///
    /// A fully populated `Report` instance.
    pub fn new(findings: Vec<Finding>, scanned_path: PathBuf) -> Self {
        let summary = ReportSummary::from_findings(&findings);

        let metadata = ReportMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono_lite_timestamp(),
            scanned_path: scanned_path.display().to_string(),
            files_analyzed: findings
                .iter()
                .map(|f| &f.file_path)
                .collect::<std::collections::HashSet<_>>()
                .len(),
        };

        Self {
            metadata,
            findings,
            summary,
        }
    }

    /// Prints colorized output to the terminal.
    ///
    /// Displays each finding with appropriate color coding based on severity.
    pub fn print_terminal(&self) {
        if self.findings.is_empty() {
            println!("\n{}", "[+] No vulnerabilities found.".green().bold());
            return;
        }

        println!("\n{}", "[!] Security Findings:".red().bold());
        println!("{}", "=".repeat(60).cyan());

        for (i, finding) in self.findings.iter().enumerate() {
            finding.print_terminal(i + 1);
        }
    }

    /// Prints summary statistics to the terminal.
    pub fn print_summary(&self) {
        println!(
            "{}",
            format!(
                "[*] Summary: {} Critical | {} High | {} Medium | {} Low | {} Info",
                self.summary.critical,
                self.summary.high,
                self.summary.medium,
                self.summary.low,
                self.summary.info
            )
            .bold()
        );

        if self.summary.total == 0 {
            println!("{}", "[+] No issues found.".green().bold());
        } else {
            let severity_color = if self.summary.critical > 0 {
                "red"
            } else if self.summary.high > 0 {
                "yellow"
            } else {
                "blue"
            };

            let message = format!("[!] Total: {} issue(s) found", self.summary.total);
            match severity_color {
                "red" => println!("{}", message.red().bold()),
                "yellow" => println!("{}", message.yellow().bold()),
                _ => println!("{}", message.blue().bold()),
            }
        }
    }

    /// Converts the report to Markdown format.
    ///
    /// # Returns
    ///
    /// A Markdown-formatted string representation of the report.
    pub fn to_markdown(&self) -> String {
        formatter::to_markdown(self)
    }
}

impl ReportSummary {
    /// Creates a summary from a collection of findings.
    fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = ReportSummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            total: findings.len(),
        };

        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }

        summary
    }
}

/// Generates a simple timestamp without external dependencies.
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_creation() {
        let findings = vec![Finding {
            id: "test-1".to_string(),
            detector_id: "V001".to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            file_path: "test.rs".to_string(),
            line: 10,
            location: "Test::field".to_string(),
            code_snippet: None,
            remediation: "Fix it".to_string(),
            cwe: Some("CWE-123".to_string()),
        }];

        let report = Report::new(findings, PathBuf::from("./test"));

        assert_eq!(report.summary.high, 1);
        assert_eq!(report.summary.total, 1);
    }
}
