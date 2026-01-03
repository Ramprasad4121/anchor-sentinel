//! # Finding and Severity Definitions
//!
//! @title Security Finding Data Structures
//! @author Ramprasad
//!
//! Defines the core data structures for representing security findings
//! and their severity classification.

use colored::*;
use serde::{Deserialize, Serialize};

/// Severity level classification for security findings.
///
/// Ordered from lowest to highest severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding, no direct security impact.
    Info = 0,

    /// Low severity, minimal security impact.
    Low = 1,

    /// Medium severity, moderate security impact.
    Medium = 2,

    /// High severity, significant security impact.
    High = 3,

    /// Critical severity, severe security impact.
    Critical = 4,
}

impl Severity {
    /// Parses a severity level from a string.
    ///
    /// # Arguments
    ///
    /// * `s` - String representation of severity
    ///
    /// # Returns
    ///
    /// The corresponding `Severity` variant, defaulting to `Info` for unknown values.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Returns a colored label for terminal output.
    pub fn colored_label(&self) -> ColoredString {
        match self {
            Severity::Critical => "CRITICAL".white().on_red().bold(),
            Severity::High => "HIGH".black().on_yellow().bold(),
            Severity::Medium => "MEDIUM".white().on_bright_blue().bold(),
            Severity::Low => "LOW".black().on_white().bold(),
            Severity::Info => "INFO".black().on_bright_white(),
        }
    }

    /// Returns a text indicator for the severity.
    pub fn indicator(&self) -> &'static str {
        match self {
            Severity::Critical => "[!!]",
            Severity::High => "[!]",
            Severity::Medium => "[~]",
            Severity::Low => "[-]",
            Severity::Info => "[i]",
        }
    }

    /// Returns a Markdown badge for the severity.
    pub fn markdown_badge(&self) -> &'static str {
        match self {
            Severity::Critical => {
                "![Critical](https://img.shields.io/badge/severity-CRITICAL-red)"
            }
            Severity::High => "![High](https://img.shields.io/badge/severity-HIGH-orange)",
            Severity::Medium => "![Medium](https://img.shields.io/badge/severity-MEDIUM-yellow)",
            Severity::Low => "![Low](https://img.shields.io/badge/severity-LOW-blue)",
            Severity::Info => "![Info](https://img.shields.io/badge/severity-INFO-lightgrey)",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

/// Represents a security finding from static analysis.
///
/// Contains all information needed to understand, locate, and remediate
/// a detected vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding instance.
    pub id: String,

    /// ID of the detector that produced this finding (e.g., "V001").
    pub detector_id: String,

    /// Short, descriptive title of the finding.
    pub title: String,

    /// Detailed description of the vulnerability.
    pub description: String,

    /// Severity classification.
    pub severity: Severity,

    /// Path to the file containing the vulnerability.
    pub file_path: String,

    /// Line number where the vulnerability was detected.
    pub line: usize,

    /// Code location identifier (e.g., "StructName::field").
    pub location: String,

    /// Optional code snippet showing the vulnerable pattern.
    pub code_snippet: Option<String>,

    /// Remediation guidance for fixing the vulnerability.
    pub remediation: String,

    /// CWE (Common Weakness Enumeration) identifier if applicable.
    pub cwe: Option<String>,
}

impl Finding {
    /// Prints the finding to terminal with color formatting.
    ///
    /// # Arguments
    ///
    /// * `index` - The finding number for display.
    pub fn print_terminal(&self, index: usize) {
        println!();
        println!(
            "{} {} [{}] {}",
            format!("#{}", index).cyan().bold(),
            self.severity.colored_label(),
            self.detector_id.yellow(),
            self.title.white().bold()
        );

        println!(
            "   {} {}:{}",
            "Location:".dimmed(),
            self.file_path.blue(),
            self.line.to_string().cyan()
        );

        for line in self.description.lines() {
            println!("   {}", line.dimmed());
        }

        if let Some(ref snippet) = self.code_snippet {
            println!("\n   {}", "Code:".yellow());
            for line in snippet.lines() {
                println!("   {}", line.bright_white());
            }
        }

        if let Some(ref cwe) = self.cwe {
            println!("   {} {}", "Reference:".dimmed(), cwe.blue());
        }

        println!("\n   {}", "Remediation:".green());
        for line in self.remediation.lines().take(3) {
            println!("   {}", line.green().dimmed());
        }

        println!("{}", "-".repeat(60).dimmed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("critical"), Severity::Critical);
        assert_eq!(Severity::from_str("HIGH"), Severity::High);
        assert_eq!(Severity::from_str("unknown"), Severity::Info);
    }
}
