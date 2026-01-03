//! # CLI Module
//!
//! @title Command Line Interface
//! @author Ramprasad
//!
//! This module defines the command-line interface for Anchor-Sentinel using
//! the `clap` derive macros for declarative argument parsing.
//!
//! ## Commands
//!
//! - `scan` - Analyze Anchor smart contracts for vulnerabilities
//! - `list` - Display available vulnerability detectors
//! - `version` - Show version information

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Anchor-Sentinel command-line interface.
///
/// A static analysis security scanner for Solana Anchor smart contracts.
/// Detects common vulnerability patterns and generates proof-of-concept
/// exploit tests.
#[derive(Parser, Debug)]
#[command(name = "anchor-sentinel")]
#[command(author = "RamprasadGoud")]
#[command(version)]
#[command(about = "Static analysis security scanner for Solana Anchor smart contracts")]
#[command(long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for the Anchor-Sentinel CLI.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan Anchor smart contracts for security vulnerabilities.
    ///
    /// Analyzes Rust source files for common security issues including
    /// missing signer checks, owner validation, integer overflow, and more.
    Scan {
        /// Path to the file or directory to scan.
        ///
        /// If a directory is specified, all `.rs` files within it will be analyzed.
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Scan directories recursively.
        ///
        /// When enabled, subdirectories will also be searched for Rust source files.
        #[arg(short, long, default_value_t = true)]
        recursive: bool,

        /// Output format for the security report.
        ///
        /// Supported formats:
        /// - `terminal`: Colorized console output (default)
        /// - `json`: Machine-readable JSON format
        /// - `markdown`: Human-readable Markdown report
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Generate TypeScript proof-of-concept exploit tests.
        ///
        /// Creates test files that demonstrate how detected vulnerabilities
        /// could be exploited.
        #[arg(short, long)]
        generate_poc: bool,

        /// Output directory for reports and POC files.
        ///
        /// If not specified, reports are printed to stdout and POC files
        /// are written to `./exploits/`.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum severity level to include in results.
        ///
        /// Valid values: critical, high, medium, low, info
        #[arg(short, long)]
        severity: Option<String>,

        /// Exclude specific detectors from the scan.
        ///
        /// Comma-separated list of detector IDs to skip.
        /// Example: --exclude V004,V005
        #[arg(short = 'x', long, value_delimiter = ',')]
        exclude: Vec<String>,

        /// Include only specific detectors in the scan.
        ///
        /// Comma-separated list of detector IDs to run.
        /// Example: --only V001,V002,V003
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },

    /// Compare security findings between two program versions.
    ///
    /// Runs a full scan on both directories and reports:
    /// - New Vulnerabilities (Regression)
    /// - Fixed Vulnerabilities
    Diff {
        /// Path to the old version (base).
        #[arg(value_name = "OLD_PATH")]
        old_path: PathBuf,

        /// Path to the new version (target).
        #[arg(value_name = "NEW_PATH")]
        new_path: PathBuf,
    },

    /// Initialize Anchor-Sentinel configuration.
    ///
    /// Generates a GitHub Actions workflow file for CI/CD integration.
    Init,

    /// List all available vulnerability detectors.
    ///
    /// Displays the ID, name, severity, and description of each
    /// registered vulnerability detector.
    List,

    /// Print version information.
    Version,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Verify that the CLI definition is valid.
    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
