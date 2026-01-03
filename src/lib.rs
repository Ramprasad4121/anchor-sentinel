//! # Anchor-Sentinel Library
//!
//! @title Anchor-Sentinel - Static Analysis Security Scanner
//! @author Ramprasad
//!
//! A comprehensive static analysis library for Solana Anchor smart contracts.
//!
//! This library provides the core functionality for detecting security vulnerabilities
//! in Anchor programs and generating proof-of-concept exploit tests.
//!
//! ## Modules
//!
//! - [`cli`] - Command-line interface definitions and argument parsing
//! - [`parser`] - AST parsing utilities for Rust/Anchor source code
//! - [`detectors`] - Vulnerability detection implementations
//! - [`report`] - Report generation in multiple formats
//! - [`poc_generator`] - TypeScript proof-of-concept test generation
//!
//! ## Example
//!
//! ```rust,ignore
//! use anchor_sentinel::{DetectorRegistry, Report};
//! use anchor_sentinel::parser::parse_anchor_files;
//!
//! let context = parse_anchor_files(Path::new("./program.rs"))?;
//! let registry = DetectorRegistry::new();
//! let findings = registry.run_all(&context);
//! let report = Report::new(findings, path);
//! ```

pub mod cli;
pub mod detectors;
pub mod parser;
pub mod poc_generator;
pub mod report;

pub use cli::Cli;
pub use detectors::DetectorRegistry;
pub use parser::AnalysisContext;
pub use report::{Finding, Report, Severity};
