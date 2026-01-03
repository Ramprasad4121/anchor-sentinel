//! # Anchor-Sentinel CLI Entry Point
//!
//! @title Anchor-Sentinel CLI
//! @author Ramprasad
//!
//! This module provides the main entry point for the Anchor-Sentinel
//! command-line security scanner.

use anchor_sentinel::{Cli, DetectorRegistry, Report};
use anchor_sentinel::report::Finding;
use anyhow::Result;
use clap::Parser;
use colored::*;
use std::path::PathBuf;

/// ASCII art banner displayed at startup.
const BANNER: &str = r#"
    _                _                   ____             _   _            _ 
   / \   _ __   ___| |__   ___  _ __   / ___|  ___ _ __ | |_(_)_ __   ___| |
  / _ \ | '_ \ / __| '_ \ / _ \| '__| | \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 / ___ \| | | | (__| | | | (_) | |     ___) |  __/ | | | |_| | | | |  __/ |
/_/   \_\_| |_|\___|_| |_|\___/|_|    |____/ \___|_| |_|\__|_|_| |_|\___|_|
                                                                            
              Solana Anchor Smart Contract Security Scanner
"#;

/// Application entry point.
///
/// Initializes the logging system, displays the banner, parses command-line
/// arguments, and dispatches to the appropriate command handler.
///
/// # Returns
///
/// Returns `Ok(())` on successful execution, or an error if any operation fails.
fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("{}", BANNER.cyan().bold());

    let cli = Cli::parse();

    match cli.command {
        anchor_sentinel::cli::Commands::Scan {
            path,
            recursive,
            format,
            generate_poc,
            output,
            severity,
            exclude,
            only,
        } => {
            run_scan(path, recursive, format, generate_poc, output, severity, exclude, only)?;
        }
        anchor_sentinel::cli::Commands::List => {
            list_detectors();
        }
        anchor_sentinel::cli::Commands::Version => {
            println!(
                "{} {}",
                "Anchor-Sentinel version:".green(),
                env!("CARGO_PKG_VERSION").yellow()
            );
        }
        anchor_sentinel::cli::Commands::Diff { old_path, new_path } => {
            run_diff(old_path, new_path)?;
        }
        anchor_sentinel::cli::Commands::Init => {
            run_init()?;
        }
    }

    Ok(())
}

fn run_init() -> Result<()> {
    let workflow_dir = PathBuf::from(".github/workflows");
    let workflow_path = workflow_dir.join("sentinel.yml");

    if workflow_path.exists() {
        println!("{}", "[!] Workflow file already exists: .github/workflows/sentinel.yml".yellow());
        return Ok(());
    }

    std::fs::create_dir_all(&workflow_dir)?;

    let workflow_content = r#"name: Anchor-Sentinel Security Scan

on:
  pull_request:
    branches: [ "master", "main" ]
  push:
    branches: [ "master", "main" ]

env:
  CARGO_TERM_COLOR: always

jobs:
  security_scan:
    name: Anchor-Sentinel Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Install Anchor-Sentinel
        run: cargo install --git https://github.com/ramprasadgoud/anchor-sentinel --branch main 

      - name: Run Security Scan
        run: anchor-sentinel scan . --format github
"#;

    std::fs::write(&workflow_path, workflow_content)?;

    println!(
        "{} {}",
        "[+] Generated GitHub Actions workflow:".green().bold(),
        workflow_path.display().to_string().yellow()
    );
    println!("    Triggers on Push/PR to main/master branches.");
    println!("    Runs 'anchor-sentinel scan' and helps block vulnerabilities.");

    Ok(())
}

/// Executes the security scan operation.
///
/// This function orchestrates the complete scanning workflow:
/// 1. Collects Rust source files from the specified path
/// 2. Parses each file into an analysis context
/// 3. Runs all registered vulnerability detectors
/// 4. Generates reports in the specified format
/// 5. Optionally generates proof-of-concept exploit tests
///
/// # Arguments
///
/// * `path` - The file or directory path to scan
/// * `recursive` - Whether to scan directories recursively
/// * `format` - Output format: "terminal", "json", or "markdown"
/// * `generate_poc` - Whether to generate TypeScript POC exploit tests
/// * `output` - Optional output directory for reports and POC files
/// * `min_severity` - Optional minimum severity level to include in results
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if scanning fails.
fn run_scan(
    path: PathBuf,
    recursive: bool,
    format: String,
    generate_poc: bool,
    output: Option<PathBuf>,
    min_severity: Option<String>,
    exclude: Vec<String>,
    only: Vec<String>,
) -> Result<()> {
    use anchor_sentinel::parser::parse_anchor_files;
    use anchor_sentinel::poc_generator::PocGenerator;


    println!(
        "{} {}",
        "[*] Scanning:".green().bold(),
        path.display().to_string().yellow()
    );

    let all_findings = perform_scan(&path, recursive)?;

    if all_findings.is_empty() {
        // No findings detected
    }

    let mut findings = if let Some(ref min_sev) = min_severity {
        let min = anchor_sentinel::Severity::from_str(min_sev);
        all_findings
            .into_iter()
            .filter(|f| f.severity >= min)
            .collect()
    } else {
        all_findings
    };

    // Filter out excluded detectors
    if !exclude.is_empty() {
        let exclude_upper: Vec<String> = exclude.iter().map(|s| s.to_uppercase()).collect();
        findings = findings
            .into_iter()
            .filter(|f| !exclude_upper.contains(&f.detector_id.to_uppercase()))
            .collect();
    }

    // Include only specific detectors (if --only is specified)
    if !only.is_empty() {
        let only_upper: Vec<String> = only.iter().map(|s| s.to_uppercase()).collect();
        findings = findings
            .into_iter()
            .filter(|f| only_upper.contains(&f.detector_id.to_uppercase()))
            .collect();
    }

    let report = Report::new(findings, path.clone());

    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "markdown" => {
            let md = report.to_markdown();
            if let Some(ref out_path) = output {
                let report_path = out_path.join("security_report.md");
                std::fs::write(&report_path, &md)?;
                println!(
                    "{} {}",
                    "[+] Report saved to:".green(),
                    report_path.display().to_string().yellow()
                );
            } else {
                println!("{}", md);
            }
        }
        "github" => {
            // Print GitHub Actions annotations
            // Format: ::error file={name},line={line},title={title}::{message}
            for finding in &report.findings {
                let level = match finding.severity {
                    anchor_sentinel::report::Severity::Critical | anchor_sentinel::report::Severity::High => "error",
                    anchor_sentinel::report::Severity::Medium => "warning",
                    _ => "notice",
                };
                
                println!(
                    "::{} file={},line={},title={}::{}",
                    level,
                    finding.file_path,
                    finding.line,
                    finding.title,
                    finding.description
                );
            }
        }
        _ => {
            report.print_terminal();
        }
    }

    if generate_poc && !report.findings.is_empty() {
        let poc_output = output.unwrap_or_else(|| PathBuf::from("./exploits"));
        std::fs::create_dir_all(&poc_output)?;

        let generator = PocGenerator::new();
        let generated_files = generator.generate_all(&report.findings, &poc_output, Some(&path))?;

        println!("\n{}", "[+] Generated POC Exploit Tests:".magenta().bold());
        for file in generated_files {
            println!("    -> {}", file.display().to_string().yellow());
        }
    }

    println!("\n{}", "=".repeat(60).cyan());
    report.print_summary();

    Ok(())
}

/// Collects Rust source files from a directory.
///
/// Traverses the specified directory and collects all `.rs` files,
/// excluding files in the `target` directory.
///
/// # Arguments
///
/// * `dir` - The directory to search
/// * `recursive` - Whether to search subdirectories
///
/// # Returns
///
/// A vector of paths to Rust source files.
/// Performs the actual scanning logic on a directory.
fn perform_scan(path: &PathBuf, recursive: bool) -> Result<Vec<Finding>> {
    use anchor_sentinel::parser::parse_anchor_files;
    use indicatif::{ProgressBar, ProgressStyle};

    let files = if path.is_file() {
        vec![path.clone()]
    } else {
        collect_rust_files(path, recursive)?
    };

    if files.is_empty() {
        return Ok(Vec::new());
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );

    let registry = DetectorRegistry::new();
    let mut all_findings = Vec::new();

    for file_path in &files {
        pb.set_message(format!(
            "Analyzing {}",
            file_path.file_name().unwrap_or_default().to_string_lossy()
        ));

        match parse_anchor_files(file_path) {
            Ok(context) => {
                let findings = registry.run_all(&context);
                all_findings.extend(findings);
            }
            Err(e) => {
                log::warn!("Failed to parse {}: {}", file_path.display(), e);
            }
        }

        pb.inc(1);
    }

    pb.finish_and_clear();
    Ok(all_findings)
}

fn run_diff(old_path: PathBuf, new_path: PathBuf) -> Result<()> {
    println!("{}", "[*] Running Differential Analysis...".blue().bold());

    // Canonicalize paths to ensure consistent diffs
    let old_abs = std::fs::canonicalize(&old_path).unwrap_or(old_path.clone());
    let new_abs = std::fs::canonicalize(&new_path).unwrap_or(new_path.clone());

    println!("{} {}", "[base]".dimmed(), old_abs.display());
    let old_findings = perform_scan(&old_abs, true)?;
    
    println!("{} {}", "[target]".dimmed(), new_abs.display());
    let new_findings = perform_scan(&new_abs, true)?;

    // Compare findings
    // We use a simplified key for comparison: DetectorID + RelativePath + LineNumber
    // Note: LineNumber is fragile but simple for now. 
    // Ideally use surrounding context hash.
    
    let get_key = |f: &Finding, base_path: &PathBuf| -> String {
        let relative = pathdiff::diff_paths(&PathBuf::from(&f.file_path), base_path).unwrap_or(PathBuf::from(&f.file_path));
        format!("{}:{}:{}", f.detector_id, relative.display(), f.line)
    };

    let mut old_map = std::collections::HashMap::new();
    for f in &old_findings {
        old_map.insert(get_key(f, &old_abs), f);
    }

    let mut new_map = std::collections::HashMap::new();
    for f in &new_findings {
        new_map.insert(get_key(f, &new_abs), f);
    }

    let mut new_risks = Vec::new();
    let mut fixed_issues = Vec::new();
    // let mut regressions = Vec::new(); // Wait, regression = new risk? Or reintroduced?
    // Let's stick to New Risk vs Fixed. Regression implies it was fixed then broken again, which requires 3 states.
    // We'll just report New Risks and Fixed Issues.

    for (key, finding) in &new_map {
        if !old_map.contains_key(key) {
            new_risks.push(finding);
        }
    }

    for (key, finding) in &old_map {
        if !new_map.contains_key(key) {
            fixed_issues.push(finding);
        }
    }

    println!("\n{}", "=== Differential Analysis Results ===".white().bold());
    
    if new_risks.is_empty() && fixed_issues.is_empty() {
        println!("{}", "No security changes detected.".green());
        return Ok(());
    }

    if !new_risks.is_empty() {
        println!("\n{}", "[NEW RISKS DETECTED]".red().bold());
        for f in new_risks {
            println!("  [{}] {} ({})", f.detector_id.red(), f.title, f.location);
        }
    }

    if !fixed_issues.is_empty() {
        println!("\n{}", "[ISSUES FIXED]".green().bold());
        for f in fixed_issues {
            println!("  [{}] {} ({})", f.detector_id.green(), f.title, f.location);
        }
    }

    Ok(())
}

fn collect_rust_files(dir: &PathBuf, recursive: bool) -> Result<Vec<PathBuf>> {
    use walkdir::WalkDir;

    let walker = if recursive {
        WalkDir::new(dir)
    } else {
        WalkDir::new(dir).max_depth(1)
    };

    let files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "rs")
                && !e.path().to_string_lossy().contains("target")
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    Ok(files)
}

/// Displays all available vulnerability detectors.
///
/// Prints a formatted list of registered detectors including their
/// IDs, names, severity levels, and descriptions.
fn list_detectors() {
    let registry = DetectorRegistry::new();

    println!("{}", "[*] Available Vulnerability Detectors:".green().bold());
    println!("{}", "-".repeat(60).cyan());

    for detector in registry.detectors() {
        println!(
            "  {} {} [{}]",
            detector.id().cyan().bold(),
            detector.name().white(),
            format!("{:?}", detector.severity()).yellow()
        );
        println!("     {}", detector.description().dimmed());
        println!();
    }
}
