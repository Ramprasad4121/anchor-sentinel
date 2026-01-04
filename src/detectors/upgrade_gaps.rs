//! # V017 - Cross-Program Upgradeability Gaps Detector
//!
//! Detects upgrades without version checks causing silent reverts.

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};

pub struct UpgradeGapsDetector;

impl UpgradeGapsDetector {
    pub fn new() -> Self { Self }
}

impl VulnerabilityDetector for UpgradeGapsDetector {
    fn id(&self) -> &'static str { "V017" }
    fn name(&self) -> &'static str { "Cross-Program Upgradeability Gaps" }
    fn description(&self) -> &'static str {
        "Detects upgradeable program invocations without version validation."
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn cwe(&self) -> Option<&'static str> { Some("CWE-440") }
    fn remediation(&self) -> &'static str {
        "Check program version before CPI: require!(program.version == EXPECTED_VERSION)"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;

        for (line_num, line) in source.lines().enumerate() {
            if line.contains("upgradeable_loader") && !source.contains("version") {
                findings.push(Finding {
                    id: format!("V017-{}", line_num + 1),
                    detector_id: self.id().to_string(),
                    title: "Upgradeable program without version check".to_string(),
                    description: "CPI to upgradeable program without version validation.".to_string(),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: line_num + 1,
                    location: format!("{}:{}", context.file_path, line_num + 1),
                    code_snippet: Some(line.trim().to_string()),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.55,
                });
            }
        }
        findings
    }
}

impl Default for UpgradeGapsDetector {
    fn default() -> Self { Self::new() }
}
