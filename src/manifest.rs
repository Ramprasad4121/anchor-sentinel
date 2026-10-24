//! # V033 - Vulnerable anchor-lang Version
//!
//! @title anchor-lang Version Check
//! @author Ramprasad
//!
//! Reads `Cargo.toml` and `Cargo.lock` and flags `anchor-lang` 1.0.0 and 1.0.1.
//!
//! In those releases `Program<'info, System>` accepted any executable account,
//! because the system program id is also the default pubkey and the generic
//! check treated it as "any program". A caller could pass another program where
//! the system program was expected. Fixed in 1.0.2.
//!
//! Advisory: RUSTSEC-2026-0144 / CVE-2026-45137 / GHSA-c6rc-8jpp-2fgc.
//! <https://rustsec.org/advisories/RUSTSEC-2026-0144>
//!
//! ## Rules
//!
//! - `Cargo.lock` that resolves `anchor-lang` to 1.0.0 or 1.0.1: finding, high confidence.
//! - `Cargo.toml` requirement whose lowest allowed version is 1.0.0 or 1.0.1:
//!   finding, unless a `Cargo.lock` in the same or a parent directory resolves a fixed version.
//! - Anything below 1.0.0 (including 1.0.0 release candidates) or 1.0.2 and up: quiet.

use crate::report::{Finding, Severity};
use std::path::Path;

const DETECTOR_ID: &str = "V033";

/// Parses `major.minor.patch` from the start of a version string.
/// Returns `None` for anything with a pre-release tag, which the advisory does not cover.
fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let v = raw
        .trim()
        .trim_start_matches(['^', '=', '~', '>', '<', ' ']);
    if v.contains('-') {
        return None;
    }
    let mut parts = v.split('.');
    let major = parts.next()?.trim().parse().ok()?;
    let minor = parts.next()?.trim().parse().ok()?;
    let patch = parts.next()?.trim().parse().ok()?;
    Some((major, minor, patch))
}

/// True for the two affected releases.
fn is_affected(v: (u64, u64, u64)) -> bool {
    v == (1, 0, 0) || v == (1, 0, 1)
}

fn make_finding(path: &str, line: usize, text: &str, version: &str, locked: bool) -> Finding {
    let source = text
        .lines()
        .nth(line.saturating_sub(1))
        .map(|s| s.trim().to_string());
    let how = if locked {
        "Cargo.lock resolves anchor-lang to this version"
    } else {
        "Cargo.toml allows this version as its lowest match"
    };
    Finding {
        id: format!("{DETECTOR_ID}-{line}"),
        detector_id: DETECTOR_ID.to_string(),
        title: "anchor-lang 1.0.0 or 1.0.1 accepts a fake System program".to_string(),
        description: format!(
            "{how} ({version}). In anchor-lang 1.0.0 and 1.0.1, `Program<'info, System>` accepts \
             any executable account, so a caller can pass another program where the system \
             program is expected. Any CPI or payment that trusts that account is then wrong. \
             Fixed in 1.0.2 (RUSTSEC-2026-0144, CVE-2026-45137)."
        ),
        severity: Severity::High,
        file_path: path.to_string(),
        line,
        location: format!("{path}:{line}"),
        code_snippet: source,
        remediation:
            "Upgrade anchor-lang to 1.0.2 or later and run `cargo update -p anchor-lang`. \
                      Until then, compare the account key to `system_program::ID` by hand."
                .to_string(),
        cwe: Some("CWE-1395".to_string()),
        confidence: if locked { 0.95 } else { 0.8 },
    }
}

/// Finds the `anchor-lang` entry in a `Cargo.lock` and returns (line, version).
fn lock_version(text: &str) -> Option<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == "name = \"anchor-lang\"" {
            let next = lines.get(i + 1)?.trim();
            let v = next.strip_prefix("version = \"")?.strip_suffix('"')?;
            return Some((i + 2, v.to_string()));
        }
    }
    None
}

/// Checks a `Cargo.lock` file's text.
pub fn check_lock(path: &str, text: &str) -> Vec<Finding> {
    match lock_version(text) {
        Some((line, v)) if parse_version(&v).is_some_and(is_affected) => {
            vec![make_finding(path, line, text, &v, true)]
        }
        _ => Vec::new(),
    }
}

/// Pulls the version out of a quoted `version = "x"` or inline `"x"` value.
fn quoted_version(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = start + s[start..].find('"')?;
    Some(s[start..end].to_string())
}

/// Checks a `Cargo.toml` file's text. `locked_fixed` is true when a lock file
/// next to or above it resolves `anchor-lang` to a version that is not affected.
pub fn check_manifest(path: &str, text: &str, locked_fixed: bool) -> Vec<Finding> {
    if locked_fixed {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut in_anchor_table = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_anchor_table = line
                .trim_matches(|c| c == '[' || c == ']')
                .ends_with(".anchor-lang");
            continue;
        }
        let version = if in_anchor_table {
            line.strip_prefix("version")
                .filter(|r| r.trim_start().starts_with('='))
                .and_then(quoted_version)
        } else if let Some(rest) = line.strip_prefix("anchor-lang") {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                let v = v.trim_start();
                if v.starts_with('"') {
                    quoted_version(v)
                } else if v.starts_with('{') {
                    v.find("version")
                        .map(|p| &v[p + 7..])
                        .filter(|r| r.trim_start().starts_with('='))
                        .and_then(quoted_version)
                } else {
                    None
                }
            } else if let Some(v) = rest.strip_prefix(".version") {
                v.trim_start().strip_prefix('=').and_then(quoted_version)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(v) = version {
            if parse_version(&v).is_some_and(is_affected) {
                out.push(make_finding(path, i + 1, text, &v, false));
            }
        }
    }
    out
}

/// Scans a directory for `Cargo.toml` and `Cargo.lock` files and returns findings.
pub fn scan_dir(root: &Path) -> Vec<Finding> {
    use walkdir::WalkDir;
    let mut out = Vec::new();
    let entries: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            e.file_name() != "target" && e.file_name() != ".git" && e.file_name() != "node_modules"
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    for e in &entries {
        let name = e.file_name().to_string_lossy();
        let Ok(text) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        let p = e.path().to_string_lossy().to_string();
        if name == "Cargo.lock" {
            out.extend(check_lock(&p, &text));
        } else if name == "Cargo.toml" {
            let fixed = e
                .path()
                .ancestors()
                .skip(1)
                .take_while(|a| a.starts_with(root))
                .map(|a| a.join("Cargo.lock"))
                .find(|l| l.is_file())
                .and_then(|l| std::fs::read_to_string(l).ok())
                .and_then(|t| lock_version(&t))
                .and_then(|(_, v)| parse_version(&v))
                .is_some_and(|v| !is_affected(v));
            out.extend(check_manifest(&p, &text, fixed));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_plain_and_caret_and_exact_requirements() {
        for v in ["1.0.0", "^1.0.1", "=1.0.1"] {
            let t = format!("[dependencies]\nanchor-lang = \"{v}\"\n");
            assert_eq!(check_manifest("Cargo.toml", &t, false).len(), 1, "{v}");
        }
    }

    #[test]
    fn flags_inline_table_dotted_and_table_forms() {
        let a = "[dependencies]\nanchor-lang = { version = \"1.0.1\", features = [\"init-if-needed\"] }\n";
        let b = "[dependencies]\nanchor-lang.version = \"1.0.0\"\n";
        let c = "[dependencies.anchor-lang]\nversion = \"1.0.1\"\nfeatures = [\"x\"]\n";
        let d = "[workspace.dependencies]\nanchor-lang = \"1.0.0\"\n";
        for t in [a, b, c, d] {
            assert_eq!(check_manifest("Cargo.toml", t, false).len(), 1, "{t}");
        }
    }

    #[test]
    fn quiet_for_fixed_old_and_prerelease_versions() {
        for v in ["1.0.2", "1.2.1", "0.31.1", "0.30.0", "1.0.0-rc.5", "2.0.0"] {
            let t = format!("[dependencies]\nanchor-lang = \"{v}\"\n");
            assert!(check_manifest("Cargo.toml", &t, false).is_empty(), "{v}");
        }
    }

    #[test]
    fn quiet_for_other_crates_and_comments() {
        let t = "[dependencies]\nanchor-spl = \"1.0.1\"\n# anchor-lang = \"1.0.1\"\n";
        assert!(check_manifest("Cargo.toml", t, false).is_empty());
    }

    #[test]
    fn lock_file_decides() {
        let bad = "[[package]]\nname = \"anchor-lang\"\nversion = \"1.0.1\"\n";
        let good = "[[package]]\nname = \"anchor-lang\"\nversion = \"1.0.2\"\n";
        let f = check_lock("Cargo.lock", bad);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 3);
        assert!(check_lock("Cargo.lock", good).is_empty());
        let t = "[dependencies]\nanchor-lang = \"1.0.1\"\n";
        assert!(check_manifest("Cargo.toml", t, true).is_empty());
    }

    #[test]
    fn scan_dir_uses_the_lock_above_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let prog = dir.path().join("programs/vault");
        std::fs::create_dir_all(&prog).unwrap();
        std::fs::write(
            prog.join("Cargo.toml"),
            "[dependencies]\nanchor-lang = \"1.0.1\"\n",
        )
        .unwrap();
        assert_eq!(scan_dir(dir.path()).len(), 1);
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "[[package]]\nname = \"anchor-lang\"\nversion = \"1.0.3\"\n",
        )
        .unwrap();
        assert!(scan_dir(dir.path()).is_empty());
    }
}
