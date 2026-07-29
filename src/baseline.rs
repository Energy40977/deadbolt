use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Finding, Severity};

pub const FILE_NAME: &str = ".deadbolt-baseline.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub tool_version: String,
    #[serde(default)]
    pub fingerprints: BTreeSet<String>,
    /// Human-readable mirror of `fingerprints`, for review in a pull request.
    #[serde(default)]
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub fingerprint: String,
    pub rule: String,
    pub severity: Severity,
    pub file: String,
    pub title: String,
}

impl Baseline {
    pub fn path(root: &Path) -> PathBuf {
        root.join(FILE_NAME)
    }

    pub fn load(root: &Path) -> Option<Self> {
        let path = Self::path(root);
        let body = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&body).ok()
    }

    pub fn from_findings(findings: &[Finding], generated_at: &str) -> Self {
        let mut entries: Vec<Entry> = findings
            .iter()
            .map(|finding| Entry {
                fingerprint: finding.fingerprint(),
                rule: finding.rule.clone(),
                severity: finding.severity,
                file: finding
                    .evidence
                    .first()
                    .map(|evidence| evidence.file.clone())
                    .unwrap_or_default(),
                title: finding.title.clone(),
            })
            .collect();
        entries.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then(a.file.cmp(&b.file))
                .then(a.rule.cmp(&b.rule))
        });
        entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);

        Self {
            note: "deadbolt baseline — accepted existing findings. \
New findings still block. This file is expected to SHRINK, not grow."
                .to_string(),
            generated_at: generated_at.to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprints: entries
                .iter()
                .map(|entry| entry.fingerprint.clone())
                .collect(),
            entries,
        }
    }

    pub fn write(&self, root: &Path) -> Result<PathBuf> {
        let path = Self::path(root);
        let body = serde_json::to_string_pretty(self).context("Baseline Serialisation Error")?;
        std::fs::write(&path, body)
            .with_context(|| format!("Could Not Write Baseline: {}", path.display()))?;
        Ok(path)
    }

    pub fn contains(&self, finding: &Finding) -> bool {
        self.fingerprints.contains(&finding.fingerprint())
    }

    /// Baseline entries no longer produced: the code was fixed, so the entry
    /// should be dropped. Surfacing these keeps the file shrinking.
    pub fn stale(&self, findings: &[Finding]) -> Vec<&Entry> {
        let current: BTreeSet<String> = findings
            .iter()
            .map(|finding| finding.fingerprint())
            .collect();
        self.entries
            .iter()
            .filter(|entry| !current.contains(&entry.fingerprint))
            .collect()
    }
}

pub struct Filtered {
    pub findings: Vec<Finding>,
    pub suppressed: usize,
    pub stale: usize,
}

/// Splits findings into "new" (returned) and "already accepted" (counted).
pub fn apply(findings: Vec<Finding>, baseline: Option<&Baseline>) -> Filtered {
    let baseline = match baseline {
        Some(baseline) => baseline,
        None => {
            return Filtered {
                findings,
                suppressed: 0,
                stale: 0,
            }
        }
    };

    let stale = baseline.stale(&findings).len();
    let total = findings.len();
    let kept: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| !baseline.contains(finding))
        .collect();

    Filtered {
        suppressed: total - kept.len(),
        findings: kept,
        stale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Evidence, Finding};

    fn finding(file: &str, line: u32, snippet: &str) -> Finding {
        Finding::builder("DB-INJ-001", Category::Injection, Severity::Critical)
            .title("SQL Query Built By Pasting In User Input")
            .evidence(Evidence::new(file, Some(line), snippet))
            .build()
    }

    #[test]
    fn same_snippet_at_a_different_line_keeps_its_identity() {
        let before = finding("a.py", 10, "db.execute(f\"SELECT {x}\")");
        let after = finding("a.py", 42, "db.execute(f\"SELECT {x}\")");
        assert_eq!(before.fingerprint(), after.fingerprint());
    }

    #[test]
    fn a_second_distinct_occurrence_is_not_absorbed() {
        let first = finding("a.py", 10, "db.execute(f\"SELECT {x}\")");
        let second = finding("a.py", 20, "db.execute(f\"UPDATE {y}\")");
        assert_ne!(first.fingerprint(), second.fingerprint());

        let accepted = Baseline::from_findings(std::slice::from_ref(&first), "now");
        let filtered = apply(vec![first, second.clone()], Some(&accepted));
        assert_eq!(filtered.suppressed, 1);
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].fingerprint(), second.fingerprint());
    }

    #[test]
    fn whitespace_changes_do_not_change_identity() {
        let tight = finding("a.py", 1, "db.execute(f\"SELECT {x}\")");
        let loose = finding("a.py", 1, "db.execute(  f\"SELECT {x}\"  )");
        assert_eq!(tight.fingerprint(), loose.fingerprint());
    }

    #[test]
    fn stale_entries_are_reported() {
        let gone = finding("a.py", 1, "db.execute(f\"OLD {x}\")");
        let accepted = Baseline::from_findings(std::slice::from_ref(&gone), "now");
        let current = vec![finding("a.py", 1, "db.execute(f\"NEW {x}\")")];
        assert_eq!(accepted.stale(&current).len(), 1);
    }

    #[test]
    fn no_baseline_passes_everything_through() {
        let findings = vec![finding("a.py", 1, "x")];
        let filtered = apply(findings, None);
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.suppressed, 0);
    }
}
