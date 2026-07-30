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
    ///
    /// Scoped to the detectors that actually ran. A narrow pass (`scan` runs no
    /// history, no chains, no dependency research) must not call their entries
    /// stale — following that advice with `--prune` would delete accepted
    /// findings, and the next full `audit` would report them as brand new.
    pub fn stale(&self, findings: &[Finding], assessed: Assessed) -> Vec<&Entry> {
        let current: BTreeSet<String> = findings
            .iter()
            .map(|finding| finding.fingerprint())
            .collect();
        self.entries
            .iter()
            .filter(|entry| assessed.covers(&entry.rule))
            .filter(|entry| !current.contains(&entry.fingerprint))
            .collect()
    }
}

/// Which detectors ran in this pass, so staleness is only claimed for entries
/// something actually looked for.
#[derive(Debug, Clone, Copy)]
pub struct Assessed {
    pub statics: bool,
    pub history: bool,
    pub chains: bool,
    pub dependencies: bool,
    pub ai: bool,
    pub compliance: bool,
}

impl Assessed {
    /// Every detector ran. No real pass can claim this — compliance is evaluated
    /// after the baseline filter — so it exists for tests that check attribution.
    #[cfg(test)]
    pub fn everything() -> Self {
        Self {
            statics: true,
            history: true,
            chains: true,
            dependencies: true,
            ai: true,
            compliance: true,
        }
    }

    /// A rule identifier says which detector produces it: `DB-HIST-*` comes from
    /// the history walk, `AI-*` from a lens, `<pack>:<control>` from compliance.
    pub fn covers(&self, rule: &str) -> bool {
        if rule.starts_with("AI-") {
            return self.ai;
        }
        if rule.starts_with("DB-HIST-") {
            return self.history;
        }
        if rule.starts_with("DB-CHAIN-") {
            return self.chains;
        }
        if rule.starts_with("DB-DEP-") {
            return self.dependencies;
        }
        if rule.starts_with("DB-") {
            return self.statics;
        }
        // Compliance findings are named `<pack>:<control>`.
        if rule.contains(':') {
            return self.compliance;
        }
        // An identifier this build does not recognise: never claim it is stale.
        false
    }
}

pub struct Filtered {
    pub findings: Vec<Finding>,
    pub suppressed: usize,
    pub stale: usize,
}

/// Splits findings into "new" (returned) and "already accepted" (counted).
pub fn apply(findings: Vec<Finding>, baseline: Option<&Baseline>, assessed: Assessed) -> Filtered {
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

    let stale = baseline.stale(&findings, assessed).len();
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
        rule_finding("DB-INJ-001", file, line, snippet)
    }

    fn rule_finding(rule: &str, file: &str, line: u32, snippet: &str) -> Finding {
        Finding::builder(rule, Category::Injection, Severity::Critical)
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
        let filtered = apply(
            vec![first, second.clone()],
            Some(&accepted),
            Assessed::everything(),
        );
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
        assert_eq!(accepted.stale(&current, Assessed::everything()).len(), 1);
    }

    #[test]
    fn no_baseline_passes_everything_through() {
        let findings = vec![finding("a.py", 1, "x")];
        let filtered = apply(findings, None, Assessed::everything());
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.suppressed, 0);
    }

    /// The bug this guards: `scan` runs no history walk, so a `DB-HIST-*` entry it
    /// cannot see looked stale. The advice that followed — `--prune` — would have
    /// deleted an accepted finding, and the next full audit reported it as new.
    #[test]
    fn a_detector_that_did_not_run_never_makes_its_entries_stale() {
        let secret = rule_finding("DB-HIST-001", "src/old.rs", 1, "token = \"abc\"");
        let accepted = Baseline::from_findings(std::slice::from_ref(&secret), "now");

        let scan_only = Assessed {
            statics: true,
            history: false,
            chains: false,
            dependencies: false,
            ai: false,
            compliance: false,
        };
        assert!(accepted.stale(&[], scan_only).is_empty());
        assert_eq!(accepted.stale(&[], Assessed::everything()).len(), 1);
    }

    #[test]
    fn every_producer_is_attributed_to_its_detector() {
        let none = Assessed {
            statics: false,
            history: false,
            chains: false,
            dependencies: false,
            ai: false,
            compliance: false,
        };
        let all = Assessed::everything();
        for rule in [
            "DB-INJ-001",
            "DB-HIST-001",
            "DB-CHAIN-001",
            "DB-DEP-VULN",
            "AI-authz",
            "owasp-asvs:V2.1.1",
        ] {
            assert!(all.covers(rule), "{rule} belongs to no detector");
            assert!(!none.covers(rule), "{rule} claimed by an idle pass");
        }
    }

    #[test]
    fn an_unrecognised_rule_identifier_is_never_pruned() {
        // A baseline written by a newer build must survive an older one.
        assert!(!Assessed::everything().covers("FUTURE_RULE"));
    }
}
