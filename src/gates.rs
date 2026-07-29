use serde::Deserialize;

use crate::model::{Confidence, Finding, Severity};

/// `any` means every severity blocks; `never` means nothing does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threshold {
    Any,
    At(Severity),
    Never,
}

impl Threshold {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "any" | "all" => Threshold::Any,
            "never" | "none" | "off" => Threshold::Never,
            "critical" => Threshold::At(Severity::Critical),
            "high" => Threshold::At(Severity::High),
            "medium" => Threshold::At(Severity::Medium),
            "low" => Threshold::At(Severity::Low),
            _ => Threshold::At(Severity::High),
        }
    }

    /// Used by `Policy::blocking`; kept separate so it can be unit-tested.
    pub(crate) fn blocks(self, severity: Severity) -> bool {
        match self {
            Threshold::Any => true,
            Threshold::Never => false,
            Threshold::At(limit) => severity <= limit,
        }
    }

    /// How far down the severity scale this threshold blocks — **larger is
    /// stricter**. Note that `Severity` orders the other way round (Critical =
    /// 0), so comparing severities directly would invert the meaning: a
    /// `medium` gate blocks *more* than a `high` gate.
    fn strictness(self) -> i32 {
        match self {
            Threshold::Never => 0,
            Threshold::At(severity) => severity as i32 + 1,
            Threshold::Any => 100,
        }
    }

    fn stricter(self, other: Self) -> Self {
        if other.strictness() > self.strictness() {
            other
        } else {
            self
        }
    }

    pub fn label(self) -> String {
        match self {
            Threshold::Any => "any".to_string(),
            Threshold::Never => "never".to_string(),
            Threshold::At(severity) => severity.label().to_ascii_lowercase(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathGate {
    /// Glob matched against the finding's file path.
    pub pattern: String,
    pub fail_on: String,
}

#[derive(Debug, Default)]
pub struct Policy {
    pub global: Threshold,
    /// Evaluated in order; every match contributes, strictest wins.
    pub paths: Vec<(String, Threshold)>,
    pub categories: Vec<(String, Threshold)>,
}

impl Default for Threshold {
    fn default() -> Self {
        Threshold::At(Severity::High)
    }
}

impl Policy {
    pub fn new(
        global: Threshold,
        path_gates: &[PathGate],
        category_gates: &std::collections::BTreeMap<String, String>,
    ) -> Self {
        Self {
            global,
            paths: path_gates
                .iter()
                .map(|gate| (gate.pattern.clone(), Threshold::parse(&gate.fail_on)))
                .collect(),
            categories: category_gates
                .iter()
                .map(|(category, level)| (category.to_ascii_lowercase(), Threshold::parse(level)))
                .collect(),
        }
    }

    /// Effective threshold for one finding.
    pub fn threshold_for(&self, finding: &Finding) -> Threshold {
        let mut effective = self.global;

        let category = finding.category.slug();
        for (candidate, threshold) in &self.categories {
            if candidate == category {
                effective = effective.stricter(*threshold);
            }
        }

        if let Some(evidence) = finding.evidence.first() {
            for (pattern, threshold) in &self.paths {
                if crate::glob_match(pattern, &evidence.file) {
                    effective = effective.stricter(*threshold);
                }
            }
        }

        effective
    }

    /// Findings that block, with the reason each one blocked.
    pub fn blocking<'a>(&self, findings: &'a [Finding]) -> Vec<(&'a Finding, Threshold)> {
        findings
            .iter()
            .filter_map(|finding| {
                if finding.confidence == Confidence::Possible {
                    return None;
                }
                let threshold = self.threshold_for(finding);
                threshold
                    .blocks(finding.severity)
                    .then_some((finding, threshold))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Evidence};
    use std::collections::BTreeMap;

    fn finding(category: Category, severity: Severity, file: &str) -> Finding {
        Finding::builder("R", category, severity)
            .title("t")
            .evidence(Evidence::new(file, Some(1), "x"))
            .build()
    }

    #[test]
    fn global_threshold_alone() {
        let policy = Policy::new(Threshold::At(Severity::High), &[], &BTreeMap::new());
        assert_eq!(
            policy
                .blocking(&[finding(Category::Secrets, Severity::High, "a.py")])
                .len(),
            1
        );
        assert_eq!(
            policy
                .blocking(&[finding(Category::Secrets, Severity::Medium, "a.py")])
                .len(),
            0
        );
    }

    #[test]
    fn category_gate_can_be_stricter_than_global() {
        let mut categories = BTreeMap::new();
        categories.insert("secrets".to_string(), "any".to_string());
        let policy = Policy::new(Threshold::At(Severity::High), &[], &categories);

        assert_eq!(
            policy
                .blocking(&[finding(Category::Secrets, Severity::Low, "a.py")])
                .len(),
            1
        );
        assert_eq!(
            policy
                .blocking(&[finding(Category::Frontend, Severity::Low, "a.py")])
                .len(),
            0
        );
    }

    #[test]
    fn path_gate_tightens_critical_directories() {
        let gates = vec![PathGate {
            pattern: "**/auth/**".to_string(),
            fail_on: "medium".to_string(),
        }];
        let policy = Policy::new(Threshold::At(Severity::High), &gates, &BTreeMap::new());

        assert_eq!(
            policy
                .blocking(&[finding(
                    Category::Frontend,
                    Severity::Medium,
                    "app/auth/x.py"
                )])
                .len(),
            1
        );
        assert_eq!(
            policy
                .blocking(&[finding(Category::Frontend, Severity::Medium, "app/ui/x.py")])
                .len(),
            0
        );
    }

    #[test]
    fn strictest_input_wins_regardless_of_order() {
        let gates = vec![PathGate {
            pattern: "**/generated/**".to_string(),
            fail_on: "critical".to_string(),
        }];
        let mut categories = BTreeMap::new();
        categories.insert("secrets".to_string(), "any".to_string());
        let policy = Policy::new(Threshold::At(Severity::High), &gates, &categories);

        let findings = vec![finding(
            Category::Secrets,
            Severity::Low,
            "src/generated/x.py",
        )];
        let blocked = policy.blocking(&findings);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].1, Threshold::Any);
    }

    #[test]
    fn a_lower_severity_gate_is_the_stricter_one() {
        let gates = vec![PathGate {
            pattern: "**/auth/**".to_string(),
            fail_on: "medium".to_string(),
        }];
        let policy = Policy::new(Threshold::At(Severity::High), &gates, &BTreeMap::new());
        let findings = vec![finding(
            Category::Frontend,
            Severity::Medium,
            "app/auth/x.py",
        )];
        let blocked = policy.blocking(&findings);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].1, Threshold::At(Severity::Medium));
    }

    #[test]
    fn never_gate_lets_everything_through() {
        let policy = Policy::new(Threshold::Never, &[], &BTreeMap::new());
        assert!(policy
            .blocking(&[finding(Category::Secrets, Severity::Critical, "a.py")])
            .is_empty());
    }

    #[test]
    fn unverified_findings_never_block() {
        let policy = Policy::new(Threshold::Any, &[], &BTreeMap::new());
        let unverified = Finding::builder("R", Category::Secrets, Severity::Critical)
            .title("t")
            .confidence(Confidence::Possible)
            .evidence(Evidence::new("a.py", Some(1), "x"))
            .build();
        assert!(policy.blocking(&[unverified]).is_empty());
    }
}

#[cfg(test)]
mod glob {
    #[test]
    fn patterns_used_by_path_gates_match_as_expected() {
        for (pattern, path) in [
            ("**/auth/**", "app/auth/x.py"),
            ("**/auth/**", "auth/x.py"),
            ("**/payment*/**", "app/payments/x.py"),
            ("generated/**", "generated/a.py"),
        ] {
            assert!(crate::glob_match(pattern, path), "{pattern} ⊃ {path}");
        }
        for (pattern, path) in [
            ("**/auth/**", "app/ui/x.py"),
            ("generated/**", "src/generated/a.py"),
        ] {
            assert!(!crate::glob_match(pattern, path), "{pattern} ⊅ {path}");
        }
    }
}
