use std::collections::BTreeMap;

use chrono::NaiveDate;
use regex::Regex;

use crate::discover::{Inventory, SourceFile};
use crate::model::{Category, Confidence, Evidence, Finding, Origin, Severity};

/// Recognised on any comment syntax, because the marker is distinctive enough.
const MARKER: &str = "deadbolt-ignore";

#[derive(Debug, Clone)]
pub struct Directive {
    pub rules: Vec<String>,
    pub until: Option<NaiveDate>,
    pub reason: String,
    pub line: u32,
    pub raw: String,
}

impl Directive {
    fn covers(&self, rule: &str) -> bool {
        self.rules
            .iter()
            .any(|candidate| candidate == "*" || candidate.eq_ignore_ascii_case(rule))
    }

    fn expired(&self, today: NaiveDate) -> bool {
        match self.until {
            Some(until) => until < today,
            None => true,
        }
    }
}

/// Directives found in one file, indexed by the line they apply to.
#[derive(Debug, Default, Clone)]
pub struct FileExceptions {
    by_line: BTreeMap<u32, Vec<Directive>>,
}

impl FileExceptions {
    /// A directive applies to its own line and to the line immediately below.
    pub fn allows(&self, rule: &str, line: u32, today: NaiveDate) -> bool {
        [line, line.saturating_sub(1)]
            .iter()
            .filter_map(|candidate| self.by_line.get(candidate))
            .flatten()
            .any(|directive| directive.covers(rule) && !directive.expired(today))
    }

    pub fn is_empty(&self) -> bool {
        self.by_line.is_empty()
    }
}

fn directive_pattern() -> Regex {
    Regex::new(&format!(
        r#"(?i){MARKER}\s+([A-Za-z0-9\-_*,\s]+?)(?:\s+(?:until|reason)=|$)"#
    ))
    .expect("A built-in pattern must be valid")
}

fn field(line: &str, name: &str) -> Option<String> {
    let pattern = Regex::new(&format!(
        r#"(?i){name}\s*=\s*"([^"]*)"|(?i){name}\s*=\s*(\S+)"#
    ))
    .ok()?;
    let captures = pattern.captures(line)?;
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .map(|m| m.as_str().trim().to_string())
}

pub fn parse_file(file: &SourceFile) -> FileExceptions {
    let mut result = FileExceptions::default();
    if !file.content.contains(MARKER) {
        return result;
    }
    let pattern = directive_pattern();
    // A directive inside an in-file test module is a fixture for this very parser.
    // Reporting its expiry as a finding turns the tool's own tests into defects.
    let tests_from = crate::scan::test_region_start(file);

    for (line_no, line) in file.lines_iter() {
        if tests_from.is_some_and(|boundary| line_no >= boundary) {
            break;
        }
        if !line.contains(MARKER) {
            continue;
        }
        let rules: Vec<String> = match pattern.captures(line) {
            Some(captures) => captures
                .get(1)
                .map(|m| {
                    m.as_str()
                        .split([',', ' '])
                        .map(str::trim)
                        .filter(|token| !token.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            None => Vec::new(),
        };
        if rules.is_empty() {
            continue;
        }

        let until =
            field(line, "until").and_then(|raw| NaiveDate::parse_from_str(&raw, "%Y-%m-%d").ok());
        let reason = field(line, "reason").unwrap_or_default();

        result.by_line.entry(line_no).or_default().push(Directive {
            rules,
            until,
            reason,
            line: line_no,
            raw: line.trim().chars().take(160).collect(),
        });
    }
    result
}

/// Expired or malformed directives, reported so the gate fails on the calendar.
pub fn audit(inventory: &Inventory, today: NaiveDate) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file in &inventory.files {
        let exceptions = parse_file(file);
        for directives in exceptions.by_line.values() {
            for directive in directives {
                if !directive.expired(today) {
                    continue;
                }

                let (title, description, severity) = match directive.until {
                    Some(until) => (
                        format!("Exception Has Expired: {}", directive.rules.join(", ")),
                        format!(
                            "The `until={until}` date has passed (today is {today}). Reason: {}",
                            if directive.reason.is_empty() {
                                "not stated".to_string()
                            } else {
                                directive.reason.clone()
                            }
                        ),
                        Severity::High,
                    ),
                    None => (
                        format!(
                            "Exception Written Without An `until=` Date: {}",
                            directive.rules.join(", ")
                        ),
                        "An open-ended exception is not accepted. `until=YYYY-MM-DD` and \
`reason=\"...\"` are both required."
                            .to_string(),
                        Severity::Medium,
                    ),
                };

                findings.push(
                    Finding::builder("DB-GATE-001", Category::Compliance, severity)
                        .title(title)
                        .description(description)
                        .impact(
                            "The rule applies again because the exception has lapsed. An expired \
exception means a hidden defect: the code never changed, it was only removed from the report.",
                        )
                        .remediation(
                            "Either fix the underlying defect and delete the exception, or renew it \
formally with a new date and a justification (SEC-00, clause 8: no open-ended exceptions).",
                        )
                        .origin(Origin::Static)
                        .confidence(Confidence::Confirmed)
                        .evidence(Evidence::new(
                            &file.rel_path,
                            Some(directive.line),
                            directive.raw.clone(),
                        ))
                        .policy("SEC-00, b.8")
                        .build(),
                );
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file(body: &str) -> SourceFile {
        SourceFile {
            rel_path: "app/x.py".to_string(),
            abs_path: PathBuf::from("app/x.py"),
            language: "Python",
            size: body.len() as u64,
            lines: body.lines().count(),
            content: body.to_string(),
            truncated: false,
        }
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 7, 28).unwrap()
    }

    #[test]
    fn an_active_exception_suppresses_its_own_line() {
        let body = "x = 1  # deadbolt-ignore DB-INJ-001 until=2026-12-31 reason=\"US-142\"\n";
        let exceptions = parse_file(&file(body));
        assert!(exceptions.allows("DB-INJ-001", 1, today()));
        assert!(!exceptions.allows("DB-SEC-001", 1, today()));
    }

    #[test]
    fn an_exception_also_covers_the_following_line() {
        let body =
            "# deadbolt-ignore DB-INJ-001 until=2026-12-31 reason=\"x\"\nquery = f\"SELECT {x}\"\n";
        let exceptions = parse_file(&file(body));
        assert!(exceptions.allows("DB-INJ-001", 2, today()));
    }

    #[test]
    fn an_expired_exception_stops_suppressing_and_becomes_a_finding() {
        let body = "x = 1  # deadbolt-ignore DB-INJ-001 until=2026-01-01 reason=\"legacy\"\n";
        let source = file(body);
        let exceptions = parse_file(&source);
        assert!(!exceptions.allows("DB-INJ-001", 1, today()));

        let inventory = Inventory {
            root: PathBuf::from("/tmp"),
            files: vec![source],
            stack: Default::default(),
            manifests: Vec::new(),
            skipped_large: 0,
            skipped_large_names: Vec::new(),
        };
        let findings = audit(&inventory, today());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn a_dateless_exception_is_treated_as_expired() {
        let body = "x = 1  # deadbolt-ignore DB-INJ-001 reason=\"forever\"\n";
        let source = file(body);
        assert!(!parse_file(&source).allows("DB-INJ-001", 1, today()));

        let inventory = Inventory {
            root: PathBuf::from("/tmp"),
            files: vec![source],
            stack: Default::default(),
            manifests: Vec::new(),
            skipped_large: 0,
            skipped_large_names: Vec::new(),
        };
        let findings = audit(&inventory, today());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn multiple_rules_and_wildcards_are_supported() {
        let body = "x  # deadbolt-ignore DB-INJ-001,DB-SEC-001 until=2026-12-31 reason=\"x\"\n";
        let exceptions = parse_file(&file(body));
        assert!(exceptions.allows("DB-INJ-001", 1, today()));
        assert!(exceptions.allows("DB-SEC-001", 1, today()));

        let wildcard = parse_file(&file(
            "y  # deadbolt-ignore * until=2026-12-31 reason=\"x\"\n",
        ));
        assert!(wildcard.allows("DB-ANY-999", 1, today()));
    }

    #[test]
    fn a_file_without_the_marker_is_cheap_to_check() {
        assert!(parse_file(&file("just some code\n")).is_empty());
    }
}
