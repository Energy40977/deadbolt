use std::collections::HashSet;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::{
    Category, Confidence, ControlResult, ControlStatus, Finding, PackSummary, Severity,
};

/// Packs shipped inside the binary, so a single file works with no data dir.
const BUILT_IN: &[(&str, &str)] = &[
    ("owasp-asvs", include_str!("../../packs/owasp-asvs.yaml")),
    ("cwe-top", include_str!("../../packs/cwe-top.yaml")),
    ("privacy", include_str!("../../packs/privacy.yaml")),
    ("ecc", include_str!("../../packs/ecc.yaml")),
];

#[derive(Debug, Deserialize)]
pub struct Pack {
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub controls: Vec<Control>,
}

#[derive(Debug, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub detected_by: DetectedBy,
    #[serde(default)]
    pub note: String,
}

fn default_severity() -> String {
    "medium".to_string()
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectedBy {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<u32>,
    #[serde(default)]
    pub asvs: Vec<String>,
}

impl DetectedBy {
    fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && self.categories.is_empty()
            && self.cwe.is_empty()
            && self.asvs.is_empty()
    }
}

pub fn built_in_names() -> Vec<&'static str> {
    BUILT_IN.iter().map(|(name, _)| *name).collect()
}

pub fn load_built_in(name: &str) -> Result<Pack> {
    let (_, body) = BUILT_IN
        .iter()
        .find(|(pack_name, _)| *pack_name == name)
        .with_context(|| {
            format!(
                "Pack '{name}' Not Found. Available: {}",
                built_in_names().join(", ")
            )
        })?;
    parse(body).with_context(|| format!("Could Not Read Pack '{name}'"))
}

pub fn load_file(path: &std::path::Path) -> Result<Pack> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("Could Not Read Pack File: {}", path.display()))?;
    parse(&body).with_context(|| format!("Invalid Pack File: {}", path.display()))
}

pub fn parse(body: &str) -> Result<Pack> {
    let pack: Pack = serde_yaml::from_str(body).context("Invalid YAML Structure")?;
    if pack.controls.is_empty() {
        anyhow::bail!("The pack contains no controls");
    }
    Ok(pack)
}

/// What this run was actually able to check.
pub struct Coverage {
    pub rule_ids: HashSet<String>,
    /// Reserved: category-level coverage once packs declare category gates.
    #[allow(dead_code)]
    pub categories: HashSet<String>,
}

impl Coverage {
    pub fn new(static_rule_ids: &[&str], lenses_run: &[String], deps_ran: bool) -> Self {
        let mut rule_ids: HashSet<String> =
            static_rule_ids.iter().map(|id| id.to_string()).collect();
        for lens in lenses_run {
            rule_ids.insert(format!("AI-{lens}"));
        }
        if deps_ran {
            rule_ids.insert("DB-DEP-VULN".to_string());
            rule_ids.insert("DB-DEP-RISK".to_string());
            rule_ids.insert("DB-DEP-PRIVACY".to_string());
            rule_ids.insert("DB-DEP-INCIDENT".to_string());
        }
        Self {
            rule_ids,
            categories: HashSet::new(),
        }
    }

    fn can_assess(&self, detected_by: &DetectedBy) -> bool {
        if detected_by.is_empty() {
            return false;
        }
        detected_by
            .rules
            .iter()
            .any(|rule| self.rule_ids.contains(rule))
    }
}

fn matches(finding: &Finding, detected_by: &DetectedBy) -> bool {
    if detected_by.rules.contains(&finding.rule) {
        return true;
    }
    if detected_by
        .categories
        .iter()
        .any(|category| category == finding.category.slug())
    {
        return true;
    }
    if let Some(cwe) = finding.cwe {
        if detected_by.cwe.contains(&cwe) {
            return true;
        }
    }
    detected_by
        .asvs
        .iter()
        .any(|control| finding.asvs.iter().any(|item| item == control))
}

pub fn evaluate(pack: &Pack, findings: &[Finding], coverage: &Coverage) -> Vec<ControlResult> {
    pack.controls
        .iter()
        .map(|control| {
            let matched: Vec<&Finding> = findings
                .iter()
                .filter(|finding| matches(finding, &control.detected_by))
                .collect();

            let confirmed: Vec<&&Finding> = matched
                .iter()
                .filter(|finding| finding.confidence != Confidence::Possible)
                .collect();

            let status = if !confirmed.is_empty() {
                ControlStatus::Violated
            } else if !matched.is_empty() {
                ControlStatus::Partial
            } else if coverage.can_assess(&control.detected_by) {
                ControlStatus::Satisfied
            } else {
                ControlStatus::Unknown
            };

            let rationale = match status {
                ControlStatus::Violated => {
                    format!(
                        "{} confirmed findings violate this control",
                        confirmed.len()
                    )
                }
                ControlStatus::Partial => {
                    "only unconfirmed (possible) findings exist — manual review required"
                        .to_string()
                }
                ControlStatus::Satisfied => {
                    "the rules covering this control ran and found no violation".to_string()
                }
                ControlStatus::Unknown => {
                    if control.detected_by.is_empty() {
                        "no automated detector exists for this control — it has to be assessed by \
a person and the result recorded in the register"
                            .to_string()
                    } else {
                        // Naming the detector turns "unknown" from a mystery into a
                        // one-line instruction.
                        let missing: Vec<String> = control
                            .detected_by
                            .rules
                            .iter()
                            .filter(|rule| !coverage.rule_ids.contains(*rule))
                            .cloned()
                            .collect();
                        let hint = missing
                            .iter()
                            .find(|rule| rule.starts_with("AI-"))
                            .map(|rule| {
                                format!(
                                    "run the AI lens with `--lens {}`",
                                    rule.trim_start_matches("AI-")
                                )
                            })
                            .or_else(|| {
                                missing
                                    .iter()
                                    .find(|rule| rule.starts_with("DB-DEP"))
                                    .map(|_| {
                                        "run the dependency phase (drop `--offline`)".to_string()
                                    })
                            })
                            .unwrap_or_else(|| "enable the detector".to_string());
                        format!(
                            "the detector for this control did not run in this pass ({}) — {hint}",
                            missing.join(", ")
                        )
                    }
                }
                ControlStatus::NotApplicable => String::new(),
            };

            let evidence_severity = matched
                .iter()
                .map(|finding| finding.severity)
                .min_by_key(|severity| *severity as u8);

            ControlResult {
                pack: pack.name.clone(),
                id: control.id.clone(),
                title: control.title.clone(),
                status,
                rationale: if control.note.is_empty() {
                    rationale
                } else {
                    format!("{rationale}. {}", control.note)
                },
                matched_findings: matched
                    .iter()
                    .map(|finding| format!("{} @ {}", finding.rule, finding.primary_location()))
                    .take(6)
                    .collect(),
                severity: Severity::parse(&control.severity),
                evidence_severity,
            }
        })
        .collect()
}

pub fn summarize(pack: &Pack, results: &[ControlResult]) -> PackSummary {
    let own: Vec<&ControlResult> = results
        .iter()
        .filter(|result| result.pack == pack.name)
        .collect();
    let count = |status: ControlStatus| own.iter().filter(|r| r.status == status).count();

    PackSummary {
        name: pack.name.clone(),
        title: pack.title.clone(),
        version: pack.version.clone(),
        total: own.len(),
        satisfied: count(ControlStatus::Satisfied),
        violated: count(ControlStatus::Violated),
        partial: count(ControlStatus::Partial),
        unknown: count(ControlStatus::Unknown),
        not_applicable: count(ControlStatus::NotApplicable),
    }
}

/// Violated controls become findings so they appear in the main report and in
/// the CI gate, not only in the compliance table.
pub fn to_findings(results: &[ControlResult]) -> Vec<Finding> {
    results
        .iter()
        .filter(|result| result.status == ControlStatus::Violated)
        .map(|result| {
            // The pack states how serious the control is; the evidence states how
            // serious this violation is. The lower of the two is the honest one.
            let severity = match result.evidence_severity {
                Some(evidence) if evidence > result.severity => evidence,
                _ => result.severity,
            };
            Finding::builder(
                format!("{}:{}", result.pack, result.id),
                Category::Compliance,
                severity,
            )
            .title(format!("{} {} Violated — {}", result.pack, result.id, result.title))
            .description(result.rationale.clone())
            .impact("A compliance control is violated: it will be recorded as a documented gap during an audit, a customer review or certification.".to_string())
            .remediation(format!(
                "Resolve the linked findings: {}",
                result.matched_findings.join(", ")
            ))
            .origin(crate::model::Origin::Compliance)
            .confidence(Confidence::Confirmed)
            .evidence(crate::model::Evidence::new("<compliance>", None, String::new()))
            .policy(format!("{} {}", result.pack, result.id))
            .build()
        })
        .collect()
}
