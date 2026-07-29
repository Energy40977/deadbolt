use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    /// Weight used by the overall score. Critical findings dominate on purpose.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 40.0,
            Severity::High => 15.0,
            Severity::Medium => 4.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn all() -> [Severity; 5] {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Verified against the code; safe to act on.
    Confirmed,
    /// Strong signal, one assumption unverified.
    Probable,
    /// Heuristic only; never blocks a pipeline.
    Possible,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Probable => "probable",
            Confidence::Possible => "possible",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "confirmed" | "high" | "certain" => Confidence::Confirmed,
            "probable" | "medium" | "likely" => Confidence::Probable,
            _ => Confidence::Possible,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Secrets,
    Cryptography,
    Authentication,
    Authorization,
    Injection,
    DataProtection,
    Privacy,
    ErrorHandling,
    SupplyChain,
    Infrastructure,
    Frontend,
    Mobile,
    Database,
    ApiContract,
    Configuration,
    Compliance,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Secrets => "Secrets And Keys",
            Category::Cryptography => "Encryption",
            Category::Authentication => "Authentication",
            Category::Authorization => "Authorisation",
            Category::Injection => "Injection",
            Category::DataProtection => "Data Protection",
            Category::Privacy => "Personal Data",
            Category::ErrorHandling => "Error Handling",
            Category::SupplyChain => "Dependencies",
            Category::Infrastructure => "Infrastructure",
            Category::Frontend => "Frontend",
            Category::Mobile => "Mobil",
            Category::Database => "Database",
            Category::ApiContract => "API Contract",
            Category::Configuration => "Konfiqurasiya",
            Category::Compliance => "Standards",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Category::Secrets => "secrets",
            Category::Cryptography => "cryptography",
            Category::Authentication => "authentication",
            Category::Authorization => "authorization",
            Category::Injection => "injection",
            Category::DataProtection => "data-protection",
            Category::Privacy => "privacy",
            Category::ErrorHandling => "error-handling",
            Category::SupplyChain => "supply-chain",
            Category::Infrastructure => "infrastructure",
            Category::Frontend => "frontend",
            Category::Mobile => "mobile",
            Category::Database => "database",
            Category::ApiContract => "api-contract",
            Category::Configuration => "configuration",
            Category::Compliance => "compliance",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snippet: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl Evidence {
    pub fn new(file: impl Into<String>, line: Option<u32>, snippet: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line,
            snippet: snippet.into(),
            note: String::new(),
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    pub fn location(&self) -> String {
        match self.line {
            Some(line) => format!("{}:{}", self.file, line),
            None => self.file.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Deterministic rule engine.
    Static,
    /// AI lens (name carried in `lens`).
    Ai,
    /// Dependency research phase.
    Dependency,
    /// Compliance pack evaluation.
    Compliance,
    /// Correlated attack path built from other findings.
    Chain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `DB-SEC-001` or `AI-authz`.
    pub rule: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub origin: Origin,
    pub title: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lens: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// What an attacker or a failure actually achieves.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub impact: String,
    /// Concrete input/state -> concrete wrong outcome.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scenario: String,
    /// How to fix it, concretely.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remediation: String,
    /// Optional patch suggestion (unified diff or snippet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub patch: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asvs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

impl Finding {
    pub fn builder(
        rule: impl Into<String>,
        category: Category,
        severity: Severity,
    ) -> FindingBuilder {
        FindingBuilder {
            finding: Finding {
                rule: rule.into(),
                category,
                severity,
                confidence: Confidence::Confirmed,
                origin: Origin::Static,
                title: String::new(),
                lens: String::new(),
                description: String::new(),
                impact: String::new(),
                scenario: String::new(),
                remediation: String::new(),
                patch: String::new(),
                evidence: Vec::new(),
                cwe: None,
                asvs: Vec::new(),
                policy_refs: Vec::new(),
                references: Vec::new(),
            },
        }
    }

    pub fn primary_location(&self) -> String {
        self.evidence
            .first()
            .map(Evidence::location)
            .unwrap_or_else(|| "<project>".to_string())
    }

    /// Identity of a finding across runs.
    ///
    /// Built from rule + file + a whitespace-normalised copy of the offending
    /// code, deliberately NOT the line number:
    ///   * reformatting (whitespace) or inserting code above it keeps the same
    ///     fingerprint, so a baseline survives ordinary edits;
    ///   * a *second, different* occurrence of the same rule in the same file
    ///     gets its own fingerprint, so a newly introduced instance is not
    ///     silently absorbed by an accepted one.
    ///
    /// Findings with no snippet (repo-level checks, AI lenses) fall back to the
    /// title, which is the only stable identity they have.
    pub fn fingerprint(&self) -> String {
        let evidence = self.evidence.first();
        let file = evidence.map(|item| item.file.as_str()).unwrap_or("");
        let snippet = evidence.map(|item| item.snippet.as_str()).unwrap_or("");

        let body = if snippet.trim().is_empty() {
            self.title.to_lowercase()
        } else {
            snippet.to_lowercase()
        };
        let normalized: String = body.chars().filter(|c| !c.is_whitespace()).collect();

        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}|{}", self.rule, file, normalized).as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
}

pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub fn title(mut self, value: impl Into<String>) -> Self {
        self.finding.title = value.into();
        self
    }
    pub fn description(mut self, value: impl Into<String>) -> Self {
        self.finding.description = value.into();
        self
    }
    pub fn impact(mut self, value: impl Into<String>) -> Self {
        self.finding.impact = value.into();
        self
    }
    pub fn scenario(mut self, value: impl Into<String>) -> Self {
        self.finding.scenario = value.into();
        self
    }
    pub fn remediation(mut self, value: impl Into<String>) -> Self {
        self.finding.remediation = value.into();
        self
    }
    /// Part of the public finding contract; no shipped rule emits a patch yet.
    #[allow(dead_code)]
    pub fn patch(mut self, value: impl Into<String>) -> Self {
        self.finding.patch = value.into();
        self
    }
    pub fn confidence(mut self, value: Confidence) -> Self {
        self.finding.confidence = value;
        self
    }
    pub fn origin(mut self, value: Origin) -> Self {
        self.finding.origin = value;
        self
    }
    pub fn lens(mut self, value: impl Into<String>) -> Self {
        self.finding.lens = value.into();
        self
    }
    pub fn evidence(mut self, value: Evidence) -> Self {
        self.finding.evidence.push(value);
        self
    }
    pub fn cwe(mut self, value: u32) -> Self {
        self.finding.cwe = Some(value);
        self
    }
    pub fn asvs(mut self, value: impl Into<String>) -> Self {
        self.finding.asvs.push(value.into());
        self
    }
    pub fn policy(mut self, value: impl Into<String>) -> Self {
        self.finding.policy_refs.push(value.into());
        self
    }
    pub fn reference(mut self, value: impl Into<String>) -> Self {
        self.finding.references.push(value.into());
        self
    }
    pub fn build(self) -> Finding {
        self.finding
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackProfile {
    pub languages: Vec<LanguageStat>,
    pub frameworks: Vec<String>,
    pub databases: Vec<String>,
    pub package_managers: Vec<String>,
    pub ci_systems: Vec<String>,
    pub infrastructure: Vec<String>,
    pub has_frontend: bool,
    pub has_backend: bool,
    pub has_mobile: bool,
    pub has_migrations: bool,
    pub has_iac: bool,
    pub total_files: usize,
    pub total_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageStat {
    pub name: String,
    pub files: usize,
    pub lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub direct: bool,
    pub manifest: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageAudit {
    pub package: Option<Package>,
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_release: Option<String>,
    #[serde(default)]
    pub maintainers: usize,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub license: String,
    #[serde(default)]
    pub install_scripts: bool,
    /// True only when registry metadata was actually retrieved. Absence of
    /// data must never be reported as a finding.
    #[serde(default)]
    pub enriched: bool,
    #[serde(default)]
    pub signals: Vec<RiskSignal>,
    #[serde(default)]
    pub risk_score: f64,
    /// Filled by the deep research tier only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub research: Option<PackageResearch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub summary: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fixed_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskSignal {
    KnownVulnerability,
    Unmaintained,
    Deprecated,
    SingleMaintainer,
    RecentOwnershipChange,
    InstallScript,
    PossibleTyposquat,
    NetworkAtRuntime,
    TelemetryDetected,
    RestrictiveLicense,
    UnknownLicense,
    VeryNewPackage,
    LowAdoption,
}

impl RiskSignal {
    pub fn label(&self) -> &'static str {
        match self {
            RiskSignal::KnownVulnerability => "known vulnerability",
            RiskSignal::Unmaintained => "unmaintained",
            RiskSignal::Deprecated => "deprecated",
            RiskSignal::SingleMaintainer => "single maintainer",
            RiskSignal::RecentOwnershipChange => "ownership change",
            RiskSignal::InstallScript => "install script",
            RiskSignal::PossibleTyposquat => "possible typosquat",
            RiskSignal::NetworkAtRuntime => "network at runtime",
            RiskSignal::TelemetryDetected => "telemetriya izi",
            RiskSignal::RestrictiveLicense => "restrictive licence",
            RiskSignal::UnknownLicense => "lisenziya bilinmir",
            RiskSignal::VeryNewPackage => "very new package",
            RiskSignal::LowAdoption => "low adoption",
        }
    }

    pub fn weight(&self) -> f64 {
        match self {
            RiskSignal::KnownVulnerability => 40.0,
            RiskSignal::TelemetryDetected => 20.0,
            RiskSignal::PossibleTyposquat => 30.0,
            RiskSignal::RecentOwnershipChange => 18.0,
            RiskSignal::InstallScript => 15.0,
            RiskSignal::Deprecated => 12.0,
            RiskSignal::Unmaintained => 10.0,
            RiskSignal::NetworkAtRuntime => 8.0,
            RiskSignal::SingleMaintainer => 5.0,
            RiskSignal::RestrictiveLicense => 6.0,
            RiskSignal::UnknownLicense => 4.0,
            RiskSignal::VeryNewPackage => 6.0,
            RiskSignal::LowAdoption => 3.0,
        }
    }
}

/// Result of the deep (AI + web) research tier for one package.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageResearch {
    #[serde(default)]
    pub collects_personal_data: DataCollection,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data_collected: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoints: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub opt_out: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub maintenance_status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub incidents: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verdict: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recommendation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataCollection {
    Yes,
    Optional,
    No,
    #[default]
    Unknown,
}

impl DataCollection {
    pub fn label(self) -> &'static str {
        match self {
            DataCollection::Yes => "yes",
            DataCollection::Optional => "opsional",
            DataCollection::No => "xeyr",
            DataCollection::Unknown => "bilinmir",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" => DataCollection::Yes,
            "optional" | "opt-in" | "opt_in" => DataCollection::Optional,
            "no" | "false" | "xeyr" => DataCollection::No,
            _ => DataCollection::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlStatus {
    Satisfied,
    Violated,
    Partial,
    NotApplicable,
    Unknown,
}

impl ControlStatus {
    /// Used by report renderers that print a status column.
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            ControlStatus::Satisfied => "satisfied",
            ControlStatus::Violated => "violated",
            ControlStatus::Partial => "partial",
            ControlStatus::NotApplicable => "not applicable",
            ControlStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub pack: String,
    pub id: String,
    pub title: String,
    pub status: ControlStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_findings: Vec<String>,
    /// Severity declared by the pack.
    pub severity: Severity,
    /// Worst severity among the findings that violate this control.
    ///
    /// A control cannot be more severe than its own evidence. Three findings the
    /// scanner already softened to medium — test fixtures, for instance — must not
    /// resurface as a critical compliance violation with the softening lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_severity: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackSummary {
    pub name: String,
    pub title: String,
    pub version: String,
    pub total: usize,
    pub satisfied: usize,
    pub violated: usize,
    pub partial: usize,
    pub unknown: usize,
    pub not_applicable: usize,
}

impl PackSummary {
    pub fn coverage(&self) -> f64 {
        let assessed = self.satisfied + self.violated + self.partial;
        if assessed == 0 {
            return 0.0;
        }
        (self.satisfied as f64 / assessed as f64) * 100.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub tool: String,
    pub version: String,
    pub target: String,
    pub project: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub mode: String,
    pub ai_enabled: bool,
    pub research_enabled: bool,
    #[serde(default)]
    pub lenses_run: Vec<String>,
    #[serde(default)]
    pub packs_run: Vec<String>,
    #[serde(default)]
    pub ai_cost_usd: f64,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub meta: ReportMeta,
    pub stack: StackProfile,
    pub score: Score,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub packages: Vec<PackageAudit>,
    #[serde(default)]
    pub controls: Vec<ControlResult>,
    #[serde(default)]
    pub packs: Vec<PackSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Score {
    /// 0-100, higher is better.
    pub overall: f64,
    pub grade: String,
    pub by_category: BTreeMap<String, f64>,
    pub counts: BTreeMap<String, usize>,
}

/// Canonical finding order.
///
/// The parallel scan collects per-thread results in completion order while the
/// cache restores them in storage order, so two runs over identical code produced
/// identical findings in a different sequence. Every consumer notices: a committed
/// markdown report shows churn with no change behind it, and a JSON diff between
/// two runs is unreadable. Severity leads because that is the order a reader wants;
/// the rest only has to be stable.
pub fn sort_findings(findings: &mut [Finding]) {
    let location = |finding: &Finding| {
        finding
            .evidence
            .first()
            .map(|evidence| (evidence.file.clone(), evidence.line.unwrap_or(0)))
            .unwrap_or_default()
    };
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| location(a).cmp(&location(b)))
            .then_with(|| a.title.cmp(&b.title))
    });
}

impl AuditReport {
    pub fn counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for severity in Severity::all() {
            let total = self
                .findings
                .iter()
                .filter(|f| f.severity == severity)
                .count();
            counts.insert(severity.label().to_string(), total);
        }
        counts
    }

    /// Density-based score.
    ///
    /// Absolute counts punish size, not quality: a 140k-line project with 50
    /// findings is in far better shape than a 2k-line project with the same 50.
    /// The penalty is therefore normalised per 1000 lines, with a floor so a
    /// tiny repository cannot game the denominator.
    pub fn compute_score(&mut self) {
        const KLOC_FLOOR: f64 = 3.0;
        const DECAY: f64 = 12.0;

        let penalty: f64 = self
            .findings
            .iter()
            .filter(|finding| !matches!(finding.origin, Origin::Compliance | Origin::Chain))
            .map(|finding| {
                let confidence_factor = match finding.confidence {
                    Confidence::Confirmed => 1.0,
                    Confidence::Probable => 0.6,
                    Confidence::Possible => 0.25,
                };
                finding.severity.weight() * confidence_factor
            })
            .sum();

        let kloc = (self.stack.total_lines as f64 / 1000.0).max(KLOC_FLOOR);
        let density = penalty / kloc;
        let overall = (100.0 * (-density / DECAY).exp()).clamp(0.0, 100.0);

        let grade = match overall {
            s if s >= 90.0 => "A",
            s if s >= 75.0 => "B",
            s if s >= 60.0 => "C",
            s if s >= 40.0 => "D",
            s if s >= 20.0 => "E",
            _ => "F",
        };

        let mut by_category: BTreeMap<String, f64> = BTreeMap::new();
        for finding in self
            .findings
            .iter()
            .filter(|finding| !matches!(finding.origin, Origin::Compliance | Origin::Chain))
        {
            let entry = by_category
                .entry(finding.category.slug().to_string())
                .or_insert(0.0);
            *entry += finding.severity.weight();
        }

        self.score = Score {
            overall: (overall * 10.0).round() / 10.0,
            grade: grade.to_string(),
            by_category,
            counts: self.counts(),
        };
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;

    fn finding(rule: &str, severity: Severity, file: &str, line: u32) -> Finding {
        Finding::builder(rule, Category::Injection, severity)
            .title("t")
            .evidence(Evidence::new(file, Some(line), ""))
            .build()
    }

    #[test]
    fn ordering_is_stable_regardless_of_arrival_order() {
        let mut first = vec![
            finding("DB-B", Severity::High, "b.py", 2),
            finding("DB-A", Severity::Critical, "a.py", 9),
            finding("DB-A", Severity::Critical, "a.py", 1),
            finding("DB-C", Severity::Low, "c.py", 5),
        ];
        let mut second = vec![
            finding("DB-C", Severity::Low, "c.py", 5),
            finding("DB-A", Severity::Critical, "a.py", 1),
            finding("DB-B", Severity::High, "b.py", 2),
            finding("DB-A", Severity::Critical, "a.py", 9),
        ];
        sort_findings(&mut first);
        sort_findings(&mut second);

        let shape = |list: &[Finding]| {
            list.iter()
                .map(|f| (f.severity, f.rule.clone(), f.evidence[0].line.unwrap_or(0)))
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(&first), shape(&second));
        assert_eq!(first[0].severity, Severity::Critical);
        assert_eq!(first[0].evidence[0].line, Some(1));
        assert_eq!(first[3].severity, Severity::Low);
    }
}
