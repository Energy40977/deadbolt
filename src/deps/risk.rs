use chrono::{DateTime, Utc};

use crate::deps::DepsOptions;
use crate::model::{
    Category, Confidence, Evidence, Finding, Origin, Package, PackageAudit, RiskSignal, Severity,
};

/// Packages older than this with no release are treated as unmaintained.
const UNMAINTAINED_DAYS: i64 = 730;
const VERY_NEW_DAYS: i64 = 30;

/// A small, deliberately conservative list used only for typosquat distance.
/// Being short keeps false accusations rare; it is not a popularity index.
const POPULAR: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "axios",
    "express",
    "moment",
    "chalk",
    "commander",
    "typescript",
    "webpack",
    "eslint",
    "jest",
    "next",
    "vue",
    "svelte",
    "dotenv",
    "uuid",
    "zod",
    "prisma",
    "tailwindcss",
    "vite",
    "rimraf",
    "yargs",
    "debug",
    "semver",
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "django",
    "flask",
    "fastapi",
    "pydantic",
    "sqlalchemy",
    "boto3",
    "cryptography",
    "pytest",
    "click",
    "jinja2",
    "pillow",
    "celery",
    "redis",
    "httpx",
    "attrs",
    "certifi",
    "setuptools",
    "colorama",
    "python-dateutil",
    "serde",
    "tokio",
    "clap",
    "regex",
    "anyhow",
    "thiserror",
    "reqwest",
    "rand",
    "chrono",
];

const RESTRICTIVE_LICENSES: &[&str] =
    &["AGPL", "SSPL", "BUSL", "Commons Clause", "Elastic License"];

pub fn score_all(audits: &mut [PackageAudit]) {
    for audit in audits.iter_mut() {
        let mut signals = Vec::new();

        if !audit.vulnerabilities.is_empty() {
            signals.push(RiskSignal::KnownVulnerability);
        }
        if audit.enriched {
            if audit.deprecated {
                signals.push(RiskSignal::Deprecated);
            }
            if audit.install_scripts {
                signals.push(RiskSignal::InstallScript);
            }
            if audit.maintainers == 1 {
                signals.push(RiskSignal::SingleMaintainer);
            }

            match age_in_days(audit.last_release.as_deref()) {
                Some(days) if days > UNMAINTAINED_DAYS => signals.push(RiskSignal::Unmaintained),
                Some(days) if days < VERY_NEW_DAYS => signals.push(RiskSignal::VeryNewPackage),
                _ => {}
            }

            if audit.license.is_empty() {
                signals.push(RiskSignal::UnknownLicense);
            } else if RESTRICTIVE_LICENSES.iter().any(|needle| {
                audit
                    .license
                    .to_uppercase()
                    .contains(&needle.to_uppercase())
            }) {
                signals.push(RiskSignal::RestrictiveLicense);
            }
        }

        if let Some(package) = &audit.package {
            if let Some(_similar) = typosquat_of(&package.name) {
                signals.push(RiskSignal::PossibleTyposquat);
            }
        }

        let vulnerability_bonus: f64 = audit
            .vulnerabilities
            .iter()
            .map(|vulnerability| match vulnerability.severity {
                Severity::Critical => 30.0,
                Severity::High => 15.0,
                Severity::Medium => 5.0,
                _ => 1.0,
            })
            .sum();

        audit.risk_score =
            signals.iter().map(RiskSignal::weight).sum::<f64>() + vulnerability_bonus;
        audit.signals = signals;
    }
}

fn age_in_days(timestamp: Option<&str>) -> Option<i64> {
    let raw = timestamp?;
    let parsed = DateTime::parse_from_rfc3339(raw).ok()?;
    Some((Utc::now() - parsed.with_timezone(&Utc)).num_days())
}

/// Returns the popular package this name is suspiciously close to.
fn typosquat_of(name: &str) -> Option<&'static str> {
    let candidate = name.rsplit('/').next().unwrap_or(name).to_lowercase();
    if candidate.len() < 4 {
        return None;
    }
    POPULAR
        .iter()
        .find(|popular| **popular != candidate.as_str() && levenshtein(&candidate, popular) == 1)
        .copied()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];

    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            current[j + 1] = (previous[j] + cost)
                .min(previous[j + 1] + 1)
                .min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

pub fn to_findings(audits: &[PackageAudit]) -> Vec<Finding> {
    let mut out = Vec::new();

    for audit in audits {
        let package = match &audit.package {
            Some(package) => package,
            None => continue,
        };

        if !audit.vulnerabilities.is_empty() {
            let worst = audit
                .vulnerabilities
                .iter()
                .map(|v| v.severity)
                .min()
                .unwrap_or(Severity::Medium);

            let ids: Vec<String> = audit
                .vulnerabilities
                .iter()
                .map(|v| {
                    if v.fixed_version.is_empty() {
                        v.id.clone()
                    } else {
                        format!("{} (fixed in: {})", v.id, v.fixed_version)
                    }
                })
                .collect();

            let fix = audit
                .vulnerabilities
                .iter()
                .find(|v| !v.fixed_version.is_empty())
                .map(|v| {
                    format!(
                        "Upgrade {} to version {} or newer.",
                        package.name, v.fixed_version
                    )
                })
                .unwrap_or_else(|| {
                    format!(
                        "No fixed release exists: consider replacing {} or restricting how it is used.",
                        package.name
                    )
                });

            let mut builder = Finding::builder("DB-DEP-VULN", Category::SupplyChain, worst)
                .title(format!(
                    "{}@{} — {} Known Vulnerabilities",
                    package.name,
                    package.version,
                    audit.vulnerabilities.len()
                ))
                .description(
                    audit
                        .vulnerabilities
                        .iter()
                        .map(|v| format!("{}: {}", v.id, v.summary))
                        .collect::<Vec<_>>()
                        .join(" · "),
                )
                .impact(
                    "A known vulnerability is documented in public databases: the exploit is usually public and automated scanners find it.",
                )
                .remediation(fix)
                .origin(Origin::Dependency)
                .confidence(Confidence::Confirmed)
                .evidence(Evidence::new(
                    &package.manifest,
                    None,
                    format!("{}@{} — {}", package.name, package.version, ids.join(", ")),
                ))
                .cwe(1395)
                .policy("DEV-02, b.12.4");

            for vulnerability in &audit.vulnerabilities {
                builder = builder.reference(format!(
                    "https://osv.dev/vulnerability/{}",
                    vulnerability.id
                ));
            }
            out.push(builder.build());
        }

        let other: Vec<&RiskSignal> = audit
            .signals
            .iter()
            .filter(|signal| **signal != RiskSignal::KnownVulnerability)
            .collect();

        if other.is_empty() {
            continue;
        }

        let notable = other.iter().any(|signal| {
            matches!(
                signal,
                RiskSignal::PossibleTyposquat
                    | RiskSignal::InstallScript
                    | RiskSignal::Deprecated
                    | RiskSignal::RecentOwnershipChange
                    | RiskSignal::TelemetryDetected
            )
        });
        let weak_only = !notable && other.len() < 2;
        if weak_only || (!package.direct && !notable) {
            continue;
        }

        let severity = if other
            .iter()
            .any(|s| matches!(s, RiskSignal::PossibleTyposquat))
        {
            Severity::High
        } else if other.iter().any(|s| {
            matches!(
                s,
                RiskSignal::InstallScript
                    | RiskSignal::Deprecated
                    | RiskSignal::RecentOwnershipChange
            )
        }) {
            Severity::Medium
        } else {
            Severity::Low
        };

        let labels: Vec<&str> = other.iter().map(|signal| signal.label()).collect();

        let mut remediation = Vec::new();
        for signal in &other {
            remediation.push(match signal {
                RiskSignal::PossibleTyposquat => {
                    if let Some(similar) = typosquat_of(&package.name) {
                        format!(
                            "The name is very close to the popular package \"{similar}\" — confirm in the registry that this is the right package."
                        )
                    } else {
                        "Confirm the package name in the registry.".to_string()
                    }
                }
                RiskSignal::InstallScript => {
                    "Read the install script and consider using `--ignore-scripts` in CI.".to_string()
                }
                RiskSignal::Deprecated => "The package is deprecated — move to a maintained alternative.".to_string(),
                RiskSignal::Unmaintained => {
                    "No release for over two years: if a vulnerability is found, no fix will arrive.".to_string()
                }
                RiskSignal::SingleMaintainer => {
                    "Single maintainer: a takeover of that account affects you directly.".to_string()
                }
                RiskSignal::RestrictiveLicense => {
                    format!("The licence ({}) may restrict commercial use — legal review required.", audit.license)
                }
                RiskSignal::UnknownLicense => "The licence could not be determined — a legal risk.".to_string(),
                RiskSignal::VeryNewPackage => {
                    "The package is very new: it has no reputation history, so assess it carefully.".to_string()
                }
                other => format!("Siqnal: {}", other.label()),
            });
        }

        out.push(
            Finding::builder("DB-DEP-RISK", Category::SupplyChain, severity)
                .title(format!(
                    "{}@{} — Supply-Chain Risk: {}",
                    package.name,
                    package.version,
                    labels.join(", ")
                ))
                .impact("A dependency runs with the same privileges as your own code: a compromised package gains access to all application data.")
                .remediation(remediation.join(" "))
                .origin(Origin::Dependency)
                .confidence(Confidence::Probable)
                .evidence(Evidence::new(
                    &package.manifest,
                    None,
                    format!("{}@{}", package.name, package.version),
                ))
                .policy("DEV-02, b.12")
                .build(),
        );
    }

    out
}

/// Copyleft strength, used to decide whether a dependency licence conflicts
/// with the project's own. Not legal advice — a signal that needs a human.
fn copyleft_rank(license: &str) -> u8 {
    let upper = license.to_uppercase();
    if upper.contains("SSPL") || upper.contains("BUSL") || upper.contains("COMMONS CLAUSE") {
        4 // source-available, not open source
    } else if upper.contains("AGPL") {
        3 // network copyleft
    } else if upper.contains("GPL") && !upper.contains("LGPL") {
        2 // strong copyleft
    } else if upper.contains("LGPL") || upper.contains("MPL") || upper.contains("EPL") {
        1 // weak copyleft
    } else {
        0 // permissive or unknown
    }
}

/// Flags dependencies whose licence is stronger copyleft than the project's own.
///
/// The classic failure is an AGPL dependency inside an MIT-licensed product:
/// technically it builds, legally it can force disclosure of the whole service.
pub fn license_conflicts(audits: &[PackageAudit], project_license: &str) -> Vec<Finding> {
    let project_rank = copyleft_rank(project_license);
    let mut conflicts: Vec<(&str, &str, bool)> = Vec::new();

    for audit in audits {
        if !audit.enriched || audit.license.is_empty() {
            continue;
        }
        let package = match &audit.package {
            Some(package) => package,
            None => continue,
        };
        if copyleft_rank(&audit.license) > project_rank {
            conflicts.push((
                package.name.as_str(),
                audit.license.as_str(),
                package.direct,
            ));
        }
    }

    if conflicts.is_empty() {
        return Vec::new();
    }

    conflicts.sort_by_key(|(name, _, direct)| (!*direct, *name));
    let listing = conflicts
        .iter()
        .take(15)
        .map(|(name, license, direct)| {
            format!(
                "{name} ({license}{})",
                if *direct { ", direct" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    vec![Finding::builder("DB-DEP-LICENSE", Category::SupplyChain, Severity::Medium)
        .title(format!(
            "{} Dependencies Have A Stronger Licence Than The Project ({})",
            conflicts.len(),
            if project_license.is_empty() { "undetermined" } else { project_license }
        ))
        .description(listing)
        .impact(
            "A strong copyleft dependency can require the source of the whole product to be released, and AGPL covers use over a network as well. Source-available licences (SSPL, BUSL) can restrict commercial use outright.",
        )
        .remediation(
            "Decide for each one: move to a permissively licensed alternative, isolate the use in a separate process, or obtain legal advice and record the decision. This is a signal, not legal advice.",
        )
        .origin(Origin::Dependency)
        .confidence(Confidence::Probable)
        .evidence(Evidence::new("<dependencies>", None, String::new()))
        .policy("SEC-09, b.6.1")
        .build()]
}

/// Which packages deserve the expensive research tier.
pub fn select_for_research(audits: &[PackageAudit], options: &DepsOptions) -> Vec<Package> {
    let mut candidates: Vec<(&PackageAudit, f64)> = audits
        .iter()
        .filter_map(|audit| {
            audit.package.as_ref()?;
            if options.exhaustive {
                return Some((audit, audit.risk_score.max(0.1)));
            }
            let boost = if audit.package.as_ref().map(|p| p.direct).unwrap_or(false) {
                4.0
            } else {
                0.0
            };
            let score = audit.risk_score + boost;
            (score > 0.0).then_some((audit, score))
        })
        .collect();

    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let limit = if options.exhaustive || options.research_limit == 0 {
        usize::MAX
    } else {
        options.research_limit
    };

    candidates
        .into_iter()
        .take(limit)
        .filter_map(|(audit, _)| audit.package.clone())
        .collect()
}

#[cfg(test)]
mod license_tests {
    use super::*;
    use crate::model::Package;

    fn audit(name: &str, license: &str, direct: bool) -> PackageAudit {
        PackageAudit {
            package: Some(Package {
                name: name.into(),
                version: "1.0.0".into(),
                ecosystem: "npm".into(),
                direct,
                manifest: "package.json".into(),
            }),
            license: license.into(),
            enriched: true,
            ..Default::default()
        }
    }

    #[test]
    fn copyleft_is_ranked_by_strength() {
        assert!(copyleft_rank("SSPL-1.0") > copyleft_rank("AGPL-3.0"));
        assert!(copyleft_rank("AGPL-3.0") > copyleft_rank("GPL-3.0"));
        assert!(copyleft_rank("GPL-3.0") > copyleft_rank("LGPL-3.0"));
        assert!(copyleft_rank("LGPL-3.0") > copyleft_rank("MIT"));
        assert_eq!(copyleft_rank("Apache-2.0"), 0);
        assert_eq!(copyleft_rank("LGPL-2.1"), 1);
    }

    #[test]
    fn an_agpl_dependency_in_an_mit_project_is_flagged() {
        let audits = vec![audit("copyleft-lib", "AGPL-3.0", true)];
        let findings = license_conflicts(&audits, "MIT");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("copyleft-lib"));
        assert!(findings[0].description.contains("direct"));
    }

    #[test]
    fn a_permissive_dependency_is_never_a_conflict() {
        let audits = vec![audit("ok-lib", "Apache-2.0", true)];
        assert!(license_conflicts(&audits, "MIT").is_empty());
    }

    #[test]
    fn an_agpl_project_may_use_agpl_dependencies() {
        let audits = vec![audit("copyleft-lib", "AGPL-3.0", true)];
        assert!(license_conflicts(&audits, "AGPL-3.0").is_empty());
    }

    #[test]
    fn unenriched_packages_are_not_judged() {
        let mut unenriched = audit("unknown-lib", "AGPL-3.0", true);
        unenriched.enriched = false;
        assert!(license_conflicts(&[unenriched], "MIT").is_empty());
    }
}
