pub mod manifest;
pub mod osv;
pub mod registry;
pub mod risk;

use anyhow::Result;

use crate::discover::Inventory;
use crate::model::{
    Category, Confidence, Evidence, Finding, Origin, Package, PackageAudit, Severity,
};

/// Reads the project's own licence from the usual places.
pub fn project_license(inventory: &Inventory) -> String {
    for file in &inventory.files {
        let base = file.rel_path.rsplit('/').next().unwrap_or("");
        match base {
            "package.json" => {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&file.content) {
                    if let Some(license) = value.get("license").and_then(|v| v.as_str()) {
                        return license.to_string();
                    }
                }
            }
            "Cargo.toml" | "pyproject.toml" => {
                for (_, line) in file.lines_iter() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("license") {
                        if let Some(value) = rest.split('=').nth(1) {
                            let value = value.trim().trim_matches(['"', '\'']);
                            if !value.is_empty() && !value.starts_with('{') {
                                return value.to_string();
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"] {
        if let Some(body) = inventory.read_root_file(name) {
            let head: String = body.chars().take(600).collect::<String>().to_uppercase();
            for (needle, label) in [
                ("AGPL", "AGPL"),
                ("GNU LESSER", "LGPL"),
                ("GNU GENERAL PUBLIC", "GPL"),
                ("MOZILLA PUBLIC", "MPL"),
                ("APACHE LICENSE", "Apache-2.0"),
                ("MIT LICENSE", "MIT"),
                ("BSD", "BSD"),
                ("SERVER SIDE PUBLIC", "SSPL"),
                ("BUSINESS SOURCE", "BUSL"),
            ] {
                if head.contains(needle) {
                    return label.to_string();
                }
            }
        }
    }
    String::new()
}

pub struct DepsOptions {
    pub offline: bool,
    pub research_limit: usize,
    pub exhaustive: bool,
}

impl Default for DepsOptions {
    fn default() -> Self {
        Self {
            offline: false,
            research_limit: 30,
            exhaustive: false,
        }
    }
}

pub struct DepsOutcome {
    pub packages: Vec<PackageAudit>,
    pub findings: Vec<Finding>,
    /// Packages the caller should escalate to deep research, most risky first.
    pub escalate: Vec<Package>,
    pub warnings: Vec<String>,
}

/// Cheap tier: parse manifests, query OSV, pull registry metadata, score risk.
pub async fn survey(inventory: &Inventory, options: &DepsOptions) -> Result<DepsOutcome> {
    let packages = manifest::collect(inventory);
    let mut warnings = Vec::new();

    if packages.is_empty() {
        return Ok(DepsOutcome {
            packages: Vec::new(),
            findings: Vec::new(),
            escalate: Vec::new(),
            warnings: vec!["No Dependency Manifest Found".to_string()],
        });
    }

    let mut audits: Vec<PackageAudit> = packages
        .iter()
        .cloned()
        .map(|package| PackageAudit {
            package: Some(package),
            ..Default::default()
        })
        .collect();

    if !options.offline {
        match osv::query_batch(&packages).await {
            Ok(vulnerabilities) => {
                for audit in &mut audits {
                    if let Some(package) = &audit.package {
                        let key = osv::key(package);
                        if let Some(found) = vulnerabilities.get(&key) {
                            audit.vulnerabilities = found.clone();
                        }
                    }
                }
            }
            Err(error) => warnings.push(format!("OSV Query Failed: {error:#}")),
        }

        match registry::enrich(&mut audits).await {
            Ok(count) => {
                if count == 0 {
                    warnings.push("Registry Metadata Unavailable".to_string());
                }
            }
            Err(error) => warnings.push(format!("Registry Query Failed: {error:#}")),
        }
    } else {
        warnings.push("Offline Mode: Vulnerability And Registry Checks Skipped".to_string());
    }

    risk::score_all(&mut audits);

    let mut findings = risk::to_findings(&audits);
    findings.extend(risk::license_conflicts(
        &audits,
        &project_license(inventory),
    ));
    let escalate = risk::select_for_research(&audits, options);

    Ok(DepsOutcome {
        packages: audits,
        findings,
        escalate,
        warnings,
    })
}

/// Turn a completed deep-research result into report findings.
pub fn research_findings(audits: &[PackageAudit]) -> Vec<Finding> {
    use crate::model::DataCollection;

    let mut out = Vec::new();
    for audit in audits {
        let (package, research) = match (&audit.package, &audit.research) {
            (Some(package), Some(research)) => (package, research),
            _ => continue,
        };

        if matches!(
            research.collects_personal_data,
            DataCollection::Yes | DataCollection::Optional
        ) {
            let severity = if research.collects_personal_data == DataCollection::Yes {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut builder = Finding::builder("DB-DEP-PRIVACY", Category::Privacy, severity)
                .title(format!(
                    "{} Collects Personal Data ({})",
                    package.name,
                    research.collects_personal_data.label()
                ))
                .description(research.data_collected.clone())
                .impact(format!(
                    "The collected data is transferred to a third party{}. That requires a legal basis, disclosure in the privacy policy and user consent, and the jurisdiction where the data is stored has to be considered as well.",
                    if research.endpoints.is_empty() {
                        String::new()
                    } else {
                        format!(" (endpoint: {})", research.endpoints)
                    }
                ))
                .remediation(if research.opt_out.is_empty() {
                    research.recommendation.clone()
                } else {
                    format!("{} Opt-Out: {}", research.recommendation, research.opt_out)
                })
                .origin(Origin::Dependency)
                .confidence(Confidence::Probable)
                .evidence(Evidence::new(
                    &package.manifest,
                    None,
                    format!("{}@{}", package.name, package.version),
                ))
                .cwe(359)
                .policy("SEC-05, b.4");
            for source in &research.sources {
                builder = builder.reference(source.clone());
            }
            out.push(builder.build());
        }

        if !research.incidents.is_empty() {
            out.push(
                Finding::builder("DB-DEP-INCIDENT", Category::SupplyChain, Severity::High)
                    .title(format!(
                        "Security Incident Linked To The {} Package",
                        package.name
                    ))
                    .description(research.incidents.clone())
                    .impact("A compromised package, or one whose ownership changed, can ship malicious code in the next update.")
                    .remediation(research.recommendation.clone())
                    .origin(Origin::Dependency)
                    .confidence(Confidence::Probable)
                    .evidence(Evidence::new(
                        &package.manifest,
                        None,
                        format!("{}@{}", package.name, package.version),
                    ))
                    .cwe(1357)
                    .policy("DEV-02, b.12.2")
                    .build(),
            );
        }
    }
    out
}
