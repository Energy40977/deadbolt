use serde_json::{json, Value};

use crate::model::{AuditReport, PackageAudit, Severity};

/// Package URL (purl) for a package, per the purl spec type names.
fn purl(name: &str, version: &str, ecosystem: &str) -> String {
    let kind = match ecosystem {
        "npm" => "npm",
        "PyPI" => "pypi",
        "crates.io" => "cargo",
        "Go" => "golang",
        "Packagist" => "composer",
        "RubyGems" => "gem",
        "Pub" => "pub",
        "Maven" => "maven",
        other => other,
    };
    format!("pkg:{kind}/{name}@{version}")
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn component(audit: &PackageAudit) -> Option<Value> {
    let package = audit.package.as_ref()?;
    let reference = purl(&package.name, &package.version, &package.ecosystem);

    let mut properties = vec![json!({
        "name": "deadbolt:direct",
        "value": package.direct.to_string()
    })];
    if !package.manifest.is_empty() {
        properties.push(json!({
            "name": "deadbolt:manifest",
            "value": package.manifest
        }));
    }
    if !audit.signals.is_empty() {
        properties.push(json!({
            "name": "deadbolt:risk-signals",
            "value": audit
                .signals
                .iter()
                .map(|signal| signal.label())
                .collect::<Vec<_>>()
                .join(", ")
        }));
    }
    if let Some(research) = &audit.research {
        properties.push(json!({
            "name": "deadbolt:collects-personal-data",
            "value": research.collects_personal_data.label()
        }));
    }

    let mut entry = json!({
        "type": "library",
        "bom-ref": reference,
        "name": package.name,
        "version": package.version,
        "purl": reference,
        "scope": if package.direct { "required" } else { "optional" },
        "properties": properties,
    });

    if !audit.license.is_empty() {
        entry["licenses"] = json!([{ "license": { "name": audit.license } }]);
    }
    Some(entry)
}

fn vulnerability(audit: &PackageAudit) -> Vec<Value> {
    let package = match audit.package.as_ref() {
        Some(package) => package,
        None => return Vec::new(),
    };
    let reference = purl(&package.name, &package.version, &package.ecosystem);

    audit
        .vulnerabilities
        .iter()
        .map(|item| {
            let mut entry = json!({
                "id": item.id,
                "source": { "name": "OSV", "url": format!("https://osv.dev/vulnerability/{}", item.id) },
                "description": item.summary,
                "ratings": [{
                    "severity": severity_label(item.severity),
                    "method": if item.cvss.is_some() { "CVSSv31" } else { "other" }
                }],
                "affects": [{ "ref": reference }],
            });
            if !item.aliases.is_empty() {
                entry["references"] = json!(item
                    .aliases
                    .iter()
                    .map(|alias| json!({ "id": alias, "source": { "name": "alias" } }))
                    .collect::<Vec<_>>());
            }
            if let Some(vector) = &item.cvss {
                entry["ratings"][0]["vector"] = json!(vector);
            }
            if !item.fixed_version.is_empty() {
                entry["analysis"] = json!({
                    "state": "exploitable",
                    "detail": format!("Fixed In Version: {}", item.fixed_version)
                });
            }
            entry
        })
        .collect()
}

pub fn cyclonedx(report: &AuditReport) -> Value {
    let components: Vec<Value> = report.packages.iter().filter_map(component).collect();
    let vulnerabilities: Vec<Value> = report.packages.iter().flat_map(vulnerability).collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": report.meta.started_at,
            "tools": [{
                "vendor": "deadbolt",
                "name": "deadbolt",
                "version": report.meta.version
            }],
            "component": {
                "type": "application",
                "bom-ref": format!("root:{}", report.meta.project),
                "name": report.meta.project,
            },
            "properties": [
                { "name": "deadbolt:score", "value": format!("{:.1}", report.score.overall) },
                { "name": "deadbolt:grade", "value": report.score.grade },
            ]
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    })
}

/// Serialised CycloneDX document.
pub fn render(report: &AuditReport) -> anyhow::Result<String> {
    serde_json::to_string_pretty(&cyclonedx(report)).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Package, PackageAudit, ReportMeta, StackProfile, Vulnerability};

    fn report() -> AuditReport {
        let mut audit = AuditReport {
            meta: ReportMeta {
                tool: "deadbolt".into(),
                version: "0.1.0".into(),
                target: "/tmp/x".into(),
                project: "demo".into(),
                started_at: "2026-07-28T00:00:00Z".into(),
                duration_ms: 1,
                mode: "audit".into(),
                ai_enabled: false,
                research_enabled: false,
                lenses_run: Vec::new(),
                packs_run: Vec::new(),
                ai_cost_usd: 0.0,
                warnings: Vec::new(),
            },
            stack: StackProfile::default(),
            score: Default::default(),
            findings: Vec::new(),
            packages: vec![PackageAudit {
                package: Some(Package {
                    name: "lodash".into(),
                    version: "4.17.20".into(),
                    ecosystem: "npm".into(),
                    direct: true,
                    manifest: "package.json".into(),
                }),
                license: "MIT".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "GHSA-xxxx".into(),
                    severity: Severity::High,
                    summary: "prototype pollution".into(),
                    fixed_version: "4.17.21".into(),
                    aliases: vec!["CVE-2020-8203".into()],
                    cvss: Some("CVSS:3.1/AV:N/AC:L".into()),
                }],
                ..Default::default()
            }],
            controls: Vec::new(),
            packs: Vec::new(),
        };
        audit.compute_score();
        audit
    }

    #[test]
    fn emits_a_valid_cyclonedx_skeleton() {
        let bom = cyclonedx(&report());
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.5");
        assert_eq!(bom["components"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn component_carries_a_purl_and_licence() {
        let bom = cyclonedx(&report());
        let component = &bom["components"][0];
        assert_eq!(component["purl"], "pkg:npm/lodash@4.17.20");
        assert_eq!(component["licenses"][0]["license"]["name"], "MIT");
        assert_eq!(component["scope"], "required");
    }

    #[test]
    fn vulnerabilities_are_linked_to_their_component() {
        let bom = cyclonedx(&report());
        let vulnerability = &bom["vulnerabilities"][0];
        assert_eq!(vulnerability["id"], "GHSA-xxxx");
        assert_eq!(vulnerability["affects"][0]["ref"], "pkg:npm/lodash@4.17.20");
        assert_eq!(vulnerability["ratings"][0]["severity"], "high");
        assert!(vulnerability["analysis"]["detail"]
            .as_str()
            .unwrap()
            .contains("4.17.21"));
    }

    #[test]
    fn purl_types_follow_the_spec() {
        assert_eq!(purl("django", "5.0", "PyPI"), "pkg:pypi/django@5.0");
        assert_eq!(purl("serde", "1.0", "crates.io"), "pkg:cargo/serde@1.0");
        assert_eq!(purl("rails", "7.1", "RubyGems"), "pkg:gem/rails@7.1");
    }
}
