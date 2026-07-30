pub mod html;

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

use crate::model::{AuditReport, Confidence, Finding, Origin, Severity};

fn icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "■",
        Severity::High => "▲",
        Severity::Medium => "●",
        Severity::Low => "·",
        Severity::Info => "○",
    }
}

fn paint(severity: Severity, text: &str, color: bool) -> String {
    if !color {
        return text.to_string();
    }
    match severity {
        Severity::Critical => text.on_red().white().bold().to_string(),
        Severity::High => text.red().bold().to_string(),
        Severity::Medium => text.yellow().to_string(),
        Severity::Low => text.bright_black().to_string(),
        Severity::Info => text.blue().to_string(),
    }
}

pub fn terminal(report: &AuditReport, color: bool, limit: usize) -> String {
    let mut out = String::new();
    let rule = "─".repeat(74);

    let header = format!("  deadbolt — {}", report.meta.project);
    out.push('\n');
    out.push_str(&if color {
        header.bold().to_string()
    } else {
        header
    });
    out.push_str(&format!("\n  {rule}\n"));

    let languages: Vec<String> = report
        .stack
        .languages
        .iter()
        .take(4)
        .map(|l| format!("{} ({})", l.name, l.files))
        .collect();
    out.push_str(&format!("  Stack       {}\n", languages.join(", ")));
    if !report.stack.frameworks.is_empty() {
        out.push_str(&format!(
            "  Frameworks  {}\n",
            report.stack.frameworks.join(", ")
        ));
    }
    if !report.stack.databases.is_empty() {
        out.push_str(&format!(
            "  Databases   {}\n",
            report.stack.databases.join(", ")
        ));
    }
    out.push_str(&format!(
        "  Size        {} Files, {} Lines\n",
        report.stack.total_files, report.stack.total_lines
    ));

    let grade_line = format!(
        "  Score       {:.1}/100  ({})",
        report.score.overall, report.score.grade
    );
    let grade_severity = match report.score.overall {
        s if s >= 75.0 => Severity::Low,
        s if s >= 50.0 => Severity::Medium,
        _ => Severity::High,
    };
    out.push_str(&paint(grade_severity, &grade_line, color));
    out.push('\n');

    let mut counts = Vec::new();
    for severity in Severity::all() {
        let total = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .count();
        if total > 0 {
            counts.push(paint(
                severity,
                &format!("{} {}: {}", icon(severity), severity.label(), total),
                color,
            ));
        }
    }
    out.push_str(&format!("  {rule}\n"));
    if counts.is_empty() {
        out.push_str("  No Findings.\n");
    } else {
        out.push_str(&format!("  {}\n\n", counts.join("   ")));
    }

    for finding in report.findings.iter().take(limit) {
        let badge = paint(
            finding.severity,
            &format!(" {} {} ", icon(finding.severity), finding.severity.label()),
            color,
        );
        let origin = match finding.origin {
            Origin::Ai => format!("AI/{}", finding.lens),
            Origin::Dependency => "dependency".to_string(),
            Origin::Compliance => "compliance".to_string(),
            Origin::Chain => "attack chain".to_string(),
            Origin::Static => finding.rule.clone(),
        };
        let location = finding.primary_location();
        out.push_str(&format!(
            "  {badge} {}  {}\n",
            if color {
                location.bold().to_string()
            } else {
                location.clone()
            },
            if color {
                origin.bright_black().to_string()
            } else {
                origin
            }
        ));
        out.push_str(&format!("      {}\n", finding.title));
        if !finding.impact.is_empty() {
            out.push_str(&wrap("      What Can Happen: ", &finding.impact));
        }
        if !finding.scenario.is_empty() {
            out.push_str(&wrap("      Scenario: ", &finding.scenario));
        }
        if !finding.remediation.is_empty() {
            out.push_str(&wrap("      How To Fix It: ", &finding.remediation));
        }
        let mut meta = Vec::new();
        if let Some(cwe) = finding.cwe {
            meta.push(format!("CWE-{cwe}"));
        }
        meta.extend(finding.asvs.iter().cloned());
        meta.extend(finding.policy_refs.iter().cloned());
        if finding.confidence != Confidence::Confirmed {
            meta.push(format!("confidence: {}", finding.confidence.label()));
        }
        if !meta.is_empty() {
            let line = format!("      {}\n", meta.join(" · "));
            out.push_str(&if color {
                line.bright_black().to_string()
            } else {
                line
            });
        }
        out.push('\n');
    }

    if report.findings.len() > limit {
        out.push_str(&format!(
            "  ... {} More Findings (Full List: --format markdown|json)\n\n",
            report.findings.len() - limit
        ));
    }

    out.push_str(&format!("  {rule}\n"));
    let mut footer = vec![format!("{} ms", report.meta.duration_ms)];
    if !report.packages.is_empty() {
        footer.push(format!("{} packages", report.packages.len()));
    }
    if !report.meta.lenses_run.is_empty() {
        footer.push(format!("AI lens: {}", report.meta.lenses_run.join(", ")));
    }
    if report.meta.ai_cost_usd > 0.0 {
        footer.push(format!("cost: ${:.4}", report.meta.ai_cost_usd));
    }
    let footer_line = format!("  {}\n", footer.join(" · "));
    out.push_str(&if color {
        footer_line.bright_black().to_string()
    } else {
        footer_line
    });

    for warning in &report.meta.warnings {
        let line = format!("  ⚠ {warning}\n");
        out.push_str(&if color {
            line.yellow().to_string()
        } else {
            line
        });
    }

    out
}

fn wrap(prefix: &str, text: &str) -> String {
    let indent = " ".repeat(prefix.len());
    let wrapped = textwrap::fill(
        text,
        textwrap::Options::new(96)
            .initial_indent(prefix)
            .subsequent_indent(&indent),
    );
    format!("{wrapped}\n")
}

pub fn markdown(report: &AuditReport) -> String {
    let mut out = String::new();

    out.push_str(&format!("# Security Audit — {}\n\n", report.meta.project));
    out.push_str(&format!(
        "| | |\n|---|---|\n| Tool | {} {} |\n| Target | `{}` |\n| Date | {} |\n| Mode | {} |\n| Duration | {} ms |\n| Overall Score | **{:.1}/100 ({})** |\n\n",
        report.meta.tool,
        report.meta.version,
        report.meta.target,
        report.meta.started_at,
        report.meta.mode,
        report.meta.duration_ms,
        report.score.overall,
        report.score.grade
    ));

    out.push_str("## Summary\n\n| Severity | Count |\n|---|---|\n");
    for severity in Severity::all() {
        let total = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .count();
        out.push_str(&format!("| {} | {} |\n", severity.label(), total));
    }
    out.push('\n');

    out.push_str("## Texnoloji stack\n\n");
    out.push_str("| Category | Findings |\n|---|---|\n");
    let languages: Vec<String> = report
        .stack
        .languages
        .iter()
        .take(8)
        .map(|l| format!("{} ({} files)", l.name, l.files))
        .collect();
    out.push_str(&format!("| Languages | {} |\n", languages.join(", ")));
    out.push_str(&format!(
        "| Frameworks | {} |\n",
        or_dash(&report.stack.frameworks)
    ));
    out.push_str(&format!(
        "| Databases | {} |\n",
        or_dash(&report.stack.databases)
    ));
    out.push_str(&format!(
        "| Package Managers | {} |\n",
        or_dash(&report.stack.package_managers)
    ));
    out.push_str(&format!("| CI | {} |\n", or_dash(&report.stack.ci_systems)));
    out.push_str(&format!(
        "| Infrastructure | {} |\n\n",
        or_dash(&report.stack.infrastructure)
    ));

    out.push_str("## Findings\n\n");
    let mut grouped: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        grouped
            .entry(finding.category.label())
            .or_default()
            .push(finding);
    }

    if grouped.is_empty() {
        out.push_str("No Findings.\n\n");
    }

    for (category, findings) in grouped {
        out.push_str(&format!("### {category} ({})\n\n", findings.len()));
        for finding in findings {
            out.push_str(&format!(
                "#### {} {} — `{}`\n\n",
                icon(finding.severity),
                finding.severity.label(),
                finding.primary_location()
            ));
            out.push_str(&format!("**{}**\n\n", finding.title));
            if !finding.description.is_empty() {
                out.push_str(&format!("{}\n\n", finding.description));
            }
            if !finding.evidence.is_empty() {
                for evidence in finding.evidence.iter().take(3) {
                    if !evidence.snippet.is_empty() {
                        out.push_str(&format!(
                            "```\n{}:{}  {}\n```\n\n",
                            evidence.file,
                            evidence.line.unwrap_or(0),
                            evidence.snippet
                        ));
                    }
                }
            }
            if !finding.impact.is_empty() {
                out.push_str(&format!("- **What Can Happen:** {}\n", finding.impact));
            }
            if !finding.scenario.is_empty() {
                out.push_str(&format!("- **Scenario:** {}\n", finding.scenario));
            }
            if !finding.remediation.is_empty() {
                out.push_str(&format!("- **How To Fix It:** {}\n", finding.remediation));
            }
            let mut meta = Vec::new();
            if let Some(cwe) = finding.cwe {
                meta.push(format!(
                    "[CWE-{cwe}](https://cwe.mitre.org/data/definitions/{cwe}.html)"
                ));
            }
            if !finding.asvs.is_empty() {
                meta.push(format!("ASVS {}", finding.asvs.join(", ")));
            }
            if !finding.policy_refs.is_empty() {
                meta.push(finding.policy_refs.join(", "));
            }
            meta.push(format!("rule: `{}`", finding.rule));
            meta.push(format!("confidence: {}", finding.confidence.label()));
            out.push_str(&format!("- **References:** {}\n", meta.join(" · ")));
            out.push('\n');
        }
    }

    let risky: Vec<_> = report
        .packages
        .iter()
        .filter(|audit| !audit.vulnerabilities.is_empty() || !audit.signals.is_empty())
        .collect();
    if !risky.is_empty() {
        out.push_str(&format!(
            "## Dependencies ({} Packages Checked, {} Risky)\n\n",
            report.packages.len(),
            risky.len()
        ));
        out.push_str("| Package | Version | Ecosystem | Known Vulnerabilities | Risk Signals | Risk Score |\n|---|---|---|---|---|---|\n");
        let mut sorted = risky.clone();
        sorted.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for audit in sorted.iter().take(60) {
            let package = match &audit.package {
                Some(package) => package,
                None => continue,
            };
            let signals: Vec<&str> = audit.signals.iter().map(|s| s.label()).collect();
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {:.0} |\n",
                package.name,
                package.version,
                package.ecosystem,
                audit.vulnerabilities.len(),
                signals.join(", "),
                audit.risk_score
            ));
        }
        out.push('\n');
    }

    if !report.meta.warnings.is_empty() {
        out.push_str("## Notes\n\n");
        for warning in &report.meta.warnings {
            out.push_str(&format!("- {warning}\n"));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "---\n\n<sub>deadbolt {} · {}</sub>\n",
        report.meta.version, report.meta.started_at
    ));

    out
}

fn or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_string()
    } else {
        items.join(", ")
    }
}

pub fn json(report: &AuditReport) -> Result<String> {
    let mut value = serde_json::to_value(report).context("JSON Serialisation Error")?;
    if let Some(findings) = value.get_mut("findings").and_then(|v| v.as_array_mut()) {
        for (slot, finding) in findings.iter_mut().zip(report.findings.iter()) {
            if let Some(object) = slot.as_object_mut() {
                object.insert(
                    "fingerprint".to_string(),
                    serde_json::Value::String(finding.fingerprint()),
                );
            }
        }
    }
    serde_json::to_string_pretty(&value).context("JSON Serialisation Error")
}

pub fn sarif(report: &AuditReport) -> Result<String> {
    let rules: Vec<serde_json::Value> = {
        let mut seen: BTreeMap<&str, &Finding> = BTreeMap::new();
        for finding in &report.findings {
            seen.entry(finding.rule.as_str()).or_insert(finding);
        }
        seen.values()
            .map(|finding| {
                serde_json::json!({
                    "id": finding.rule,
                    "name": finding.rule,
                    "shortDescription": { "text": finding.title },
                    "fullDescription": { "text": finding.description },
                    "help": { "text": finding.remediation },
                    "properties": {
                        "category": finding.category.slug(),
                        "tags": finding.cwe.map(|c| vec![format!("CWE-{c}")]).unwrap_or_default(),
                    }
                })
            })
            .collect()
    };

    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                _ => "note",
            };
            let locations: Vec<serde_json::Value> = finding
                .evidence
                .iter()
                .map(|evidence| {
                    serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": { "uri": evidence.file },
                            "region": { "startLine": evidence.line.unwrap_or(1).max(1) }
                        }
                    })
                })
                .collect();
            serde_json::json!({
                "ruleId": finding.rule,
                "level": level,
                "message": { "text": format!("{} — {}", finding.title, finding.remediation) },
                "locations": locations,
                "partialFingerprints": { "deadboltFingerprint": finding.fingerprint() }
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "deadbolt",
                "version": report.meta.version,
                "informationUri": "https://github.com/deadbolt-audit/deadbolt",
                "rules": rules
            }},
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).context("SARIF Serialisation Error")
}

pub fn write_file(directory: &Path, name: &str, content: &str) -> Result<()> {
    std::fs::create_dir_all(directory)
        .with_context(|| format!("Could Not Create Directory: {}", directory.display()))?;
    let path = directory.join(name);
    std::fs::write(&path, content)
        .with_context(|| format!("Could Not Write File: {}", path.display()))?;
    Ok(())
}

/// GitHub Actions workflow commands.
///
/// Written to stdout inside a job, these place the finding on the exact line of
/// the pull-request diff. A report nobody opens changes nothing; an annotation
/// next to the line does.
pub fn github(report: &AuditReport) -> String {
    let mut out = String::new();
    for finding in &report.findings {
        let level = match finding.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            _ => "notice",
        };
        let (file, line) = match finding.evidence.first() {
            Some(evidence) if !evidence.file.starts_with('<') => {
                (evidence.file.clone(), evidence.line)
            }
            _ => continue,
        };
        // Workflow commands are newline-delimited, so the message has to be flat.
        let escape = |text: &str| {
            text.replace('%', "%25")
                .replace('\r', "%0D")
                .replace('\n', "%0A")
                .replace(',', "%2C")
                .replace("::", ":")
        };
        out.push_str(&format!(
            "::{level} file={file}{line},title={title}::{body}\n",
            line = line.map(|n| format!(",line={n}")).unwrap_or_default(),
            title = escape(&format!("deadbolt {} — {}", finding.rule, finding.title)),
            body = escape(&if finding.remediation.is_empty() {
                finding.impact.clone()
            } else {
                format!("{} Fix: {}", finding.impact, finding.remediation)
            }),
        ));
    }
    out
}

/// GitLab Code Quality report.
///
/// GitLab renders this format inline on the merge request, using `fingerprint`
/// to tell an existing finding from a new one across pipelines.
pub fn gitlab(report: &AuditReport) -> Result<String> {
    let entries: Vec<serde_json::Value> = report
        .findings
        .iter()
        .filter_map(|finding| {
            let evidence = finding.evidence.first()?;
            if evidence.file.starts_with('<') {
                return None;
            }
            Some(serde_json::json!({
                "description": format!("{} — {}", finding.rule, finding.title),
                "check_name": finding.rule,
                "fingerprint": finding.fingerprint(),
                "severity": match finding.severity {
                    Severity::Critical => "blocker",
                    Severity::High => "critical",
                    Severity::Medium => "major",
                    Severity::Low => "minor",
                    Severity::Info => "info",
                },
                "location": {
                    "path": evidence.file,
                    "lines": { "begin": evidence.line.unwrap_or(1) }
                }
            }))
        })
        .collect();
    serde_json::to_string_pretty(&entries).context("GitLab Serialisation Error")
}
