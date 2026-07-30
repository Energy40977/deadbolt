use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::{AuditReport, Severity};

#[derive(Debug)]
pub struct Member {
    pub name: String,
    pub path: PathBuf,
    pub report: AuditReport,
    pub blocking: usize,
}

impl Member {
    fn count(&self, severity: Severity) -> usize {
        self.report
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }

    /// Ranking key: unresolved risk weighted by severity, then by score.
    /// Deliberately not the score alone — a small repository with two criticals
    /// needs attention before a large one with a hundred lows.
    pub fn risk(&self) -> f64 {
        self.count(Severity::Critical) as f64 * 40.0
            + self.count(Severity::High) as f64 * 12.0
            + self.count(Severity::Medium) as f64 * 3.0
            + self.count(Severity::Low) as f64
    }
}

/// Reads a newline-separated list of repository paths; `#` starts a comment.
pub fn read_list(path: &Path) -> Result<Vec<PathBuf>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("Could Not Read List: {}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));

    Ok(body
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(|line| {
            let candidate = PathBuf::from(line);
            if candidate.is_absolute() {
                candidate
            } else {
                base.join(candidate)
            }
        })
        .collect())
}

fn grade_marker(score: f64) -> &'static str {
    match score {
        s if s >= 75.0 => "●",
        s if s >= 50.0 => "◐",
        _ => "○",
    }
}

pub fn render_terminal(members: &[Member]) -> String {
    let mut out = String::new();
    let rule = "─".repeat(78);

    out.push_str(&format!(
        "\n  deadbolt — Portfolio ({} Projects)\n  {rule}\n",
        members.len()
    ));
    out.push_str(&format!(
        "  {:<22} {:>6} {:>4} {:>5} {:>5} {:>5} {:>7} {:>6}\n",
        "PROJECT", "SCORE", "", "CRIT", "HIGH", "MED", "BLOCK", "kLOC"
    ));
    out.push_str(&format!("  {rule}\n"));

    for member in members {
        let name: String = member.name.chars().take(22).collect();
        out.push_str(&format!(
            "  {:<22} {:>6.1} {:>4} {:>5} {:>5} {:>5} {:>7} {:>6}\n",
            name,
            member.report.score.overall,
            grade_marker(member.report.score.overall),
            member.count(Severity::Critical),
            member.count(Severity::High),
            member.count(Severity::Medium),
            member.blocking,
            if member.report.stack.total_lines < 1000 {
                format!("{:.1}", member.report.stack.total_lines as f64 / 1000.0)
            } else {
                (member.report.stack.total_lines / 1000).to_string()
            },
        ));
    }

    out.push_str(&format!("  {rule}\n"));

    let total_blocking: usize = members.iter().map(|member| member.blocking).sum();
    let worst = members.first();
    if let Some(worst) = worst {
        out.push_str(&format!(
            "  Highest Risk: {} (Score {:.1})\n",
            worst.name, worst.report.score.overall
        ));
    }
    out.push_str(&format!("  Blocking Findings (Total): {total_blocking}\n"));

    let shared = shared_rules(members);
    if !shared.is_empty() {
        out.push_str("\n  Defects Repeated Across Projects:\n");
        for (rule, (repos, title)) in shared.iter().take(8) {
            out.push_str(&format!(
                "    {rule:<16} {} Projects — {}\n",
                repos.len(),
                title.chars().take(60).collect::<String>()
            ));
        }
    }
    out.push('\n');
    out
}

/// Rules that appear in more than one repository, with the projects involved.
pub fn shared_rules(members: &[Member]) -> Vec<(String, (Vec<String>, String))> {
    let mut index: BTreeMap<String, (Vec<String>, String)> = BTreeMap::new();

    for member in members {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for finding in &member.report.findings {
            if finding.severity > Severity::Medium {
                continue; // low/info noise is not a portfolio-level pattern
            }
            seen.entry(finding.rule.clone())
                .or_insert_with(|| finding.title.clone());
        }
        for (rule, title) in seen {
            let entry = index.entry(rule).or_insert_with(|| (Vec::new(), title));
            entry.0.push(member.name.clone());
        }
    }

    let mut shared: Vec<(String, (Vec<String>, String))> = index
        .into_iter()
        .filter(|(_, (repos, _))| repos.len() > 1)
        .collect();
    shared.sort_by_key(|entry| std::cmp::Reverse(entry.1 .0.len()));
    shared
}

pub fn render_markdown(members: &[Member], generated_at: &str) -> String {
    let mut out = String::new();
    out.push_str("# Portfolio Audit\n\n");
    out.push_str(&format!(
        "| | |\n|---|---|\n| Projects | {} |\n| Date | {} |\n\n",
        members.len(),
        generated_at
    ));

    out.push_str("## Ranking\n\nBy risk (weighted by severity), highest first.\n\n");
    out.push_str("| # | Project | Score | CRIT | HIGH | MED | Blocking | kLOC | Stack |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|\n");
    for (index, member) in members.iter().enumerate() {
        let stack: Vec<String> = member
            .report
            .stack
            .languages
            .iter()
            .take(3)
            .map(|language| language.name.clone())
            .collect();
        out.push_str(&format!(
            "| {} | `{}` | **{:.1}** ({}) | {} | {} | {} | {} | {} | {} |\n",
            index + 1,
            member.name,
            member.report.score.overall,
            member.report.score.grade,
            member.count(Severity::Critical),
            member.count(Severity::High),
            member.count(Severity::Medium),
            member.blocking,
            member.report.stack.total_lines / 1000,
            stack.join(", ")
        ));
    }
    out.push('\n');

    let shared = shared_rules(members);
    if !shared.is_empty() {
        out.push_str("## Repeated Defects\n\n");
        out.push_str(
            "The same defect in several projects is not a set of separate tasks but **one \
decision** (a shared template, a shared library, a shared configuration).\n\n",
        );
        out.push_str("| Rule | Projects | Problem |\n|---|---|---|\n");
        for (rule, (repos, title)) in shared.iter().take(20) {
            out.push_str(&format!("| `{rule}` | {} | {title} |\n", repos.join(", ")));
        }
        out.push('\n');
    }

    out.push_str("## Per-Project Summary\n\n");
    for member in members {
        out.push_str(&format!(
            "### {} — {:.1}/100 ({})\n\n",
            member.name, member.report.score.overall, member.report.score.grade
        ));
        out.push_str(&format!("- Yol: `{}`\n", member.path.display()));
        out.push_str(&format!(
            "- Findings: {} · Blocking: {}\n",
            member.report.findings.len(),
            member.blocking
        ));
        if !member.report.packs.is_empty() {
            let violated: usize = member.report.packs.iter().map(|pack| pack.violated).sum();
            out.push_str(&format!("- Violated Compliance Controls: {violated}\n"));
        }
        let top: Vec<String> = member
            .report
            .findings
            .iter()
            .filter(|finding| finding.severity <= Severity::High)
            .take(5)
            .map(|finding| {
                format!(
                    "  - **{}** `{}` — {}",
                    finding.severity.label(),
                    finding.primary_location(),
                    finding.title
                )
            })
            .collect();
        if !top.is_empty() {
            out.push_str("- Most Severe Findings:\n");
            out.push_str(&top.join("\n"));
            out.push('\n');
        }
        out.push('\n');
    }

    out
}

pub fn render_json(members: &[Member], generated_at: &str) -> Result<String> {
    let payload = serde_json::json!({
        "generated_at": generated_at,
        "projects": members
            .iter()
            .map(|member| serde_json::json!({
                "name": member.name,
                "path": member.path.display().to_string(),
                "score": member.report.score.overall,
                "grade": member.report.score.grade,
                "blocking": member.blocking,
                "risk": member.risk(),
                "counts": member.report.counts(),
                "lines": member.report.stack.total_lines,
                "languages": member.report.stack.languages
                    .iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
                "warnings": member.report.meta.warnings,
            }))
            .collect::<Vec<_>>(),
        "shared_rules": shared_rules(members)
            .into_iter()
            .map(|(rule, (repos, title))| serde_json::json!({
                "rule": rule, "projects": repos, "title": title
            }))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&payload).map_err(Into::into)
}

/// Sorts in place: highest risk first, score as the tie-break.
pub fn rank(members: &mut [Member]) {
    members.sort_by(|a, b| {
        b.risk()
            .partial_cmp(&a.risk())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                a.report
                    .score
                    .overall
                    .partial_cmp(&b.report.score.overall)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Evidence, Finding, ReportMeta, StackProfile};

    fn member(name: &str, criticals: usize, highs: usize, lines: usize) -> Member {
        let mut findings = Vec::new();
        for index in 0..criticals {
            findings.push(
                Finding::builder("DB-SEC-001", Category::Secrets, Severity::Critical)
                    .title("Password Or Key Written Directly Into The Code")
                    .evidence(Evidence::new(format!("a{index}.py"), Some(1), "x"))
                    .build(),
            );
        }
        for index in 0..highs {
            findings.push(
                Finding::builder("DB-DAT-003", Category::ErrorHandling, Severity::High)
                    .title("Error Caught But Never Recorded")
                    .evidence(Evidence::new(format!("b{index}.py"), Some(1), "y"))
                    .build(),
            );
        }

        let mut report = AuditReport {
            meta: ReportMeta {
                tool: "deadbolt".into(),
                version: "0".into(),
                target: name.into(),
                project: name.into(),
                started_at: "2026-07-28T00:00:00Z".into(),
                duration_ms: 0,
                mode: "audit".into(),
                ai_enabled: false,
                research_enabled: false,
                lenses_run: Vec::new(),
                packs_run: Vec::new(),
                ai_cost_usd: 0.0,
                warnings: Vec::new(),
            },
            stack: StackProfile {
                total_lines: lines,
                ..Default::default()
            },
            score: Default::default(),
            findings,
            packages: Vec::new(),
            controls: Vec::new(),
            packs: Vec::new(),
        };
        report.compute_score();

        Member {
            name: name.to_string(),
            path: PathBuf::from(name),
            blocking: criticals + highs,
            report,
        }
    }

    #[test]
    fn ranking_puts_severity_before_size() {
        let mut members = vec![member("big", 0, 3, 200_000), member("small", 2, 0, 2_000)];
        rank(&mut members);
        assert_eq!(members[0].name, "small");
    }

    #[test]
    fn shared_rules_only_reports_repeated_defects() {
        let members = vec![member("a", 1, 1, 1000), member("b", 1, 0, 1000)];
        let shared = shared_rules(&members);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].0, "DB-SEC-001");
        assert_eq!(shared[0].1 .0.len(), 2);
    }

    #[test]
    fn markdown_lists_every_project() {
        let members = vec![member("a", 1, 0, 1000), member("b", 0, 1, 1000)];
        let markdown = render_markdown(&members, "now");
        assert!(markdown.contains("`a`"));
        assert!(markdown.contains("`b`"));
        assert!(markdown.contains("Portfolio Audit"));
    }

    #[test]
    fn json_is_machine_readable() {
        let members = vec![member("a", 1, 0, 1000)];
        let value: serde_json::Value =
            serde_json::from_str(&render_json(&members, "now").unwrap()).unwrap();
        assert_eq!(value["projects"][0]["name"], "a");
        assert!(value["projects"][0]["risk"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn list_file_skips_comments_and_resolves_relative_paths() {
        let dir = std::env::temp_dir().join("deadbolt-portfolio-test");
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("repos.txt");

        // What counts as absolute is platform-specific: `/abs/two` is rooted but
        // not absolute on Windows, where a path needs a drive. Build one from the
        // platform itself so the test states the rule rather than one OS's spelling
        // of it.
        let absolute = std::env::temp_dir().join("deadbolt-portfolio-absolute");
        assert!(
            absolute.is_absolute(),
            "temp_dir is absolute on every platform"
        );
        std::fs::write(
            &list,
            format!("# comment\n./one\n\n{}   # trailing\n", absolute.display()),
        )
        .unwrap();

        let paths = read_list(&list).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(
            paths[0].ends_with("one") && paths[0].is_absolute(),
            "a relative entry resolves against the list file's directory: {:?}",
            paths[0]
        );
        assert_eq!(paths[1], absolute, "an absolute entry is taken as written");
    }
}
