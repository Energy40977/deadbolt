use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{AuditReport, Severity};

pub const FILE_NAME: &str = ".deadbolt-history.jsonl";
/// Keeping every run forever makes the file unreviewable; this is plenty for a
/// trend line and keeps the diff small.
const MAX_ENTRIES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub at: String,
    pub score: f64,
    pub grade: String,
    pub mode: String,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub findings: usize,
    #[serde(default)]
    pub packages: usize,
    #[serde(default)]
    pub lines: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub commit: String,
}

pub fn path(root: &Path) -> PathBuf {
    root.join(FILE_NAME)
}

fn count(report: &AuditReport, severity: Severity) -> usize {
    report
        .findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .count()
}

fn head_commit(root: &Path) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn entry_from(report: &AuditReport, root: &Path) -> Entry {
    Entry {
        at: report.meta.started_at.clone(),
        score: report.score.overall,
        grade: report.score.grade.clone(),
        mode: report.meta.mode.clone(),
        critical: count(report, Severity::Critical),
        high: count(report, Severity::High),
        medium: count(report, Severity::Medium),
        low: count(report, Severity::Low),
        findings: report.findings.len(),
        packages: report.packages.len(),
        lines: report.stack.total_lines,
        commit: head_commit(root),
    }
}

pub fn load(root: &Path) -> Vec<Entry> {
    let body = match std::fs::read_to_string(path(root)) {
        Ok(body) => body,
        Err(_) => return Vec::new(),
    };
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Entry>(line).ok())
        .collect()
}

/// Appends one run, trimming the oldest entries when the file grows too long.
pub fn append(root: &Path, entry: &Entry) -> Result<()> {
    let mut entries = load(root);
    entries.push(entry.clone());
    if entries.len() > MAX_ENTRIES {
        let excess = entries.len() - MAX_ENTRIES;
        entries.drain(0..excess);
    }
    let body = entries
        .iter()
        .map(|item| serde_json::to_string(item).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path(root), format!("{body}\n"))
        .with_context(|| format!("Could Not Write History: {}", path(root).display()))
}

/// Only comparable runs count: a `scan` produces fewer findings than an `audit`,
/// so mixing modes would make the ratchet fire at random.
fn last_comparable<'a>(entries: &'a [Entry], mode: &str) -> Option<&'a Entry> {
    entries.iter().rev().find(|entry| entry.mode == mode)
}

pub struct Verdict {
    pub previous: Option<Entry>,
    pub delta: f64,
    /// Set when the score fell by more than the allowed tolerance.
    pub regression: Option<String>,
}

/// Compares against the last run of the same mode.
pub fn check(entries: &[Entry], current: &Entry, tolerance: f64) -> Verdict {
    let previous = last_comparable(entries, &current.mode).cloned();
    let delta = previous
        .as_ref()
        .map(|entry| current.score - entry.score)
        .unwrap_or(0.0);

    let regression = previous.as_ref().and_then(|entry| {
        if delta < -tolerance {
            Some(format!(
                "Score {:.1} -> {:.1} ({:+.1}) — Allowed Drop Is {:.1}. Previous Run: {} ({})",
                entry.score,
                current.score,
                delta,
                tolerance,
                entry.at,
                if entry.commit.is_empty() {
                    "commit unknown".to_string()
                } else {
                    entry.commit.clone()
                }
            ))
        } else {
            None
        }
    });

    Verdict {
        previous,
        delta,
        regression,
    }
}

/// Inline SVG sparkline for the HTML report — no external chart library.
pub fn sparkline(entries: &[Entry]) -> String {
    let points: Vec<&Entry> = entries.iter().rev().take(40).rev().collect();
    if points.len() < 2 {
        return String::new();
    }

    let width = 480.0f64;
    let height = 90.0f64;
    let step = width / (points.len() - 1) as f64;

    let coords: Vec<String> = points
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let x = index as f64 * step;
            let y = height - (entry.score / 100.0 * height);
            format!("{x:.1},{y:.1}")
        })
        .collect();

    let last = points.last().map(|entry| entry.score).unwrap_or(0.0);
    let colour = if last >= 75.0 {
        "#059669"
    } else if last >= 50.0 {
        "#d97706"
    } else {
        "#dc2626"
    };

    format!(
        r#"<svg viewBox="0 0 {width:.0} {height:.0}" width="100%" height="90" preserveAspectRatio="none" role="img" aria-label="Score Trend">
<polyline fill="none" stroke="{colour}" stroke-width="2" points="{}"/>
<polyline fill="{colour}" fill-opacity="0.12" stroke="none" points="0,{height:.0} {} {width:.0},{height:.0}"/>
</svg>"#,
        coords.join(" "),
        coords.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(score: f64, mode: &str) -> Entry {
        Entry {
            at: "2026-07-28T00:00:00Z".into(),
            score,
            grade: "C".into(),
            mode: mode.into(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            findings: 0,
            packages: 0,
            lines: 1000,
            commit: "abc1234".into(),
        }
    }

    #[test]
    fn a_falling_score_is_a_regression() {
        let history = vec![entry(70.0, "audit")];
        let verdict = check(&history, &entry(60.0, "audit"), 1.0);
        assert!(verdict.regression.is_some());
        assert!((verdict.delta + 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_small_drop_inside_tolerance_is_allowed() {
        let history = vec![entry(70.0, "audit")];
        assert!(check(&history, &entry(69.5, "audit"), 1.0)
            .regression
            .is_none());
    }

    #[test]
    fn improving_is_never_a_regression() {
        let history = vec![entry(40.0, "audit")];
        assert!(check(&history, &entry(80.0, "audit"), 1.0)
            .regression
            .is_none());
    }

    #[test]
    fn modes_are_compared_only_against_themselves() {
        let history = vec![entry(95.0, "scan"), entry(60.0, "audit")];
        assert!(check(&history, &entry(59.0, "audit"), 1.0)
            .regression
            .is_none());
        assert!(check(&history, &entry(50.0, "audit"), 1.0)
            .regression
            .is_some());
    }

    #[test]
    fn the_first_run_cannot_regress() {
        assert!(check(&[], &entry(10.0, "audit"), 1.0).regression.is_none());
    }

    #[test]
    fn sparkline_needs_at_least_two_points() {
        assert!(sparkline(&[entry(50.0, "audit")]).is_empty());
        let svg = sparkline(&[entry(50.0, "audit"), entry(60.0, "audit")]);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("polyline"));
    }
}
