use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use regex::{Regex, RegexSet};

use crate::model::{Category, Confidence, Evidence, Finding, Origin, Severity};

/// Coarse pre-filter handed to `git log -G` so git discards irrelevant commits
/// before we ever see them. Deliberately broad — precision comes from the rules.
const GIT_PREFILTER: &str = "(password|passwd|secret|api[-_]?key|apikey|token|credential|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|sk_live_|glpat-|ghp_|AGE-SECRET-KEY)";

/// Patterns that mark a *value* as a credential. Kept separate from the main
/// catalogue because history lines carry no surrounding context to judge by.
const HISTORY_RULES: &[(&str, &str, Severity, &str)] = &[
    (
        "DB-HIST-001",
        r#"(?i)\b(password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|jwt[_-]?secret)\s*[:=]\s*["'][^"']{8,}["']"#,
        Severity::Critical,
        "Secret In History",
    ),
    (
        "DB-HIST-002",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AGE-SECRET-KEY-1[0-9A-Z]{20,}",
        Severity::Critical,
        "Private Key In History",
    ),
    (
        "DB-HIST-003",
        r"\bAKIA[0-9A-Z]{16}\b|\b(?:sk|rk)_live_[A-Za-z0-9]{16,}|\bgh[pousr]_[A-Za-z0-9]{30,}|\bglpat-[A-Za-z0-9_\-]{16,}|\bxox[baprs]-[A-Za-z0-9\-]{10,}|\bAIza[0-9A-Za-z_\-]{30,}",
        Severity::Critical,
        "Provider Key In History",
    ),
    (
        "DB-HIST-004",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@\s/]+:[^@\s]{3,}@",
        Severity::High,
        "Connection String Password In History",
    ),
];

/// Same placeholder guard the live rules use, so `password = "changeme"` in an
/// old commit does not become a critical finding.
const PLACEHOLDER: &str = r"(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_-]?|xxx|todo|fake|test[_-]?only|synthetic|redacted|\{\{|\$\{|<[a-z_]+>|os\.environ|getenv|process\.env|dotenv)";

pub struct Options {
    /// How many commits to walk. History scans are the slowest check here.
    pub max_commits: usize,
    /// Upper bound on diff bytes processed, so a huge repository cannot hang CI.
    pub max_bytes: usize,
    /// Skip anything still visible in the working tree — the normal scan already
    /// reports those, and duplicating them buries the history-only findings.
    pub skip_present_in_tree: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_commits: 1500,
            max_bytes: 24 * 1024 * 1024,
            skip_present_in_tree: true,
        }
    }
}

#[derive(Debug, Clone)]
struct Commit {
    sha: String,
    author: String,
    date: String,
    subject: String,
}

impl Default for Commit {
    fn default() -> Self {
        Self {
            sha: "unknown".to_string(),
            author: String::new(),
            date: String::new(),
            subject: String::new(),
        }
    }
}

struct Matcher {
    set: RegexSet,
    rules: Vec<(&'static str, Regex, Severity, &'static str)>,
    placeholder: Regex,
}

impl Matcher {
    fn new() -> Result<Self> {
        let rules: Vec<(&'static str, Regex, Severity, &'static str)> = HISTORY_RULES
            .iter()
            .map(|(id, pattern, severity, title)| {
                Ok((
                    *id,
                    Regex::new(pattern).with_context(|| format!("{id} Pattern Error"))?,
                    *severity,
                    *title,
                ))
            })
            .collect::<Result<_>>()?;
        let set = RegexSet::new(HISTORY_RULES.iter().map(|(_, pattern, _, _)| *pattern))?;
        Ok(Self {
            set,
            rules,
            placeholder: Regex::new(PLACEHOLDER)?,
        })
    }

    fn check(&self, line: &str) -> Option<(&'static str, Severity, &'static str)> {
        if !self.set.is_match(line) || self.placeholder.is_match(line) {
            return None;
        }
        self.rules
            .iter()
            .find(|(_, pattern, _, _)| pattern.is_match(line))
            .map(|(id, _, severity, title)| (*id, *severity, *title))
    }
}

/// Masks the credential so the report never republishes it.
fn redact(line: &str) -> String {
    let trimmed = line.trim();
    let masked = match trimmed.find(['=', ':']) {
        Some(index) if index + 1 < trimmed.len() => {
            format!("{}= «REDACTED»", &trimmed[..index])
        }
        _ => "«REDACTED»".to_string(),
    };
    masked.chars().take(120).collect()
}

fn tree_contains(root: &Path, needle: &str) -> bool {
    Command::new("git")
        .args(["grep", "-qF", needle])
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn scan(root: &Path, options: &Options) -> Result<(Vec<Finding>, Vec<String>)> {
    let matcher = Matcher::new()?;
    let mut warnings = Vec::new();

    let output = Command::new("git")
        .args([
            "log",
            "--all",
            "--no-color",
            "--no-merges",
            &format!("--max-count={}", options.max_commits),
            &format!("-G{GIT_PREFILTER}"),
            "--pretty=format:%x00commit%x00%H%x00%an%x00%aI%x00%s",
            "-p",
            "--unified=0",
        ])
        .current_dir(root)
        .output()
        .context("Could Not Run git log")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "git log Failed: {}",
            stderr.trim().lines().last().unwrap_or("Reason Unknown")
        );
    }

    if output.stdout.len() >= options.max_bytes {
        warnings.push(format!(
            "History Scan Truncated ({} MB Limit) — Lower --history-commits For A Deeper Scan",
            options.max_bytes / (1024 * 1024)
        ));
    }
    let body =
        String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(options.max_bytes)]);

    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut commit = Commit::default();
    let mut file = String::from("unknown");

    for line in body.lines() {
        if let Some(rest) = line.strip_prefix('\0') {
            let fields: Vec<&str> = rest.split('\0').collect();
            if fields.len() >= 5 && fields[0] == "commit" {
                commit = Commit {
                    sha: fields[1].chars().take(12).collect(),
                    author: fields[2].to_string(),
                    date: fields[3].chars().take(10).collect(),
                    subject: fields[4].chars().take(80).collect(),
                };
            }
            continue;
        }

        if let Some(path) = line.strip_prefix("+++ b/") {
            file = path.trim().to_string();
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        let added = &line[1..];
        if added.len() > 800 {
            continue; // minified or generated blob
        }

        let (rule, severity, title) = match matcher.check(added) {
            Some(hit) => hit,
            None => continue,
        };

        let normalized: String = added.chars().filter(|c| !c.is_whitespace()).collect();
        let key = format!("{rule}|{file}|{normalized}");
        if !seen.insert(key) {
            continue;
        }

        if options.skip_present_in_tree {
            let probe: String = added.trim().chars().take(60).collect();
            if probe.len() >= 12 && tree_contains(root, &probe) {
                continue; // still in the tree: the normal scan reports it
            }
        }

        findings.push(
            Finding::builder(rule, Category::Secrets, severity)
                .title(format!("{title}: {file}"))
                .description(format!(
                    "Commit {} ({}, {}) — «{}»",
                    commit.sha, commit.author, commit.date, commit.subject
                ))
                .impact(
                    "The value is absent from the working tree but remains in history: it exists in \
every clone, every fork and every CI cache. Anyone who ever had access to the repository can obtain it.",
                )
                .remediation(
                    "Do not rewrite history — **rotate the value**. Deletion offers no protection \
because existing clones cannot be reached. After rotating, check the provider log for signs \
of misuse.",
                )
                .origin(Origin::Static)
                .confidence(Confidence::Confirmed)
                .evidence(Evidence::new(
                    &file,
                    None,
                    format!("{} @ {}", redact(added), commit.sha),
                ))
                .cwe(798)
                .policy("SEC-03, b.6.2/3")
                .build(),
        );
    }

    Ok((findings, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_real_credentials_and_ignores_placeholders() {
        let matcher = Matcher::new().unwrap();
        assert!(matcher
            .check(&format!(
                r#"API_KEY = "{}""#,
                ["sk", "live", "aB3xY9zQ7mN2pL5kR8w"].join("_")
            ))
            .is_some());
        assert!(matcher.check("-----BEGIN RSA PRIVATE KEY-----").is_some());
        assert!(matcher
            .check("DATABASE_URL = postgres://user:realpass123@db/app")
            .is_some());

        assert!(matcher.check(r#"password = "changeme""#).is_none());
        assert!(matcher.check(r#"password = os.environ["PW"]"#).is_none());
        assert!(matcher.check("nothing interesting here").is_none());
    }

    #[test]
    fn redaction_keeps_the_name_and_drops_the_value() {
        let masked = redact(&format!(
            r#"  API_KEY = "{}"  "#,
            ["sk", "live", "abcdefghijklmnop"].join("_")
        ));
        assert!(masked.contains("API_KEY"));
        assert!(!masked.contains("sk_live"));
    }

    #[test]
    fn redaction_handles_a_value_with_no_separator() {
        assert_eq!(redact("-----BEGIN RSA PRIVATE KEY-----"), "«REDACTED»");
    }
}
