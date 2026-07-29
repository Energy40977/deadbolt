use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::discover::Inventory;
use crate::model::Finding;

/// Repo-level findings have no line to attribute; they belong to the full audit.
const PROJECT_SCOPE: &str = "<project>";

#[derive(Debug, Clone)]
pub struct ChangedFile {
    /// Kept for diagnostics; the map key carries the same value.
    #[allow(dead_code)]
    pub path: String,
    /// Line numbers added or modified by this change, in the new file.
    pub added_lines: BTreeSet<u32>,
    pub is_new: bool,
}

#[derive(Debug, Clone)]
pub struct ChangeSet {
    /// Human-readable description of what was compared.
    pub range: String,
    pub files: BTreeMap<String, ChangedFile>,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn added_line_count(&self) -> usize {
        self.files.values().map(|file| file.added_lines.len()).sum()
    }

    /// A finding belongs to this change when it sits on an added line, or in a
    /// newly added file, or carries no line at all but touches a changed file.
    pub fn covers(&self, finding: &Finding) -> bool {
        let evidence = match finding.evidence.first() {
            Some(evidence) => evidence,
            None => return false,
        };
        if evidence.file == PROJECT_SCOPE {
            return false;
        }
        let changed = match self.files.get(&evidence.file) {
            Some(changed) => changed,
            None => return false,
        };
        if changed.is_new {
            return true;
        }
        match evidence.line {
            Some(line) if line > 0 => changed
                .added_lines
                .iter()
                .any(|added| added.abs_diff(line) <= 12),
            _ => true,
        }
    }
}

fn run_git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| format!("Could Not Run git {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "git {}: {}",
            args.join(" "),
            stderr.trim().lines().last().unwrap_or("Reason Unknown")
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn is_repository(root: &Path) -> bool {
    run_git(root, &["rev-parse", "--git-dir"]).is_ok()
}

/// Resolves the merge base with `base`, trying the remote-tracking ref too.
fn merge_base(root: &Path, base: &str) -> Result<String> {
    let remote = format!("origin/{base}");
    for candidate in [base, remote.as_str()] {
        if let Ok(output) = run_git(root, &["merge-base", candidate, "HEAD"]) {
            let resolved = output.trim().to_string();
            if !resolved.is_empty() {
                return Ok(resolved);
            }
        }
    }
    anyhow::bail!("No merge-base found for '{base}' (does the branch exist?)")
}

/// Builds the change set. `base = None` means staged changes (pre-commit).
pub fn collect(root: &Path, base: Option<&str>) -> Result<ChangeSet> {
    if !is_repository(root) {
        anyhow::bail!("Not A Git Repository: {}", root.display());
    }

    let (args, range): (Vec<String>, String) = match base {
        Some(base) => {
            let resolved = merge_base(root, base)?;
            (
                vec![
                    "diff".into(),
                    "--no-color".into(),
                    "--unified=0".into(),
                    "--diff-filter=ACMR".into(),
                    format!("{resolved}..HEAD"),
                ],
                format!("{base}..HEAD"),
            )
        }
        None => (
            vec![
                "diff".into(),
                "--cached".into(),
                "--no-color".into(),
                "--unified=0".into(),
                "--diff-filter=ACMR".into(),
            ],
            "staged".to_string(),
        ),
    };

    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let patch = run_git(root, &borrowed)?;

    Ok(ChangeSet {
        range,
        files: parse_patch(&patch),
    })
}

fn parse_patch(patch: &str) -> BTreeMap<String, ChangedFile> {
    let mut files: BTreeMap<String, ChangedFile> = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let path = rest
                .split(" b/")
                .nth(1)
                .map(|path| path.trim().replace('\\', "/"));
            current = path.clone();
            if let Some(path) = path {
                files.entry(path.clone()).or_insert(ChangedFile {
                    path,
                    added_lines: BTreeSet::new(),
                    is_new: false,
                });
            }
            continue;
        }

        let path = match &current {
            Some(path) => path.clone(),
            None => continue,
        };

        if line.starts_with("new file mode") {
            if let Some(entry) = files.get_mut(&path) {
                entry.is_new = true;
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("@@ ") {
            if let Some(new_part) = rest.split('+').nth(1) {
                let spec = new_part.split(' ').next().unwrap_or("");
                let mut pieces = spec.split(',');
                let start: u32 = pieces.next().unwrap_or("0").parse().unwrap_or(0);
                let count: u32 = pieces.next().unwrap_or("1").parse().unwrap_or(1);
                if let Some(entry) = files.get_mut(&path) {
                    for offset in 0..count.max(1) {
                        entry.added_lines.insert(start + offset);
                    }
                }
            }
        }
    }

    files.retain(|_, file| file.is_new || !file.added_lines.is_empty());
    files
}

/// Narrows an inventory to the changed files, so scanning and AI lenses only
/// look at what the change touches.
pub fn restrict(inventory: Inventory, changes: &ChangeSet) -> Inventory {
    let files = inventory
        .files
        .into_iter()
        .filter(|file| changes.files.contains_key(&file.rel_path))
        .collect();
    Inventory { files, ..inventory }
}

/// Keeps only findings introduced by the change; returns `(kept, dropped)`.
pub fn filter_findings(findings: Vec<Finding>, changes: &ChangeSet) -> (Vec<Finding>, usize) {
    let total = findings.len();
    let kept: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| changes.covers(finding))
        .collect();
    let dropped = total - kept.len();
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Evidence, Finding, Severity};

    fn change_set(patch: &str) -> ChangeSet {
        ChangeSet {
            range: "test".to_string(),
            files: parse_patch(patch),
        }
    }

    fn finding_at(file: &str, line: Option<u32>) -> Finding {
        Finding::builder("R-1", Category::Secrets, Severity::High)
            .title("t")
            .evidence(Evidence::new(file, line, "x"))
            .build()
    }

    const PATCH: &str = "diff --git a/app/a.py b/app/a.py\n\
index 111..222 100644\n\
--- a/app/a.py\n\
+++ b/app/a.py\n\
@@ -10,0 +11,3 @@ def f():\n\
+one\n+two\n+three\n\
diff --git a/app/new.py b/app/new.py\n\
new file mode 100644\n\
--- /dev/null\n\
+++ b/app/new.py\n\
@@ -0,0 +1,2 @@\n\
+a\n+b\n";

    #[test]
    fn parses_added_line_ranges() {
        let changes = change_set(PATCH);
        let modified = &changes.files["app/a.py"];
        assert_eq!(
            modified.added_lines.iter().copied().collect::<Vec<u32>>(),
            vec![11, 12, 13]
        );
        assert!(!modified.is_new);
        assert!(changes.files["app/new.py"].is_new);
        assert_eq!(changes.added_line_count(), 5);
    }

    #[test]
    fn covers_findings_on_added_lines_only() {
        let changes = change_set(PATCH);
        assert!(changes.covers(&finding_at("app/a.py", Some(12))));
        assert!(changes.covers(&finding_at("app/a.py", Some(20))));
        assert!(!changes.covers(&finding_at("app/a.py", Some(400))));
        assert!(!changes.covers(&finding_at("app/other.py", Some(1))));
    }

    #[test]
    fn everything_in_a_new_file_counts() {
        let changes = change_set(PATCH);
        assert!(changes.covers(&finding_at("app/new.py", Some(999))));
    }

    #[test]
    fn repo_level_findings_are_excluded_from_diff_scope() {
        let changes = change_set(PATCH);
        assert!(!changes.covers(&finding_at(PROJECT_SCOPE, None)));
    }

    #[test]
    fn pure_deletions_are_dropped() {
        let patch = "diff --git a/gone.py b/gone.py\n\
deleted file mode 100644\n\
--- a/gone.py\n\
+++ /dev/null\n";
        assert!(change_set(patch).is_empty());
    }
}
