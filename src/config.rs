use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub const FILE_NAME: &str = ".deadbolt.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub project: ProjectSettings,
    #[serde(default)]
    pub gates: GateSettings,
    #[serde(default)]
    pub paths: PathSettings,
    #[serde(default)]
    pub scan: ScanSettings,
    #[serde(default)]
    pub ai: AiSettings,
    #[serde(default)]
    pub chains: ChainSettings,
    #[serde(default)]
    pub reach: ReachSettings,
    #[serde(default)]
    pub trend: TrendSettings,
    #[serde(default)]
    pub history: HistorySettings,
    #[serde(default)]
    pub api: ApiSettings,
    #[serde(default)]
    pub deps: DepsSettings,
    #[serde(default)]
    pub report: ReportSettings,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSettings {
    pub name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSettings {
    /// Fail when compliance `unknown` count exceeds this (coverage regression).
    pub max_unknown_controls: Option<usize>,
    /// Fail when a pull request adds a dependency (forces human review).
    pub block_new_dependencies: Option<bool>,
    /// Fail when a direct dependency has had no release for this many days.
    pub max_dependency_age_days: Option<i64>,
    /// "any" | "critical" | "high" | "medium" | "low" | "never"
    pub fail_on: Option<String>,
    /// Stricter thresholds for specific paths; strictest match wins.
    #[serde(default)]
    pub path: Vec<crate::gates::PathGate>,
    /// Stricter thresholds per category slug, e.g. `secrets = "any"`.
    #[serde(default)]
    pub category: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSettings {
    /// Never inventoried, never scanned.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Never sent to an AI tool, regardless of lens.
    #[serde(default)]
    pub ai_forbidden: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSettings {
    pub enabled: Option<bool>,
    /// Rule ids or slugs to switch off, with a reason in a comment.
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Extra YAML rule packs. `.deadbolt/rules/*.yaml` is loaded automatically.
    #[serde(default)]
    pub rule_packs: Vec<String>,
    pub max_file_kb: Option<u64>,
    /// Intra-file taint tracking (source → assignment → sink).
    pub taint: Option<bool>,
    /// Incremental cache: skip files whose size and mtime are unchanged.
    pub cache: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiSettings {
    pub enabled: Option<bool>,
    pub model: Option<String>,
    pub concurrency: Option<usize>,
    pub budget_usd: Option<f64>,
    pub timeout_seconds: Option<u64>,
    pub max_turns: Option<u32>,
    pub verify: Option<bool>,
    /// When non-empty, only these lenses may run.
    #[serde(default)]
    pub lenses: Vec<String>,
    /// Cheaper subset used by `diff` mode.
    #[serde(default)]
    pub diff_lenses: Vec<String>,
    pub cache: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachSettings {
    pub enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSettings {
    pub enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrendSettings {
    /// Append every run to `.deadbolt-history.jsonl`.
    pub record: Option<bool>,
    /// Fail when the score falls by more than this many points ("ratchet").
    pub ratchet: Option<bool>,
    pub tolerance: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySettings {
    /// Default: on for `audit`, off for `diff` and `scan`.
    pub enabled: Option<bool>,
    pub max_commits: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSettings {
    pub enabled: Option<bool>,
    /// OpenAPI documents to diff. Empty = auto-discover common filenames.
    #[serde(default)]
    pub specs: Vec<String>,
    /// Ref the contract is compared against when not in `diff` mode.
    pub base_ref: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepsSettings {
    pub enabled: Option<bool>,
    pub research_limit: Option<usize>,
    pub offline: Option<bool>,
    /// Packages excluded from findings, e.g. an accepted risk with a note.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSettings {
    /// "terminal" | "markdown" | "html" | "json" | "sarif"
    #[serde(default)]
    pub formats: Vec<String>,
    pub out: Option<PathBuf>,
    #[serde(default)]
    pub packs: Vec<String>,
    pub terminal_limit: Option<usize>,
}

impl Settings {
    /// Loads `<root>/.deadbolt.toml`, or an explicit path. Missing file is fine.
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None => root.join(FILE_NAME),
        };

        if !path.is_file() {
            if explicit.is_some() {
                anyhow::bail!("Configuration File Not Found: {}", path.display());
            }
            return Ok((Self::default(), None));
        }

        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("Could Not Read Configuration: {}", path.display()))?;
        let settings: Settings = toml::from_str(&body)
            .with_context(|| format!("Invalid Configuration: {}", path.display()))?;
        Ok((settings, Some(path)))
    }

    pub fn example() -> &'static str {
        EXAMPLE
    }
}

/// Written by `deadbolt init`.
pub const EXAMPLE: &str = r#"# deadbolt configuration
# Precedence: CLI argument > this file > built-in default.
# Every field is optional — write only what you want to change.

[project]
# name = "my-service"

[gates]
# Exit with code 1 when a finding at or above this severity exists.
fail_on = "high"           # any | critical | high | medium | low | never
# Block when compliance coverage regresses: the `unknown` count must stay below this.
# max_unknown_controls = 20
# Require human approval when a pull request adds a dependency.
block_new_dependencies = true
# Block when a direct dependency has had no release for this many days.
# max_dependency_age_days = 900

# Stricter per-category thresholds — the strictest match wins.
[gates.category]
secrets = "any"            # secrets block at any severity
cryptography = "medium"

# Stricter per-path thresholds.
[[gates.path]]
pattern = "**/auth/**"
fail_on = "medium"

[[gates.path]]
pattern = "**/payment*/**"
fail_on = "medium"

[paths]
# Never scanned.
ignore = [
  "**/node_modules/**",
  "**/vendor/**",
  "**/*.generated.*",
]
# Never sent to an AI tool (confidential modules).
ai_forbidden = [
  "**/crypto/**",
  "**/keys/**",
  "**/*.pem",
]

[scan]
enabled = true
# Disabled rules — write a reason for each one.
disabled_rules = [
  # "DB-CFG-004",  # timeouts are configured at the HTTP client level
]
# There is NO file size limit — every file is read. Enable this only if very large
# minified bundles slow the scan down (in KB).
# max_file_kb = 512
# Intra-file flow tracking: entry point -> assignment -> sink.
taint = true
# Incremental cache: a file whose size and mtime are unchanged is not rescanned.
cache = true
# Your own rule packs. `.deadbolt/rules/*.yaml` is loaded automatically.
rule_packs = [
  # "ops/deadbolt-rules.yaml",
]

[ai]
enabled = true
# Opus is the floor: the lenses reason about reachability.
model = "claude-opus-5"
concurrency = 8
# There is NO AI cost limit — every lens runs to completion. Enable this to cap it:
# budget_usd = 8.0
timeout_seconds = 600
max_turns = 45
# Adversarial verification: every severe AI finding is handed to independent
# refuters and survives only if none of them can knock it down.
verify = true
# Empty = every lens that matches the repository.
lenses = []
# The cheap subset used in `diff` mode.
diff_lenses = ["authz", "crypto", "migration"]
cache = true

[reach]
# Reachability weighting: a defect on a file that declares an external entry point
# is raised one step; one in example, script or unreferenced code is lowered one.
enabled = true

[chains]
# Correlated attack paths: several findings that together form one reachable path
# are reported as a single critical finding.
enabled = true

[trend]
# Every run is appended to `.deadbolt-history.jsonl` (commit it; it draws the trend).
record = true
# Ratchet: the score is not allowed to drop — only rise or stay flat.
ratchet = true
tolerance = 1.0

[history]
# Secret scan of git history: the working tree can be clean while a key in history is live.
# Default: on for `audit`, off for `diff` and `scan`.
enabled = true
max_commits = 1500

[api]
# OpenAPI contract diff: changes that break older clients.
enabled = true
# Empty = the usual file names are searched automatically.
specs = []
# Comparison base outside `diff` mode.
base_ref = "origin/main"

[deps]
enabled = true
research_limit = 30
offline = false
# Accepted risk — no finding is produced. Write the reason in a comment.
allow = [
  # "left-pad",  # decision: 2026-07-28, replacement planned
]

[report]
formats = ["terminal", "markdown"]
out = "deadbolt-report"
# Empty = all built-in packs.
packs = ["owasp-asvs", "cwe-top", "privacy"]
terminal_limit = 40
"#;

/// CLI value wins; then config; then the built-in default.
pub fn pick<T>(cli: Option<T>, config: Option<T>, fallback: T) -> T {
    cli.or(config).unwrap_or(fallback)
}

/// Same for lists: an empty list means "not set".
pub fn pick_list(cli: &[String], config: &[String]) -> Vec<String> {
    if !cli.is_empty() {
        cli.to_vec()
    } else {
        config.to_vec()
    }
}
