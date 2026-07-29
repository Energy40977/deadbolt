use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "deadbolt",
    version,
    about = "Deep security and compliance audit for any codebase",
    after_long_help = "EXIT CODES:\n  0  Clean — No Blocking Findings\n  1  Blocking Findings, Or A Score Regression\n  2  Tool Error (Arguments, Git, Configuration)\n  3  Degraded — Some Phases Did Not Run (AI Unreachable, No Network).\n        This Is NOT \"No Problems Found\"; Handle It Separately In CI.",
    long_about = "deadbolt audits a codebase written in any language: static analysis, \
live dependency research (vulnerabilities and personal-data collection), deep AI review \
and protocol compliance. The result is a prioritised report with concrete remediation."
)]
pub struct Cli {
    /// Optional on purpose: a bare `deadbolt` on a terminal opens the interactive
    /// setup instead of printing a usage error.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable colour output
    ///
    /// The `NO_COLOR` environment variable is honoured as well. It is not bound to
    /// clap: by convention the variable only has to be SET, its value is irrelevant,
    /// and parsing it as a bool would reject `NO_COLOR=1`.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Configuration file (defaults to <target>/.deadbolt.toml)
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Full audit: static rules + dependency research + AI + compliance
    Audit(AuditArgs),

    /// Deterministic checks only — no AI, network optional
    Scan(ScanArgs),

    /// Dependencies only: vulnerabilities, data collection, ownership risk
    Deps(DepsArgs),

    /// Change mode: checks the diff only (pull request / pre-commit)
    Diff(DiffArgs),

    /// Compliance packs: list, show, validate
    Pack(PackArgs),

    /// Baseline: accept current findings, block only new ones
    Baseline(BaselineArgs),

    /// Write .deadbolt.toml into the project
    Init(InitArgs),

    /// Portfolio: audit several repositories and rank them together
    Portfolio(PortfolioArgs),

    /// Explain a rule: what it finds, why it matters, how to fix it
    Explain(ExplainArgs),

    /// Apply safe repairs (without --apply nothing is written)
    Fix(FixArgs),

    /// Re-check on every file change (local development)
    Watch(WatchArgs),

    /// Environment and stack detection check
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Directory to audit
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Disable AI review (deterministic rules + dependency research only)
    #[arg(long)]
    pub no_ai: bool,

    /// Disable all network access (fully offline)
    #[arg(long)]
    pub offline: bool,

    /// Research every dependency deeply — expensive and slow
    #[arg(long)]
    pub exhaustive: bool,

    /// Maximum packages sent to deep research (`0` = no limit)
    #[arg(long, value_name = "N", default_value_t = 30)]
    pub research_limit: usize,

    /// Compliance packs, comma separated. All of them when omitted
    #[arg(long = "pack", value_name = "NAME", value_delimiter = ',')]
    pub packs: Vec<String>,

    /// Run only these AI lenses, comma separated: `--lens authz,crypto`
    #[arg(long = "lens", value_name = "NAME", value_delimiter = ',')]
    pub lenses: Vec<String>,

    /// Report formats, comma separated: `--format html,markdown,json`
    #[arg(long = "format", value_enum, value_delimiter = ',')]
    pub formats: Vec<Format>,

    /// Directory the reports are written to
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Exit with code 1 when a finding at or above this severity exists
    #[arg(long, value_enum, default_value_t = FailLevel::High)]
    pub fail_on: FailLevel,

    /// AI model
    #[arg(long, value_name = "MODEL", env = "DEADBOLT_MODEL")]
    pub model: Option<String>,

    /// Number of concurrent AI calls
    #[arg(long, value_name = "N", default_value_t = 8)]
    pub concurrency: usize,

    /// AI cost limit in USD. Remaining lenses are skipped once it is reached
    #[arg(long, value_name = "USD")]
    pub budget: Option<f64>,

    /// Ignore the baseline file and report every finding
    #[arg(long)]
    pub no_baseline: bool,

    /// Skip adversarial verification of AI findings (faster, less precise)
    #[arg(long)]
    pub no_verify: bool,

    /// Do not open the HTML report in a browser when the run finishes
    #[arg(long)]
    pub no_open: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Do not query the vulnerability database either
    #[arg(long)]
    pub offline: bool,

    #[arg(long = "format", value_enum, value_delimiter = ',')]
    pub formats: Vec<Format>,

    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = FailLevel::High)]
    pub fail_on: FailLevel,
    /// Do not open the HTML report in a browser when the run finishes
    #[arg(long)]
    pub no_open: bool,
    /// Ignore the baseline file and report every finding
    #[arg(long)]
    pub no_baseline: bool,
}

#[derive(Debug, Args)]
pub struct DepsArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Also research personal-data collection (AI + web)
    #[arg(long)]
    pub privacy: bool,

    /// Research every package deeply
    #[arg(long)]
    pub exhaustive: bool,

    #[arg(long, value_name = "N", default_value_t = 30)]
    pub research_limit: usize,

    #[arg(long)]
    pub offline: bool,

    /// AI model used for the data-collection research
    #[arg(long, value_name = "MODEL", env = "DEADBOLT_MODEL")]
    pub model: Option<String>,

    /// Number of concurrent research calls
    #[arg(long, value_name = "N", default_value_t = 8)]
    pub concurrency: usize,

    /// AI cost limit in USD
    #[arg(long, value_name = "USD")]
    pub budget: Option<f64>,

    #[arg(long = "format", value_enum, value_delimiter = ',')]
    pub formats: Vec<Format>,

    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = FailLevel::High)]
    pub fail_on: FailLevel,
    /// Do not open the HTML report in a browser when the run finishes
    #[arg(long)]
    pub no_open: bool,
    /// Ignore the baseline file and report every finding
    #[arg(long)]
    pub no_baseline: bool,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Comparison base, for example `main`. Staged changes when omitted
    #[arg(long, value_name = "REF")]
    pub base: Option<String>,

    /// Also run the AI review lenses
    ///
    /// Off by default here, unlike `audit`: a change gate runs on every commit and
    /// every pull request, so it has to stay fast and free unless asked otherwise.
    #[arg(long)]
    pub ai: bool,

    /// Run only these lenses (defaults to `diff_lenses` from the configuration)
    #[arg(long = "lens", value_name = "NAME", value_delimiter = ',')]
    pub lenses: Vec<String>,

    /// AI model
    #[arg(long, value_name = "MODEL", env = "DEADBOLT_MODEL")]
    pub model: Option<String>,

    /// AI cost limit in USD
    #[arg(long, value_name = "USD")]
    pub budget: Option<f64>,

    /// Number of concurrent AI calls
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,

    /// Also research dependencies (off by default: a diff run must stay fast)
    #[arg(long)]
    pub deps: bool,

    #[arg(long = "format", value_enum, value_delimiter = ',')]
    pub formats: Vec<Format>,

    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = FailLevel::High)]
    pub fail_on: FailLevel,
    /// Do not open the HTML report in a browser when the run finishes
    #[arg(long)]
    pub no_open: bool,
    /// Ignore the baseline file and report every finding
    #[arg(long)]
    pub no_baseline: bool,
}

#[derive(Debug, Args)]
pub struct BaselineArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Write the file. Without it only a preview is printed
    #[arg(long)]
    pub write: bool,

    /// Run the AI lenses as well (expensive; deterministic rules only by default)
    #[arg(long)]
    pub with_ai: bool,

    /// Drop entries that no longer exist
    #[arg(long)]
    pub prune: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct PackArgs {
    #[command(subcommand)]
    pub action: PackAction,
}

#[derive(Debug, Subcommand)]
pub enum PackAction {
    /// List the available packs
    List,
    /// Show the controls of a pack
    Show {
        /// Pack name
        name: String,
    },
    /// Validate the structure of a pack file
    Validate {
        /// Path to the pack file
        path: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Rule identifier, for example DB-INJ-001, AI-authz, owasp-asvs:V4.2.1
    pub rule: Option<String>,

    #[arg(long, default_value = ".")]
    pub target: PathBuf,

    /// List every rule
    #[arg(long)]
    pub list: bool,
}

#[derive(Debug, Args)]
pub struct FixArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Actually write the changes. Without it only a diff is shown
    #[arg(long)]
    pub apply: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Poll interval in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 900)]
    pub interval: u64,
}

#[derive(Debug, Args)]
pub struct PortfolioArgs {
    /// Repository paths, one or more
    #[arg(value_name = "REPO")]
    pub repos: Vec<PathBuf>,

    /// File listing one repository per line (`#` starts a comment)
    #[arg(long, value_name = "FILE")]
    pub list: Option<PathBuf>,

    /// Disable AI review (off by default in portfolio mode because of cost)
    #[arg(long, default_value_t = true)]
    pub no_ai: bool,

    /// Enable AI review (expensive: it runs per repository)
    #[arg(long, conflicts_with = "no_ai")]
    pub with_ai: bool,

    #[arg(long)]
    pub offline: bool,

    #[arg(long = "format", value_enum, value_delimiter = ',')]
    pub formats: Vec<Format>,

    #[arg(long, value_name = "DIR", default_value = "deadbolt-portfolio")]
    pub out: PathBuf,

    /// Exit with code 1 when any repository has a blocking finding
    #[arg(long, value_enum, default_value_t = FailLevel::High)]
    pub fail_on: FailLevel,

    #[arg(long, value_name = "USD")]
    pub budget: Option<f64>,

    #[arg(long, value_name = "MODEL", env = "DEADBOLT_MODEL")]
    pub model: Option<String>,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Coloured terminal output
    Terminal,
    /// Markdown report file
    Markdown,
    /// Single-file HTML report
    Html,
    /// SARIF (GitHub / GitLab code scanning)
    Sarif,
    /// Complete JSON output
    Json,
    /// CycloneDX 1.5 SBOM
    Sbom,
    /// GitHub Actions annotations on stdout
    Github,
    /// GitLab Code Quality report file
    Gitlab,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailLevel {
    Critical,
    High,
    Medium,
    Low,
    Never,
}

impl FailLevel {
    /// Maps the CLI flag onto a gate threshold; per-path and per-category rules
    /// in `.deadbolt.toml` can then only make it stricter.
    pub fn threshold(self) -> crate::gates::Threshold {
        use crate::gates::Threshold;
        use crate::model::Severity;
        match self {
            FailLevel::Critical => Threshold::At(Severity::Critical),
            FailLevel::High => Threshold::At(Severity::High),
            FailLevel::Medium => Threshold::At(Severity::Medium),
            FailLevel::Low => Threshold::At(Severity::Low),
            FailLevel::Never => Threshold::Never,
        }
    }
}
