mod ai;
mod apidiff;
mod authmatrix;
mod baseline;
mod chain;
mod cli;
mod compliance;
mod config;
mod deps;
mod discover;
mod exceptions;
mod gates;
mod gitdiff;
mod history;
mod model;
mod portfolio;
mod reach;
mod report;
mod sbom;
mod scan;
mod taint;
mod trend;
mod ui;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;

use cli::{Cli, Command, FailLevel, Format};
use model::{AuditReport, Finding, Origin, ReportMeta, Severity};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("deadbolt: {error:#}");
            std::process::ExitCode::from(2)
        }
    }
}

async fn run() -> Result<std::process::ExitCode> {
    let mut args = Cli::parse();

    if args.command.is_none() {
        if !ui::interactive() {
            <Cli as clap::CommandFactory>::command().print_help()?;
            return Ok(std::process::ExitCode::from(2));
        }
        match wizard_args()? {
            Some(argv) => args = Cli::parse_from(argv),
            None => return Ok(std::process::ExitCode::SUCCESS),
        }
    }
    let command = args
        .command
        .take()
        .expect("The Wizard Or The CLI Always Yields A Command");
    let color = !args.no_color && std::env::var_os("NO_COLOR").is_none();

    let load_settings = |target: &PathBuf| -> Result<(config::Settings, Option<PathBuf>)> {
        let root = target.canonicalize().unwrap_or_else(|_| target.clone());
        config::Settings::load(&root, args.config.as_deref())
    };

    match &command {
        Command::Audit(a) => {
            execute(RunOptions {
                target: a.target.clone(),
                mode: "audit",
                settings: load_settings(&a.target)?.0,
                settings_path: load_settings(&a.target)?.1,
                use_baseline: !a.no_baseline,
                verify: !a.no_verify,
                open_report: !a.no_open,
                diff_base: None,
                run_deps: true,
                packs: a.packs.clone(),
                lenses: a.lenses.clone(),
                model: a.model.clone(),
                concurrency: a.concurrency,
                budget: a.budget,
                offline: a.offline,
                ai: !a.no_ai,
                research_limit: a.research_limit,
                exhaustive: a.exhaustive,
                formats: a.formats.clone(),
                out: a.out.clone(),
                fail_on: a.fail_on,
                verbose: args.verbose,
                color,
                endpoints: Vec::new(),
            })
            .await
        }
        Command::Scan(a) => {
            execute(RunOptions {
                target: a.target.clone(),
                mode: "scan",
                settings: load_settings(&a.target)?.0,
                settings_path: load_settings(&a.target)?.1,
                use_baseline: !a.no_baseline,
                verify: true,
                open_report: !a.no_open,
                diff_base: None,
                run_deps: true,
                packs: Vec::new(),
                lenses: Vec::new(),
                model: None,
                concurrency: 1,
                budget: None,
                offline: a.offline,
                ai: false,
                research_limit: 0,
                exhaustive: false,
                formats: a.formats.clone(),
                out: a.out.clone(),
                fail_on: a.fail_on,
                verbose: args.verbose,
                color,
                endpoints: Vec::new(),
            })
            .await
        }
        Command::Deps(a) => {
            execute(RunOptions {
                target: a.target.clone(),
                mode: "deps",
                settings: load_settings(&a.target)?.0,
                settings_path: load_settings(&a.target)?.1,
                use_baseline: !a.no_baseline,
                verify: true,
                open_report: !a.no_open,
                diff_base: None,
                run_deps: true,
                packs: Vec::new(),
                lenses: Vec::new(),
                model: a.model.clone(),
                concurrency: a.concurrency,
                budget: a.budget,
                offline: a.offline,
                ai: a.privacy,
                research_limit: a.research_limit,
                exhaustive: a.exhaustive,
                formats: a.formats.clone(),
                out: a.out.clone(),
                fail_on: a.fail_on,
                verbose: args.verbose,
                color,
                endpoints: Vec::new(),
            })
            .await
        }
        Command::Pack(a) => pack_command(&a.action).map(|_| std::process::ExitCode::SUCCESS),
        Command::Diff(a) => {
            let (settings, settings_path) = load_settings(&a.target)?;
            let lenses = config::pick_list(&a.lenses, &settings.ai.diff_lenses);
            execute(RunOptions {
                target: a.target.clone(),
                mode: "diff",
                settings,
                settings_path,
                use_baseline: !a.no_baseline,
                verify: true,
                open_report: !a.no_open,
                diff_base: a.base.clone(),
                run_deps: a.deps,
                packs: Vec::new(),
                lenses,
                model: a.model.clone(),
                concurrency: a.concurrency.unwrap_or(4),
                budget: a.budget,
                offline: !a.deps,
                ai: a.ai,
                research_limit: 0,
                exhaustive: false,
                formats: a.formats.clone(),
                out: a.out.clone(),
                fail_on: a.fail_on,
                verbose: args.verbose,
                color,
                endpoints: Vec::new(),
            })
            .await
        }
        Command::Baseline(a) => {
            let (settings, settings_path) = load_settings(&a.target)?;
            baseline_command(
                a,
                BaselineContext {
                    settings,
                    settings_path,
                    verbose: args.verbose,
                },
            )
            .await
            .map(|_| std::process::ExitCode::SUCCESS)
        }
        Command::Init(a) => init_command(a).map(|_| std::process::ExitCode::SUCCESS),
        Command::Portfolio(a) => portfolio_command(a, args.verbose, color).await,
        Command::Explain(a) => explain_command(a).map(|_| std::process::ExitCode::SUCCESS),
        Command::Fix(a) => fix_command(a).map(|_| std::process::ExitCode::SUCCESS),
        Command::Watch(a) => watch_command(a, color).await,
        Command::Doctor(a) => doctor(&a.target).map(|_| std::process::ExitCode::SUCCESS),
    }
}

struct RunOptions {
    target: PathBuf,
    mode: &'static str,
    settings: config::Settings,
    settings_path: Option<PathBuf>,
    use_baseline: bool,
    verify: bool,
    open_report: bool,
    diff_base: Option<String>,
    run_deps: bool,
    packs: Vec<String>,
    lenses: Vec<String>,
    model: Option<String>,
    concurrency: usize,
    budget: Option<f64>,
    offline: bool,
    ai: bool,
    research_limit: usize,
    exhaustive: bool,
    formats: Vec<Format>,
    out: Option<PathBuf>,
    fail_on: FailLevel,
    verbose: bool,
    color: bool,
    /// Extracted route inventory (B12). Populated by `analyze`.
    endpoints: Vec<authmatrix::Endpoint>,
}

/// Result of the analysis phase, before anything is rendered or gated.
struct Analysis {
    report: AuditReport,
    ratchet_failure: Option<String>,
    endpoints: Vec<authmatrix::Endpoint>,
}

/// Runs every phase and returns the report. Kept free of printing and exit codes
/// so `portfolio` can reuse it across repositories.
async fn analyze(options: &RunOptions) -> Result<Analysis> {
    let started = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    let deps_phase =
        options.mode != "scan" && options.settings.deps.enabled.unwrap_or(true) && options.run_deps;
    let ai_phase =
        options.ai && options.settings.ai.enabled.unwrap_or(true) && options.mode != "deps";
    let total_phases = 3 + usize::from(deps_phase) + usize::from(ai_phase);
    let progress = std::sync::Arc::new(ui::Progress::new(
        ui::interactive() && !options.verbose,
        total_phases,
    ));
    progress.phase("Reading Project");
    if options.verbose {
        eprintln!("-> 1/4 Discovery");
    }
    let read_limit = options
        .settings
        .scan
        .max_file_kb
        .map(|kb| kb * 1024)
        .unwrap_or(u64::MAX);
    let mut inventory = discover::discover_with(&options.target, read_limit)?;

    let mut warnings = Vec::new();
    if let Some(path) = &options.settings_path {
        if options.verbose {
            eprintln!("   configuration: {}", path.display());
        }
    }

    let ignore = &options.settings.paths.ignore;
    if !ignore.is_empty() {
        let before = inventory.files.len();
        inventory
            .files
            .retain(|file| !glob_any(ignore, &file.rel_path));
        if options.verbose {
            eprintln!(
                "   Configuration Filter: {} Files Removed",
                before - inventory.files.len()
            );
        }
    }

    let changes = if options.mode == "diff" {
        let change_set = gitdiff::collect(&inventory.root, options.diff_base.as_deref())?;
        if change_set.is_empty() {
            println!("deadbolt: No Changes Found ({}).", change_set.range);
            anyhow::bail!("__no_changes__");
        }
        if options.verbose {
            eprintln!(
                "   Change: {} ({} Files, {} Lines)",
                change_set.range,
                change_set.files.len(),
                change_set.added_line_count()
            );
        }
        inventory = gitdiff::restrict(inventory, &change_set);
        Some(change_set)
    } else {
        None
    };
    if inventory.skipped_large > 0 {
        let names = inventory.skipped_large_names.join(", ");
        let rest = inventory
            .skipped_large
            .saturating_sub(inventory.skipped_large_names.len());
        warnings.push(format!(
            "{} Files Were Too Large To Read (Limit {} KB): {}{}. \
These Are Usually Minified Bundles Or Data Dumps. Raise \
`[scan] max_file_kb` In `.deadbolt.toml` If You Need Them Scanned.",
            inventory.skipped_large,
            read_limit / 1024,
            names,
            if rest > 0 {
                format!(" And {rest} More")
            } else {
                String::new()
            }
        ));
    }

    progress.done(
        "Project Read",
        &format!(
            "{} Files · {} Lines · {} Languages",
            inventory.stack.total_files,
            inventory.stack.total_lines,
            inventory.stack.languages.len()
        ),
    );
    progress.phase("Static Rules");
    if options.verbose {
        eprintln!(
            "-> 2/4 Static Analysis ({} Files, {} Languages)",
            inventory.files.len(),
            inventory.stack.languages.len()
        );
    }
    let scan_enabled = options.settings.scan.enabled.unwrap_or(true);
    let mut findings: Vec<Finding> = if options.mode == "deps" || !scan_enabled {
        Vec::new()
    } else {
        let cache_dir = options
            .settings
            .scan
            .cache
            .unwrap_or(true)
            .then(|| inventory.root.join(".deadbolt-cache"));
        let (result, pack_warnings, user_rules) = scan::scan_with_options(
            &inventory,
            &options.settings.scan.rule_packs,
            cache_dir.as_deref(),
        );
        warnings.extend(pack_warnings);
        if user_rules > 0 && options.verbose {
            eprintln!("   Your Own Rules: {user_rules}");
        }
        let mut static_findings = result?;

        if options.settings.scan.taint.unwrap_or(true) {
            let flows = taint::run(&inventory);
            if options.verbose && !flows.is_empty() {
                eprintln!("   Flow Tracking: {} Findings", flows.len());
            }
            static_findings.extend(flows);
        }
        static_findings
    };

    let disabled = &options.settings.scan.disabled_rules;
    if !disabled.is_empty() {
        let before = findings.len();
        findings.retain(|finding| !disabled.contains(&finding.rule));
        if before != findings.len() && options.verbose {
            eprintln!(
                "   Disabled Rules: {} Findings Removed",
                before - findings.len()
            );
        }
    }

    progress.done(
        "yoxlama bitdi",
        &format!(
            "{} Findings ({} Rules)",
            findings.len(),
            scan::all_rule_ids().len()
        ),
    );

    let endpoints = if options.mode == "deps" {
        Vec::new()
    } else {
        let extracted = authmatrix::extract(&inventory);
        if options.verbose && !extracted.is_empty() {
            let summary = authmatrix::summarize(&extracted);
            eprintln!(
                "   Endpoints: {} · Unprotected: {} · IDOR Suspects: {}",
                summary.total, summary.unprotected, summary.idor_candidates
            );
        }
        extracted
    };

    let mut packages = Vec::new();
    let mut escalate = Vec::new();
    let deps_enabled = options.settings.deps.enabled.unwrap_or(true) && options.run_deps;
    if options.mode != "scan" && deps_enabled {
        progress.phase("Dependencies (OSV.dev)");
        if options.verbose {
            eprintln!("-> 3/4 Dependency Research");
        }
        let deps_options = deps::DepsOptions {
            offline: options.offline || options.settings.deps.offline.unwrap_or(false),
            research_limit: config::pick(
                Some(options.research_limit).filter(|limit| *limit != 30),
                options.settings.deps.research_limit,
                options.research_limit,
            ),
            exhaustive: options.exhaustive,
        };
        match deps::survey(&inventory, &deps_options).await {
            Ok(outcome) => {
                findings.extend(outcome.findings);
                packages = outcome.packages;
                escalate = outcome.escalate;
                warnings.extend(outcome.warnings);
                if options.verbose && !escalate.is_empty() {
                    eprintln!("   Selected For Deep Research: {}", escalate.len());
                }
            }
            Err(error) => warnings.push(format!("Dependency Research Failed: {error:#}")),
        }
        let vulnerable = packages
            .iter()
            .filter(|audit| !audit.vulnerabilities.is_empty())
            .count();
        progress.done(
            "Dependencies Checked",
            &format!(
                "{} Packages · {vulnerable} With Known Vulnerabilities",
                packages.len()
            ),
        );

        if let Some(max_age) = options.settings.gates.max_dependency_age_days {
            let now = chrono::Utc::now();
            let stale: Vec<String> = packages
                .iter()
                .filter(|audit| audit.enriched)
                .filter(|audit| audit.package.as_ref().map(|p| p.direct).unwrap_or(false))
                .filter_map(|audit| {
                    let released = audit.last_release.as_deref()?;
                    let parsed = chrono::DateTime::parse_from_rfc3339(released).ok()?;
                    let age = (now - parsed.with_timezone(&chrono::Utc)).num_days();
                    (age > max_age).then(|| {
                        let package = audit.package.as_ref()?;
                        Some(format!("{}@{} ({age} Days)", package.name, package.version))
                    })?
                })
                .collect();

            if !stale.is_empty() {
                findings.push(
                    model::Finding::builder(
                        "DB-GATE-003",
                        model::Category::SupplyChain,
                        model::Severity::Medium,
                    )
                    .title(format!(
                        "{} Direct Dependencies Have Had No Release For Over {max_age} Days",
                        stale.len()
                    ))
                    .description(stale.join(", "))
                    .impact(
                        "An Unmaintained Package Will Not Receive A Fix When A Vulnerability \
Lands In It: Replacement Becomes The Only Option, And That Is Far More Expensive Under Pressure.",
                    )
                    .remediation(
                        "Decide For Each One: Move To A Maintained Alternative, Fork And Maintain \
It Yourself, Or Accept The Risk And Record It In `deps.allow` With A Reason.",
                    )
                    .origin(model::Origin::Static)
                    .confidence(model::Confidence::Probable)
                    .evidence(model::Evidence::new("<dependencies>", None, String::new()))
                    .policy("DEV-02, b.12")
                    .build(),
                );
            }
        }

        let allow = &options.settings.deps.allow;
        if !allow.is_empty() {
            findings.retain(|finding| {
                if !finding.rule.starts_with("DB-DEP-") {
                    return true;
                }
                !allow
                    .iter()
                    .any(|name| finding.title.contains(name.as_str()))
            });
        }
    }

    if let Some(change_set) = &changes {
        if options
            .settings
            .gates
            .block_new_dependencies
            .unwrap_or(false)
        {
            let manifest_names = [
                "package.json",
                "requirements.txt",
                "pyproject.toml",
                "Cargo.toml",
                "go.mod",
                "composer.json",
                "pubspec.yaml",
                "Gemfile",
                "pom.xml",
            ];
            let added: Vec<String> = change_set
                .files
                .keys()
                .filter(|path| {
                    let base = path.rsplit('/').next().unwrap_or("");
                    manifest_names.contains(&base)
                })
                .cloned()
                .collect();
            if !added.is_empty() {
                findings.push(
                    model::Finding::builder(
                        "DB-GATE-002",
                        model::Category::SupplyChain,
                        model::Severity::High,
                    )
                    .title("This Change Touches A Dependency Manifest — Human Review Required")
                    .description(format!("Changed Manifests: {}", added.join(", ")))
                    .impact(
                        "A New Dependency Runs With The Same Privileges As Your Own Code And Can \
Pull In Dozens Of Transitive Packages. Silent Growth Of The Supply-Chain Surface Is The \
istismar olunan yoldur.",
                    )
                    .remediation(
                        "Assess The Package Explicitly In Review: Why Is It Needed, Is There An \
Alternative, Who Maintains It, Does It Run Install Scripts? Record The Decision In The Review \
Notes, Not In `.deadbolt-baseline.json`.",
                    )
                    .origin(model::Origin::Static)
                    .confidence(model::Confidence::Confirmed)
                    .evidence(model::Evidence::new(
                        added.first().cloned().unwrap_or_default(),
                        None,
                        String::new(),
                    ))
                    .policy("DEV-02, b.12.2")
                    .build(),
                );
            }
        }
    }

    let history_enabled = options
        .settings
        .history
        .enabled
        .unwrap_or(options.mode == "audit");
    if history_enabled && gitdiff::is_repository(&inventory.root) {
        if options.verbose {
            eprintln!("-> Git History Scan");
        }
        let history_options = history::Options {
            max_commits: options.settings.history.max_commits.unwrap_or(1500),
            ..Default::default()
        };
        match history::scan(&inventory.root, &history_options) {
            Ok((history_findings, history_warnings)) => {
                if options.verbose {
                    eprintln!("   History-Only Secrets: {}", history_findings.len());
                }
                findings.extend(history_findings);
                warnings.extend(history_warnings);
            }
            Err(error) => warnings.push(format!("History Scan Failed: {error:#}")),
        }
    }

    if options.settings.api.enabled.unwrap_or(true) {
        let base_ref = options
            .diff_base
            .clone()
            .or_else(|| (options.mode == "diff").then(|| "HEAD".to_string()))
            .or_else(|| options.settings.api.base_ref.clone());
        if let Some(base_ref) = base_ref {
            if gitdiff::is_repository(&inventory.root) {
                let (api_findings, api_warnings) =
                    apidiff::run(&inventory.root, &base_ref, &options.settings.api.specs);
                if options.verbose && !api_findings.is_empty() {
                    eprintln!(
                        "   API Contract Diff: {} Breaking Changes",
                        api_findings.len()
                    );
                }
                findings.extend(api_findings);
                warnings.extend(api_warnings);
            }
        }
    }

    let mut lenses_run: Vec<String> = Vec::new();
    let mut ai_cost = 0.0f64;

    let ai_enabled = options.ai && options.settings.ai.enabled.unwrap_or(true);
    if ai_enabled {
        let ai_config = &options.settings.ai;
        let mut ai_options = ai::AiOptions::new(&inventory.root);
        ai_options.lenses = config::pick_list(&options.lenses, &ai_config.lenses);
        ai_options.concurrency =
            config::pick(Some(options.concurrency), ai_config.concurrency, 4).max(1);
        ai_options.budget_usd = options.budget.or(ai_config.budget_usd);
        ai_options.verbose = options.verbose;
        ai_options.forbidden_paths = options.settings.paths.ai_forbidden.to_vec();
        ai_options.cache = ai_config.cache.unwrap_or(true);
        ai_options.verify = options.verify && ai_config.verify.unwrap_or(true);
        ai_options.model = config::pick(
            options.model.clone(),
            ai_config.model.clone(),
            ai::DEFAULT_MODEL.to_string(),
        );
        if let Some(seconds) = ai_config.timeout_seconds {
            ai_options.timeout = std::time::Duration::from_secs(seconds);
        }
        if let Some(turns) = ai_config.max_turns {
            ai_options.max_turns = turns;
        }

        if progress.enabled() {
            let sink_progress = std::sync::Arc::clone(&progress);
            let bar: std::sync::Arc<std::sync::Mutex<Option<indicatif::ProgressBar>>> =
                std::sync::Arc::new(std::sync::Mutex::new(None));
            ai_options.events = Some(std::sync::Arc::new(move |event: ai::Event| match event {
                ai::Event::ReconStarted => {
                    sink_progress.log("Recon      Mapping Routes, Defences, Models, Sinks");
                }
                ai::Event::ReconDone {
                    lines,
                    cost_usd,
                    cached,
                } => {
                    sink_progress.log(&format!(
                        "Recon      {lines} Lines Mapped{}",
                        if cached {
                            "  (Cached, Free)".to_string()
                        } else {
                            format!("  ${cost_usd:.2}")
                        }
                    ));
                }
                ai::Event::VerifyPlan { total } => {
                    if let Ok(mut slot) = bar.lock() {
                        *slot = Some(sink_progress.counter(total as u64, "Verify"));
                    }
                }
                ai::Event::VerifyDone {
                    title,
                    kept,
                    cost_usd,
                } => {
                    if let Ok(slot) = bar.lock() {
                        if let Some(bar) = slot.as_ref() {
                            bar.inc(1);
                        }
                    }
                    let short: String = title.chars().take(52).collect();
                    if kept {
                        sink_progress.log(&format!("Verify     Held Up   {short}  ${cost_usd:.2}"));
                    } else {
                        sink_progress
                            .warn(&format!("Verify     Refuted   {short}  ${cost_usd:.2}"));
                    }
                }
                ai::Event::LensPlan {
                    total,
                    estimate_usd,
                } => {
                    sink_progress.log(&format!(
                        "AI Plan    {total} Subagents · Rough Estimate ${estimate_usd:.0}"
                    ));
                    if let Ok(mut slot) = bar.lock() {
                        *slot = Some(sink_progress.counter(total as u64, "AI Review"));
                    }
                }
                ai::Event::LensStarted { name, files } => {
                    if let Ok(slot) = bar.lock() {
                        if let Some(bar) = slot.as_ref() {
                            bar.set_message(format!("{name} Running ({files} Files)"));
                        }
                    }
                }
                ai::Event::LensDone {
                    name,
                    findings,
                    cost_usd,
                    cached,
                } => {
                    if let Ok(slot) = bar.lock() {
                        if let Some(bar) = slot.as_ref() {
                            bar.inc(1);
                        }
                    }
                    sink_progress.log(&format!(
                        "AI · {name:<10}{findings} Findings{}",
                        if cached {
                            "  (Cached, Free)".to_string()
                        } else {
                            format!("  ${cost_usd:.2}")
                        }
                    ));
                }
                ai::Event::LensFailed { name, error } => {
                    if let Ok(slot) = bar.lock() {
                        if let Some(bar) = slot.as_ref() {
                            bar.inc(1);
                        }
                    }
                    sink_progress.warn(&format!("AI · {name:<10}Failed: {error}"));
                }
                ai::Event::LensSkipped { name } => {
                    if let Ok(slot) = bar.lock() {
                        if let Some(bar) = slot.as_ref() {
                            bar.inc(1);
                        }
                    }
                    sink_progress.warn(&format!("AI · {name:<10}Skipped — Cost Limit Reached"));
                }
                ai::Event::ResearchDone { name, ok, cost_usd } => {
                    if ok {
                        sink_progress.log(&format!("Package Research · {name}  ${cost_usd:.2}"));
                    } else {
                        sink_progress.warn(&format!("Package Research · {name} Failed"));
                    }
                }
            }));
        }

        if options.mode != "deps" {
            progress.phase(&format!("AI Review ({})", ai_options.model));
            if options.verbose {
                eprintln!("-> AI Review Lenses (Model: {})", ai_options.model);
            }
            let outcome = ai::review(&inventory, &ai_options).await;
            findings.extend(outcome.findings);
            warnings.extend(outcome.warnings);
            lenses_run = outcome.lenses_run;
            ai_cost += outcome.cost_usd;
            progress.done(
                "AI Review Done",
                &format!("{} lens · ${:.2}", lenses_run.len(), ai_cost),
            );
        }

        if !escalate.is_empty() {
            if options.verbose {
                eprintln!("-> Deep Package Research ({} Packages)", escalate.len());
            }
            let signals: Vec<Vec<String>> = escalate
                .iter()
                .map(|package| {
                    packages
                        .iter()
                        .find(|audit| {
                            audit
                                .package
                                .as_ref()
                                .map(|p| p.name == package.name && p.version == package.version)
                                .unwrap_or(false)
                        })
                        .map(|audit| {
                            audit
                                .signals
                                .iter()
                                .map(|signal| signal.label().to_string())
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .collect();

            let (research, cost, research_warnings) =
                ai::research_packages(&inventory.root, &escalate, &signals, &ai_options).await;
            ai_cost += cost;
            warnings.extend(research_warnings);

            for (name, outcome) in research {
                if let Some(audit) = packages.iter_mut().find(|audit| {
                    audit
                        .package
                        .as_ref()
                        .map(|p| p.name == name)
                        .unwrap_or(false)
                }) {
                    audit.research = Some(outcome);
                }
            }
            findings.extend(deps::research_findings(&packages));
        }
    }

    let mut controls = Vec::new();
    let mut pack_summaries = Vec::new();
    let mut packs_run = Vec::new();

    if options.mode == "audit" {
        let configured = config::pick_list(&options.packs, &options.settings.report.packs);
        let requested = if configured.is_empty() {
            compliance::built_in_names()
                .iter()
                .map(|name| name.to_string())
                .collect()
        } else {
            configured
        };

        let coverage =
            compliance::Coverage::new(&scan::all_rule_ids(), &lenses_run, !packages.is_empty());

        for name in &requested {
            let loaded = if name.ends_with(".yaml") || name.ends_with(".yml") {
                compliance::load_file(Path::new(name))
            } else {
                compliance::load_built_in(name)
            };
            match loaded {
                Ok(pack) => {
                    let results = compliance::evaluate(&pack, &findings, &coverage);
                    pack_summaries.push(compliance::summarize(&pack, &results));
                    packs_run.push(pack.name.clone());
                    controls.extend(results);
                }
                Err(error) => warnings.push(format!("pack '{name}': {error:#}")),
            }
        }
        findings.extend(compliance::to_findings(&controls));
    }

    // Reachability weighting runs before correlation, so a chain inherits the
    // calibrated severities rather than the raw ones.
    if options.settings.reach.enabled.unwrap_or(true) {
        let adjustment = reach::calibrate(&inventory, &mut findings);
        if adjustment.raised + adjustment.lowered > 0 {
            progress.log(&format!(
                "Reachability   {} Raised · {} Lowered",
                adjustment.raised, adjustment.lowered
            ));
        }
    }

    // Correlation runs after every producer, because a chain can join a static
    // rule to an AI finding to a dependency signal.
    if options.settings.chains.enabled.unwrap_or(true) {
        let chains = chain::correlate(&findings);
        if !chains.is_empty() {
            progress.log(&format!(
                "{} Correlated Attack Path{}",
                chains.len(),
                if chains.len() == 1 { "" } else { "s" }
            ));
            findings.extend(chains);
        }
    }

    {
        if let Some(limit) = options.settings.gates.max_unknown_controls {
            let unknown: usize = pack_summaries.iter().map(|pack| pack.unknown).sum();
            if unknown > limit {
                findings.push(
                    model::Finding::builder(
                        "DB-GATE-004",
                        model::Category::Compliance,
                        model::Severity::High,
                    )
                    .title(format!(
                        "Unassessable Control Count Exceeds The Limit: {unknown} > {limit}"
                    ))
                    .description(
                        "An `unknown` Status Means The Control Could Not Be Evaluated — \
It Does Not Mean It Passed.",
                    )
                    .impact(
                        "The Compliance Report Looks Good Only Because Nothing Was Checked: \
No Violations Because No Evaluation. That Gap Surfaces During An Audit Or Customer Review.",
                    )
                    .remediation(
                        "Either Raise Coverage (Run The AI Lenses, Add Matching Rules), \
Or Raise The Limit Deliberately And Write Down Why.",
                    )
                    .origin(model::Origin::Compliance)
                    .confidence(model::Confidence::Confirmed)
                    .evidence(model::Evidence::new("<compliance>", None, String::new()))
                    .policy("SEC-00, b.5.5")
                    .build(),
                );
            }
        }
    }

    let today = chrono::Utc::now().date_naive();
    let mut suppressed_by_exception = 0usize;
    {
        let mut per_file: std::collections::HashMap<String, exceptions::FileExceptions> =
            std::collections::HashMap::new();
        for file in &inventory.files {
            let parsed = exceptions::parse_file(file);
            if !parsed.is_empty() {
                per_file.insert(file.rel_path.clone(), parsed);
            }
        }
        if !per_file.is_empty() {
            let before = findings.len();
            findings.retain(|finding| {
                let evidence = match finding.evidence.first() {
                    Some(evidence) => evidence,
                    None => return true,
                };
                let line = evidence.line.unwrap_or(0);
                match per_file.get(&evidence.file) {
                    Some(file_exceptions) => !file_exceptions.allows(&finding.rule, line, today),
                    None => true,
                }
            });
            suppressed_by_exception = before - findings.len();
        }
        findings.extend(exceptions::audit(&inventory, today));
    }
    if suppressed_by_exception > 0 {
        warnings.push(format!(
            "{suppressed_by_exception} Findings Suppressed By An Active Inline Exception"
        ));
    }

    findings = dedupe(findings);

    if let Some(change_set) = &changes {
        let (kept, dropped) = gitdiff::filter_findings(findings, change_set);
        findings = kept;
        if dropped > 0 {
            warnings.push(format!(
                "{dropped} Findings Hidden Because They Sit Outside The Change (Full Audit: `deadbolt audit`)"
            ));
        }
    }

    if options.use_baseline {
        if let Some(accepted) = baseline::Baseline::load(&inventory.root) {
            let filtered = baseline::apply(findings, Some(&accepted));
            findings = filtered.findings;
            if filtered.suppressed > 0 {
                warnings.push(format!(
                    "{} Findings Accepted By The Baseline",
                    filtered.suppressed
                ));
            }
            if filtered.stale > 0 {
                warnings.push(format!(
                    "The Baseline Holds {} Stale Entries — Clean Them With `deadbolt baseline --write --prune`",
                    filtered.stale
                ));
            }
        }
    }

    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(a.confidence.cmp(&b.confidence))
            .then(a.primary_location().cmp(&b.primary_location()))
    });

    let mut audit = AuditReport {
        meta: ReportMeta {
            tool: "deadbolt".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            target: inventory.root.display().to_string(),
            project: options
                .settings
                .project
                .name
                .clone()
                .or_else(|| {
                    inventory
                        .root
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                })
                .unwrap_or_else(|| "Project".to_string()),
            started_at,
            duration_ms: started.elapsed().as_millis() as u64,
            mode: options.mode.to_string(),
            ai_enabled: options.ai,
            research_enabled: !options.offline,
            lenses_run,
            packs_run,
            ai_cost_usd: ai_cost,
            warnings,
        },
        stack: inventory.stack.clone(),
        score: Default::default(),
        findings,
        packages,
        controls,
        packs: pack_summaries,
    };
    // Every producer has contributed by now: rules, taint, history, dependencies,
    // AI, chains. One canonical order from here on, so two runs are comparable.
    model::sort_findings(&mut audit.findings);
    audit.compute_score();

    let mut ratchet_failure: Option<String> = None;
    if options.settings.trend.record.unwrap_or(true) && options.mode != "diff" {
        let entry = trend::entry_from(&audit, &inventory.root);
        let history = trend::load(&inventory.root);
        let verdict = trend::check(
            &history,
            &entry,
            options.settings.trend.tolerance.unwrap_or(1.0),
        );

        if let Some(previous) = &verdict.previous {
            audit.meta.warnings.push(format!(
                "Score: {:.1} -> {:.1} ({:+.1})",
                previous.score, entry.score, verdict.delta
            ));
        }
        if let Err(error) = trend::append(&inventory.root, &entry) {
            audit
                .meta
                .warnings
                .push(format!("History Not Written: {error:#}"));
        }
        if options.settings.trend.ratchet.unwrap_or(false) {
            ratchet_failure = verdict.regression;
        }
    }

    progress.phase("Report");
    progress.finish();

    Ok(Analysis {
        report: audit,
        ratchet_failure,
        endpoints,
    })
}

async fn execute(options: RunOptions) -> Result<std::process::ExitCode> {
    let Analysis {
        report: audit,
        ratchet_failure,
        endpoints,
    } = match analyze(&options).await {
        Ok(analysis) => analysis,
        Err(error) if error.to_string().contains("__no_changes__") => {
            return Ok(std::process::ExitCode::SUCCESS)
        }
        Err(error) => return Err(error),
    };

    if options.verbose {
        eprintln!("→ 4/4 hesabat");
    }
    let mut options = options;
    options.endpoints = endpoints;
    emit(&audit, &options)?;

    let global = match (&options.settings.gates.fail_on, options.fail_on) {
        (Some(configured), FailLevel::High) => gates::Threshold::parse(configured),
        _ => options.fail_on.threshold(),
    };
    let policy = gates::Policy::new(
        global,
        &options.settings.gates.path,
        &options.settings.gates.category,
    );
    let blocking = policy.blocking(&audit.findings);

    if !blocking.is_empty() && !matches!(options.formats.first(), Some(Format::Json)) {
        // One row per defect, not per occurrence. Repeating the threshold on every
        // line pushed the useful columns off screen; the threshold is a property of
        // the run, so it belongs in the header once.
        let mut groups: BTreeMap<(Severity, &str), (usize, String)> = BTreeMap::new();
        let mut strictest = String::new();
        for (finding, threshold) in &blocking {
            if strictest.is_empty() {
                strictest = threshold.label().to_string();
            }
            let entry = groups
                .entry((finding.severity, finding.title.as_str()))
                .or_insert((0, finding.primary_location()));
            entry.0 += 1;
        }

        // A violated compliance control restates a defect that is already in the
        // table above it. Listing each separately triples the rows and buries the
        // code findings, so they collapse into one counted line.
        let compliance_blocking = blocking
            .iter()
            .filter(|(finding, _)| finding.origin == Origin::Compliance)
            .count();

        let mut rows: Vec<(Severity, &str, usize, &String)> = groups
            .iter()
            .filter(|((_, title), _)| !title.contains(" Violated — "))
            .map(|((severity, title), (count, location))| (*severity, *title, *count, location))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.cmp(&a.2)));

        const TITLE_WIDTH: usize = 52;
        const LOCATION_WIDTH: usize = 44;
        let clip = |text: &str, width: usize| -> String {
            if text.chars().count() <= width {
                return text.to_string();
            }
            let kept: String = text.chars().take(width - 1).collect();
            format!("{kept}…")
        };

        eprintln!(
            "\nBLOCKED — {} findings at or above \"{}\"\n",
            blocking.len(),
            strictest
        );
        eprintln!(
            "  {:<9} {:>3}  {:<TITLE_WIDTH$}  FIRST LOCATION",
            "SEVERITY", "N", "FINDING"
        );
        for (severity, title, count, location) in rows.iter().take(15) {
            let suffix = if *count > 1 {
                format!(" (+{})", count - 1)
            } else {
                String::new()
            };
            eprintln!(
                "  {:<9} {:>3}  {:<TITLE_WIDTH$}  {}{}",
                severity.label(),
                count,
                clip(title, TITLE_WIDTH),
                clip(location, LOCATION_WIDTH),
                suffix
            );
        }
        if rows.len() > 15 {
            eprintln!("  {:<9} {:>3}  … more defect kinds", "", rows.len() - 15);
        }
        if compliance_blocking > 0 {
            eprintln!(
                "\n  Plus {compliance_blocking} violated compliance controls, which restate the \
defects above against a standard."
            );
        }
        eprintln!("\n  Every occurrence, with evidence and remediation, is in the report.");
    }

    if let Some(reason) = &ratchet_failure {
        eprintln!("\nRATCHET: The Score Regressed — {reason}");
    }

    let degraded: Vec<&String> = audit
        .meta
        .warnings
        .iter()
        .filter(|warning| {
            let lowered = warning.to_lowercase();
            lowered.contains("failed")
                || lowered.contains("not found")
                || lowered.contains("unavailable")
                || lowered.contains("skipped")
                || lowered.contains("truncated")
        })
        .collect();

    if !blocking.is_empty() || ratchet_failure.is_some() {
        return Ok(std::process::ExitCode::from(1));
    }

    if !degraded.is_empty() {
        eprintln!(
            "\nDEGRADED ({} Phases Did Not Complete) — Exit Code 3:",
            degraded.len()
        );
        for warning in degraded.iter().take(6) {
            eprintln!("  {warning}");
        }
        eprintln!(
            "  This Is Not \"No Problems Found\": Some Checks Never Ran. \
Handle Exit Code 3 Separately In CI."
        );
        return Ok(std::process::ExitCode::from(3));
    }

    Ok(std::process::ExitCode::SUCCESS)
}

/// Very small glob: supports `**`, `*` and literal segments. Enough for the
/// ignore patterns a config file realistically contains.
pub(crate) fn glob_match(pattern: &str, path: &str) -> bool {
    fn helper(pattern: &[u8], path: &[u8]) -> bool {
        if pattern.is_empty() {
            return path.is_empty();
        }
        if pattern[0] == b'*' {
            let double = pattern.len() > 1 && pattern[1] == b'*';
            let rest = if double { &pattern[2..] } else { &pattern[1..] };
            let rest = if double && !rest.is_empty() && rest[0] == b'/' {
                &rest[1..]
            } else {
                rest
            };
            if helper(rest, path) {
                return true;
            }
            for index in 0..path.len() {
                if !double && path[index] == b'/' {
                    break;
                }
                if helper(rest, &path[index + 1..]) {
                    return true;
                }
            }
            return false;
        }
        if !path.is_empty() && (pattern[0] == b'?' || pattern[0] == path[0]) {
            return helper(&pattern[1..], &path[1..]);
        }
        false
    }
    helper(pattern.as_bytes(), path.as_bytes())
}

/// True when any pattern matches the path.
pub(crate) fn glob_any(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| glob_match(pattern, path))
}

/// `CLI > config > built-in default`.
///
/// The CLI list is empty exactly when the flag was not passed — which is why
/// `--format` has no clap default. Inferring "did the user pass this?" from the
/// value is the bug this replaced: `--format json` was silently overridden by a
/// config that listed two formats.
fn resolve_formats(cli: &[Format], config: &[String], fallback: &[Format]) -> Vec<Format> {
    if !cli.is_empty() {
        return cli.to_vec();
    }
    let parsed: Vec<Format> = config
        .iter()
        .filter_map(|name| match name.to_ascii_lowercase().as_str() {
            "terminal" => Some(Format::Terminal),
            "markdown" | "md" => Some(Format::Markdown),
            "html" => Some(Format::Html),
            "json" => Some(Format::Json),
            "sarif" => Some(Format::Sarif),
            "sbom" | "cyclonedx" => Some(Format::Sbom),
            "github" | "gh" => Some(Format::Github),
            "gitlab" => Some(Format::Gitlab),
            _ => None,
        })
        .collect();
    if parsed.is_empty() {
        fallback.to_vec()
    } else {
        parsed
    }
}

fn emit(audit: &AuditReport, options: &RunOptions) -> Result<()> {
    let endpoints = &options.endpoints;
    let default_formats: &[Format] = if options.mode == "audit" {
        &[Format::Terminal, Format::Markdown]
    } else {
        &[Format::Terminal]
    };
    let mut formats = resolve_formats(
        &options.formats,
        &options.settings.report.formats,
        default_formats,
    );
    // Inside a CI job the annotation format is what the reviewer actually sees, so
    // add it unless the caller asked for a specific format list.
    if options.formats.is_empty() && options.settings.report.formats.is_empty() {
        if std::env::var_os("GITHUB_ACTIONS").is_some() && !formats.contains(&Format::Github) {
            formats.push(Format::Github);
        } else if std::env::var_os("GITLAB_CI").is_some() && !formats.contains(&Format::Gitlab) {
            formats.push(Format::Gitlab);
        }
    }

    let mut html_report: Option<PathBuf> = None;
    let limit = options.settings.report.terminal_limit.unwrap_or(40);
    let out = options
        .out
        .clone()
        .or_else(|| options.settings.report.out.clone())
        .unwrap_or_else(|| PathBuf::from("deadbolt-report"));

    // `deadbolt scan . --format json | jq` is the obvious way to consume a document
    // format, and it has to work without a temporary directory. When exactly one
    // document format is requested, no destination is given and stdout is a pipe,
    // the document goes to stdout. An interactive terminal still gets a file,
    // because a wall of JSON is not a report anybody reads.
    let stream_to_stdout = options.out.is_none()
        && options.settings.report.out.is_none()
        && formats.len() == 1
        && !std::io::IsTerminal::is_terminal(&std::io::stdout())
        && !matches!(formats[0], Format::Terminal | Format::Html | Format::Github);
    if stream_to_stdout {
        let document = match formats[0] {
            Format::Json => report::json(audit)?,
            Format::Markdown => report::markdown(audit),
            Format::Sarif => report::sarif(audit)?,
            Format::Sbom => sbom::render(audit)?,
            Format::Gitlab => report::gitlab(audit)?,
            _ => unreachable!("stream_to_stdout excludes the interactive formats"),
        };
        println!("{document}");
        return Ok(());
    }

    for format in &formats {
        match format {
            Format::Terminal => print!("{}", report::terminal(audit, options.color, limit)),
            Format::Markdown => {
                let mut body = report::markdown(audit);
                let matrix = authmatrix::render_markdown(endpoints);
                if !matrix.is_empty() {
                    body.push_str(&matrix);
                }
                report::write_file(&out, "deadbolt-report.md", &body)?;
                println!("Report: {}/deadbolt-report.md", out.display());
            }
            Format::Json => {
                report::write_file(&out, "deadbolt-report.json", &report::json(audit)?)?;
                println!("Report: {}/deadbolt-report.json", out.display());
            }
            Format::Sarif => {
                report::write_file(&out, "deadbolt.sarif", &report::sarif(audit)?)?;
                println!("Report: {}/deadbolt.sarif", out.display());
            }
            Format::Github => {
                print!("{}", report::github(audit));
            }
            Format::Gitlab => {
                report::write_file(&out, "deadbolt-gitlab.json", &report::gitlab(audit)?)?;
                println!("Report: {}/deadbolt-gitlab.json", out.display());
            }
            Format::Sbom => {
                report::write_file(&out, "deadbolt-sbom.cdx.json", &sbom::render(audit)?)?;
                println!("Report: {}/deadbolt-sbom.cdx.json", out.display());
            }
            Format::Html => {
                let history = trend::load(std::path::Path::new(&audit.meta.target));
                let sparkline = trend::sparkline(&history);
                report::write_file(
                    &out,
                    "deadbolt-report.html",
                    &report::html::render_with_trend(audit, &sparkline),
                )?;
                println!("Report: {}/deadbolt-report.html", out.display());
                html_report = Some(out.join("deadbolt-report.html"));
            }
        }
    }

    // A report nobody opens is a report nobody reads. Only on a terminal, and only
    // for the format meant for a browser: piped output and CI jobs must not have a
    // browser launched at them.
    if let Some(path) = html_report {
        if options.open_report && ui::interactive() {
            open_in_browser(&path);
        }
    }
    Ok(())
}

/// Collapse identical findings that reached the report through two phases.
fn dedupe(findings: Vec<Finding>) -> Vec<Finding> {
    let mut best: std::collections::HashMap<String, Finding> = std::collections::HashMap::new();
    for finding in findings {
        let key = format!("{}|{}", finding.rule, finding.primary_location());
        match best.get(&key) {
            Some(existing) if existing.severity <= finding.severity => {}
            _ => {
                best.insert(key, finding);
            }
        }
    }
    best.into_values().collect()
}

/// Welcome screen + interactive setup. Returns the argv the user chose.
fn wizard_args() -> Result<Option<Vec<String>>> {
    ui::welcome(env!("CARGO_PKG_VERSION"));

    let target = PathBuf::from(".");
    eprintln!("  Reading Project...");
    let inventory = discover::discover_with(&target, u64::MAX)?;
    let claude = which("claude").map(PathBuf::from);
    ui::project_summary(&target, &inventory, claude.as_deref());
    ui::wizard(&target, &inventory, claude.as_deref())
}

/// Opens a file with the platform handler.
///
/// Failure is deliberately silent: a headless box without a handler is a normal
/// place to run an audit, and the path was already printed.
fn open_in_browser(path: &Path) {
    let command = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(command)
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

fn doctor(target: &Path) -> Result<()> {
    println!("deadbolt doctor");
    println!("{}", "─".repeat(60));
    println!("  Version            {}", env!("CARGO_PKG_VERSION"));

    match discover::discover(target) {
        Ok(inventory) => {
            println!("  Target             {}", inventory.root.display());
            println!(
                "  Files / Lines      {} / {}",
                inventory.stack.total_files, inventory.stack.total_lines
            );
            let languages: Vec<String> = inventory
                .stack
                .languages
                .iter()
                .take(5)
                .map(|language| language.name.clone())
                .collect();
            println!("  Languages          {}", languages.join(", "));
            println!(
                "  Frameworks         {}",
                if inventory.stack.frameworks.is_empty() {
                    "—".to_string()
                } else {
                    inventory.stack.frameworks.join(", ")
                }
            );
            println!("  Manifests          {}", inventory.manifests.len());
        }
        Err(error) => println!("  Target             ERROR: {error:#}"),
    }

    match scan::Engine::new() {
        Ok(engine) => println!(
            "  Checks             {} line rules + {} repo-level = {}",
            engine.rule_count(),
            scan::repo_check_count(),
            engine.rule_count() + scan::repo_check_count()
        ),
        Err(error) => println!("  Static Rules       ERROR: {error:#}"),
    }

    println!(
        "  claude CLI         {}",
        which("claude").unwrap_or_else(|| "Not Found (AI Layer Will Be Skipped)".to_string())
    );
    println!("{}", "─".repeat(60));
    Ok(())
}

fn which(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.display().to_string())
}

fn pack_command(action: &cli::PackAction) -> Result<()> {
    match action {
        cli::PackAction::List => {
            println!("Built-In Packs:\n");
            for name in compliance::built_in_names() {
                match compliance::load_built_in(name) {
                    Ok(pack) => println!(
                        "  {:<12} {:<58} {} controls",
                        pack.name,
                        pack.title,
                        pack.controls.len()
                    ),
                    Err(error) => println!("  {name:<12} ERROR: {error:#}"),
                }
            }
            println!("\nXarici pack: --pack ./my-pack.yaml");
        }
        cli::PackAction::Show { name } => {
            let pack = if name.ends_with(".yaml") || name.ends_with(".yml") {
                compliance::load_file(Path::new(name))?
            } else {
                compliance::load_built_in(name)?
            };
            println!("{} — {} ({})\n", pack.name, pack.title, pack.version);
            if !pack.description.is_empty() {
                println!("{}\n", pack.description.trim());
            }
            for control in &pack.controls {
                let detectable = if control.detected_by.rules.is_empty() {
                    "Manual"
                } else {
                    "auto  "
                };
                println!(
                    "  {:<14} [{:<8}] {:<9} {}",
                    control.id, control.severity, detectable, control.title
                );
            }
            println!("\nTotal: {} Controls", pack.controls.len());
        }
        cli::PackAction::Validate { path } => {
            let pack = compliance::load_file(path)?;
            let manual = pack
                .controls
                .iter()
                .filter(|control| control.detected_by.rules.is_empty())
                .count();
            println!("Pack Is Valid: {} ({})", pack.name, pack.title);
            println!("  Controls: {}", pack.controls.len());
            println!("  Automated:  {}", pack.controls.len() - manual);
            println!("  Manual:     {manual}");
        }
    }
    Ok(())
}

struct BaselineContext {
    settings: config::Settings,
    settings_path: Option<PathBuf>,
    verbose: bool,
}

async fn baseline_command(args: &cli::BaselineArgs, ctx: BaselineContext) -> Result<()> {
    let BaselineContext {
        settings,
        settings_path,
        verbose,
    } = ctx;
    let mut inventory = discover::discover(&args.target)?;

    let ignore = &settings.paths.ignore;
    if !ignore.is_empty() {
        inventory
            .files
            .retain(|file| !glob_any(ignore, &file.rel_path));
    }
    if verbose {
        if let Some(path) = &settings_path {
            eprintln!("   configuration: {}", path.display());
        }
        eprintln!("   files: {}", inventory.files.len());
    }

    let mut findings = scan::scan(&inventory)?;

    let disabled = &settings.scan.disabled_rules;
    findings.retain(|finding| !disabled.contains(&finding.rule));

    if args.with_ai {
        let mut ai_options = ai::AiOptions::new(&inventory.root);
        ai_options.verbose = verbose;
        if let Some(model) = &settings.ai.model {
            ai_options.model = model.clone();
        }
        let outcome = ai::review(&inventory, &ai_options).await;
        for warning in &outcome.warnings {
            eprintln!("   ⚠ {warning}");
        }
        findings.extend(outcome.findings);
    }

    findings = dedupe(findings);

    // The baseline has to hold what the gate will see. Reachability and correlation
    // run after the rule engine in a normal run, so building the baseline from raw
    // scan output left every attack chain outside it: `baseline --write` followed by
    // `scan` still blocked, on findings the user had just accepted.
    if settings.reach.enabled.unwrap_or(true) {
        reach::calibrate(&inventory, &mut findings);
    }
    if settings.chains.enabled.unwrap_or(true) {
        let chains = chain::correlate(&findings);
        findings.extend(chains);
    }
    model::sort_findings(&mut findings);

    let existing = baseline::Baseline::load(&inventory.root);
    let stale = existing
        .as_ref()
        .map(|current| current.stale(&findings).len())
        .unwrap_or(0);

    let mut record = baseline::Baseline::from_findings(&findings, &chrono::Utc::now().to_rfc3339());

    if let (Some(current), false) = (&existing, args.prune) {
        for fingerprint in &current.fingerprints {
            record.fingerprints.insert(fingerprint.clone());
        }
        for entry in &current.entries {
            if !record
                .entries
                .iter()
                .any(|existing_entry| existing_entry.fingerprint == entry.fingerprint)
            {
                record.entries.push(entry.clone());
            }
        }
    }

    let by_severity = |severity: model::Severity| {
        record
            .entries
            .iter()
            .filter(|entry| entry.severity == severity)
            .count()
    };

    println!("Baseline — {}", inventory.root.display());
    println!("{}", "─".repeat(60));
    println!("  Current Findings    {}", findings.len());
    println!("  Baseline Entries    {}", record.entries.len());
    for severity in model::Severity::all() {
        let count = by_severity(severity);
        if count > 0 {
            println!("    {:<16}  {}", severity.label(), count);
        }
    }
    if let Some(current) = &existing {
        println!("  Previous Baseline   {} Entries", current.entries.len());
        if stale > 0 {
            println!(
                "  Stale Entries       {} {}",
                stale,
                if args.prune {
                    "(Being Removed)"
                } else {
                    "(Remove With --prune)"
                }
            );
        }
    }
    if args.with_ai {
        println!("  AI Findings         Included");
    } else {
        println!("  AI Findings         Not Included (Add Them With --with-ai)");
    }
    println!("{}", "─".repeat(60));

    if !args.write {
        println!("To Write It: deadbolt baseline --write");
        return Ok(());
    }

    let path = record.write(&inventory.root)?;
    println!("Written: {}", path.display());
    println!("Commit This File. It Is Expected To SHRINK Over Time.");
    Ok(())
}

fn init_command(args: &cli::InitArgs) -> Result<()> {
    let root = args
        .target
        .canonicalize()
        .unwrap_or_else(|_| args.target.clone());
    let path = root.join(config::FILE_NAME);

    if path.exists() && !args.force {
        anyhow::bail!(
            "{} Already Exists — Use --force To Overwrite",
            path.display()
        );
    }

    std::fs::write(&path, config::Settings::example())
        .with_context(|| format!("Could Not Write: {}", path.display()))?;

    println!("Created: {}", path.display());
    println!();
    println!("Next Steps:");
    println!("  1. deadbolt scan .                     Fast Deterministic Check");
    println!("  2. deadbolt baseline --write           Accept Current Findings");
    println!("  3. deadbolt audit .                     Full Audit (AI + Research, No Cost Limit)");
    println!("  4. deadbolt diff --base main           Check Only The Change In A Pull Request");
    Ok(())
}

async fn portfolio_command(
    args: &cli::PortfolioArgs,
    verbose: bool,
    color: bool,
) -> Result<std::process::ExitCode> {
    let mut targets: Vec<PathBuf> = args.repos.clone();
    if let Some(list) = &args.list {
        targets.extend(portfolio::read_list(list)?);
    }
    if targets.is_empty() {
        anyhow::bail!("No Repository Given: Pass Paths As Arguments Or Use --list");
    }

    let generated_at = chrono::Utc::now().to_rfc3339();
    let mut members: Vec<portfolio::Member> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for target in &targets {
        // `.` and `..` carry no name of their own, so resolve before asking for one:
        // a portfolio row labelled "." tells the reader nothing.
        let name = target
            .canonicalize()
            .ok()
            .and_then(|resolved| {
                resolved
                    .file_name()
                    .map(|value| value.to_string_lossy().to_string())
            })
            .or_else(|| {
                target
                    .file_name()
                    .map(|value| value.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| target.display().to_string());

        if verbose {
            eprintln!("→ {name}");
        }

        let (settings, settings_path) = match target
            .canonicalize()
            .map_err(anyhow::Error::from)
            .and_then(|root| config::Settings::load(&root, None))
        {
            Ok(pair) => pair,
            Err(error) => {
                failures.push(format!("{name}: {error:#}"));
                continue;
            }
        };

        let options = RunOptions {
            target: target.clone(),
            mode: "audit",
            settings,
            settings_path,
            use_baseline: true,
            verify: true,
            open_report: true,
            diff_base: None,
            run_deps: true,
            packs: Vec::new(),
            lenses: Vec::new(),
            model: args.model.clone(),
            concurrency: 4,
            budget: args.budget,
            offline: args.offline,
            ai: args.with_ai,
            research_limit: 30,
            exhaustive: false,
            formats: vec![Format::Terminal],
            out: Some(args.out.clone()),
            fail_on: args.fail_on,
            verbose,
            color,
            endpoints: Vec::new(),
        };

        match analyze(&options).await {
            Ok(analysis) => {
                let policy = gates::Policy::new(
                    args.fail_on.threshold(),
                    &options.settings.gates.path,
                    &options.settings.gates.category,
                );
                let blocking = policy.blocking(&analysis.report.findings).len();
                members.push(portfolio::Member {
                    name,
                    path: target.clone(),
                    report: analysis.report,
                    blocking,
                });
            }
            Err(error) => failures.push(format!("{name}: {error:#}")),
        }
    }

    if members.is_empty() {
        anyhow::bail!(
            "No Repository Could Be Audited:\n  {}",
            failures.join("\n  ")
        );
    }

    portfolio::rank(&mut members);

    // Without a default the loop below iterated over nothing: every repository was
    // audited and not one line was printed. A command that does the work and shows
    // none of it is worse than one that fails.
    let formats: Vec<Format> = if args.formats.is_empty() {
        vec![Format::Terminal, Format::Markdown]
    } else {
        args.formats.clone()
    };

    for format in &formats {
        match format {
            Format::Terminal => print!("{}", portfolio::render_terminal(&members)),
            Format::Markdown => {
                report::write_file(
                    &args.out,
                    "deadbolt-portfolio.md",
                    &portfolio::render_markdown(&members, &generated_at),
                )?;
                println!("Report: {}/deadbolt-portfolio.md", args.out.display());
            }
            Format::Json => {
                report::write_file(
                    &args.out,
                    "deadbolt-portfolio.json",
                    &portfolio::render_json(&members, &generated_at)?,
                )?;
                println!("Report: {}/deadbolt-portfolio.json", args.out.display());
            }
            other => println!("deadbolt: Portfolio Mode Does Not Support The {other:?} Format"),
        }
    }

    for failure in &failures {
        eprintln!("⚠ {failure}");
    }

    let blocking_total: usize = members.iter().map(|member| member.blocking).sum();
    Ok(if blocking_total == 0 && failures.is_empty() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    })
}

fn explain_command(args: &cli::ExplainArgs) -> Result<()> {
    let root = args
        .target
        .canonicalize()
        .unwrap_or_else(|_| args.target.clone());

    if args.list || args.rule.is_none() {
        let rules = scan::all_rules(&root);
        println!("Qaydalar ({}):\n", rules.len());
        let mut by_category: std::collections::BTreeMap<&str, Vec<&scan::ruledef::RuleDef>> =
            std::collections::BTreeMap::new();
        for rule in &rules {
            by_category
                .entry(rule.category.label())
                .or_default()
                .push(rule);
        }
        for (category, group) in by_category {
            println!("  {category}");
            for rule in group {
                println!(
                    "    {:<14} {:<9} {}",
                    rule.id,
                    rule.severity.label(),
                    rule.title
                );
            }
            println!();
        }
        println!("\nCorrelated attack paths:");
        for id in chain::all_ids() {
            if let Some(info) = chain::describe(id) {
                println!(
                    "    {:<14} {:<9} {}",
                    info.id,
                    info.severity.label(),
                    info.title
                );
            }
        }
        println!("\nFor A Single Rule: deadbolt explain <ID>");
        return Ok(());
    }

    let wanted = args.rule.as_deref().unwrap_or_default();

    if let Some(lens_name) = wanted
        .strip_prefix("AI-")
        .or_else(|| wanted.strip_prefix("ai-"))
    {
        if let Some(lens) = ai::prompt::LENSES
            .iter()
            .find(|lens| lens.name.eq_ignore_ascii_case(lens_name))
        {
            println!("AI Lens: {}\n", lens.name);
            println!("{}", lens.skill);
            println!("\nThe Engagement Rules Are Appended To Every Lens Prompt:");
            println!("  skills/_ENGAGEMENT.md");
            println!(
                "Write Your Own Methodology: .deadbolt/skills/{}.md",
                lens.name
            );
            return Ok(());
        }
    }

    if let Some((pack_name, control_id)) = wanted.split_once(':') {
        if let Ok(pack) = compliance::load_built_in(pack_name) {
            if let Some(control) = pack
                .controls
                .iter()
                .find(|control| control.id.eq_ignore_ascii_case(control_id))
            {
                println!("{} {} — {}\n", pack.name, control.id, control.title);
                println!("  Severity    {}", control.severity);
                let detectors = if control.detected_by.rules.is_empty() {
                    "Assessed Manually".to_string()
                } else {
                    control.detected_by.rules.join(", ")
                };
                println!("  Detected By {detectors}");
                if !control.note.is_empty() {
                    println!("  Note        {}", control.note);
                }
                return Ok(());
            }
        }
    }

    let wrap = |text: &str| {
        textwrap::fill(
            text,
            textwrap::Options::new(88)
                .initial_indent("  ")
                .subsequent_indent("  "),
        )
    };

    if let Some(chain) = chain::describe(&wanted.to_uppercase()) {
        println!("{} — {}\n", chain.id, chain.title);
        println!("  Severity    {}", chain.severity.label());
        println!("  Kind        Correlated attack path, derived from other findings");
        println!("\nWHAT IT FINDS");
        println!("{}", wrap("  Every one of these has to be present:"));
        for (index, link) in chain.links.iter().enumerate() {
            println!("  {}. {link}", index + 1);
        }
        println!("\nWHY IT MATTERS\n{}", wrap(chain.impact));
        println!("\nHOW TO FIX IT\n{}", wrap(chain.remediation));
        println!(
            "\n{}",
            wrap(
                "A chain is excluded from the score: its members are already counted \
individually. It exists to say that accepting them separately is not the same as \
accepting the path they form together."
            )
        );
        return Ok(());
    }

    let rule = scan::find_rule(&root, wanted).with_context(|| {
        format!(
            "'{wanted}' Not Found. List Everything: deadbolt explain --list\n\
Note: AI Lenses Use `AI-<name>`, Compliance Controls Use `<pack>:<id>`."
        )
    })?;

    println!("{} — {}\n", rule.id, rule.title);
    println!("  Severity    {}", rule.severity.label());
    println!("  Category    {}", rule.category.label());
    println!(
        "  Source      {}",
        match &rule.source {
            scan::ruledef::RuleSource::BuiltIn => "built-in".to_string(),
            scan::ruledef::RuleSource::User(pack) => format!("Your Own Pack: {pack}"),
        }
    );
    if let Some(cwe) = rule.cwe {
        println!("  CWE         CWE-{cwe} (https://cwe.mitre.org/data/definitions/{cwe}.html)");
    }
    if !rule.asvs.is_empty() {
        println!("  ASVS        {}", rule.asvs.join(", "));
    }
    if !rule.policy.is_empty() {
        println!("  Policy      {}", rule.policy.join(", "));
    }
    println!(
        "  Scope       {:?}, Tests {}",
        rule.scope,
        if rule.skip_tests {
            "Skipped"
        } else {
            "daxildir"
        }
    );

    if !rule.description.is_empty() {
        println!("\nWHAT IT FINDS\n{}", wrap(&rule.description));
    }
    if !rule.impact.is_empty() {
        println!("\nWHY IT MATTERS\n{}", wrap(&rule.impact));
    }
    if !rule.remediation.is_empty() {
        println!("\nHOW TO FIX IT\n{}", wrap(&rule.remediation));
    }

    println!("\nSUSDURMA");
    println!(
        "{}",
        wrap(&format!(
            "Temporary: Append `# deadbolt-ignore {} until=YYYY-MM-DD reason=\"...\"` To The Line. \
The Gate Turns Red By Itself Once That Date Passes. Project Wide: `.deadbolt.toml` -> \
`[scan] disabled_rules = [\"{}\"]` (Write The Reason In A Comment).",
            rule.id, rule.id
        ))
    );
    Ok(())
}

/// One proposed change: additive, non-code, and reversible.
struct Repair {
    path: PathBuf,
    label: String,
    rationale: String,
    /// `None` = create the file with this body; `Some` = append these lines.
    append: Option<Vec<String>>,
    body: String,
}

/// Deliberately narrow.
///
/// Anything that rewrites application code is out of scope: an automatic edit to
/// a query, a timeout or a migration changes behaviour, and a tool that does
/// that unasked is more dangerous than the finding it fixes. What is safe is
/// additive configuration and documentation, which is what this handles.
fn plan_repairs(inventory: &discover::Inventory) -> Vec<Repair> {
    let mut repairs = Vec::new();
    let root = &inventory.root;

    let gitignore_path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
    if !existing.contains(".env") {
        let lines = vec![
            String::new(),
            "# deadbolt: environment files are never committed".to_string(),
            ".env".to_string(),
            ".env.*".to_string(),
            "!.env.example".to_string(),
        ];
        repairs.push(Repair {
            path: gitignore_path.clone(),
            label: if existing.is_empty() {
                "Creating .gitignore".to_string()
            } else {
                "Adding .env Rules To .gitignore".to_string()
            },
            rationale: "Committing An Environment File By Accident Is The Most Common Secret \
Leak Path, And This Is The Only Mechanism That Prevents It."
                .to_string(),
            append: if existing.is_empty() {
                None
            } else {
                Some(lines.clone())
            },
            body: if existing.is_empty() {
                lines.join("\n").trim_start().to_string() + "\n"
            } else {
                lines.join("\n") + "\n"
            },
        });
    }

    let security_path = root.join("SECURITY.md");
    if !security_path.exists() {
        repairs.push(Repair {
            path: security_path,
            label: "Creating SECURITY.md".to_string(),
            rationale: "A Researcher Who Finds A Vulnerability Has No Way To Reach You; Without \
A Channel The Finding Ends Up In Public."
                .to_string(),
            append: None,
            body: "# Security Policy\n\n\
## Reporting A Vulnerability\n\n\
If You Have Found A Vulnerability, **Do Not Open A Public Issue**. Instead:\n\n\
- Email: security@example.com  <- change this\n\
- Response Time: 3 Business Days\n\
- Fix Target: Critical 7 Days, High 30 Days\n\n\
## Scope\n\n\
The Code In This Repository And The Configuration It Uses.\n\n\
## Disclosure\n\n\
Coordinated Disclosure After The Fix Ships. The Reporter Is Credited With \
Their Consent.\n"
                .to_string(),
        });
    }

    let config_path = root.join(config::FILE_NAME);
    if !config_path.exists() {
        repairs.push(Repair {
            path: config_path,
            label: format!("Creating {}", config::FILE_NAME),
            rationale: "Gate Thresholds, Filters And Exceptions Cannot Be Expressed Without A \
Configuration File; Every Run Repeats The Same Noise."
                .to_string(),
            append: None,
            body: config::Settings::example().to_string(),
        });
    }

    repairs
}

fn fix_command(args: &cli::FixArgs) -> Result<()> {
    let inventory = discover::discover(&args.target)?;
    let repairs = plan_repairs(&inventory);

    if repairs.is_empty() {
        println!("deadbolt fix: No Safe Repair Is Available.");
        return Ok(());
    }

    println!(
        "deadbolt fix — {} Suggestion{}\n",
        repairs.len(),
        if args.apply {
            " (Applying)"
        } else {
            " (Preview Only)"
        }
    );

    for repair in &repairs {
        let relative = repair
            .path
            .strip_prefix(&inventory.root)
            .unwrap_or(&repair.path);
        println!("── {} ── {}", relative.display(), repair.label);
        println!("{}", textwrap::fill(&repair.rationale, 86));
        println!();
        for line in repair.body.lines().take(14) {
            println!("  + {line}");
        }
        let total = repair.body.lines().count();
        if total > 14 {
            println!("  + ... {} More Lines", total - 14);
        }
        println!();
    }

    if !args.apply {
        println!("To Apply: deadbolt fix --apply");
        println!("Note: Only Additive Changes That Never Touch Code Are Applied.");
        return Ok(());
    }

    for repair in &repairs {
        match &repair.append {
            Some(_) => {
                let mut current = std::fs::read_to_string(&repair.path).unwrap_or_default();
                if !current.ends_with('\n') && !current.is_empty() {
                    current.push('\n');
                }
                current.push_str(&repair.body);
                std::fs::write(&repair.path, current)
                    .with_context(|| format!("Could Not Write: {}", repair.path.display()))?;
            }
            None => {
                std::fs::write(&repair.path, &repair.body)
                    .with_context(|| format!("Could Not Write: {}", repair.path.display()))?;
            }
        }
        println!("✓ {}", repair.path.display());
    }

    println!("\nWarning: If `.env` Is Already Committed, .gitignore Does NOT Untrack It —");
    println!("Run `git rm --cached .env` And Rotate Every Value.");
    Ok(())
}

async fn watch_command(args: &cli::WatchArgs, color: bool) -> Result<std::process::ExitCode> {
    let root = args
        .target
        .canonicalize()
        .unwrap_or_else(|_| args.target.clone());

    println!("deadbolt watch — {} (Stop With Ctrl+C)", root.display());

    let mut previous: Option<u64> = None;
    loop {
        let inventory = match discover::discover(&root) {
            Ok(inventory) => inventory,
            Err(error) => {
                eprintln!("deadbolt: {error:#}");
                tokio::time::sleep(std::time::Duration::from_millis(args.interval)).await;
                continue;
            }
        };

        let stamp = fingerprint_tree(&inventory);
        if previous != Some(stamp) {
            previous = Some(stamp);

            let findings = match scan::scan(&inventory) {
                Ok(mut findings) => {
                    findings.extend(taint::run(&inventory));
                    findings
                }
                Err(error) => {
                    eprintln!("deadbolt: {error:#}");
                    Vec::new()
                }
            };

            let mut report = AuditReport {
                meta: ReportMeta {
                    tool: "deadbolt".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    target: root.display().to_string(),
                    project: root
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Project".to_string()),
                    started_at: chrono::Utc::now().to_rfc3339(),
                    duration_ms: 0,
                    mode: "watch".to_string(),
                    ai_enabled: false,
                    research_enabled: false,
                    lenses_run: Vec::new(),
                    packs_run: Vec::new(),
                    ai_cost_usd: 0.0,
                    warnings: Vec::new(),
                },
                stack: inventory.stack.clone(),
                score: Default::default(),
                findings: dedupe(findings),
                packages: Vec::new(),
                controls: Vec::new(),
                packs: Vec::new(),
            };
            report.compute_score();

            print!("\x1B[2J\x1B[H");
            print!("{}", report::terminal(&report, color, 15));
        }

        tokio::time::sleep(std::time::Duration::from_millis(args.interval)).await;
    }
}

/// Cheap change signal: size and mtime of every inventoried file.
fn fingerprint_tree(inventory: &discover::Inventory) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for file in &inventory.files {
        file.rel_path.hash(&mut hasher);
        file.size.hash(&mut hasher);
        if let Ok(metadata) = std::fs::metadata(&file.abs_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.duration_since(std::time::UNIX_EPOCH) {
                    elapsed.as_secs().hash(&mut hasher);
                    elapsed.subsec_millis().hash(&mut hasher);
                }
            }
        }
    }
    hasher.finish()
}

#[cfg(test)]
mod format_precedence {
    use super::*;

    #[test]
    fn an_explicit_flag_always_wins_over_config() {
        let resolved = resolve_formats(
            &[Format::Json],
            &["terminal".to_string(), "markdown".to_string()],
            &[Format::Terminal],
        );
        assert_eq!(resolved, vec![Format::Json]);
    }

    #[test]
    fn config_applies_when_no_flag_was_passed() {
        let resolved = resolve_formats(
            &[],
            &["html".to_string(), "sarif".to_string()],
            &[Format::Terminal],
        );
        assert_eq!(resolved, vec![Format::Html, Format::Sarif]);
    }

    #[test]
    fn built_in_default_applies_when_neither_is_set() {
        let resolved = resolve_formats(&[], &[], &[Format::Terminal, Format::Markdown]);
        assert_eq!(resolved, vec![Format::Terminal, Format::Markdown]);
    }

    #[test]
    fn unknown_config_names_fall_back_rather_than_producing_nothing() {
        let resolved = resolve_formats(&[], &["nonsense".to_string()], &[Format::Terminal]);
        assert_eq!(resolved, vec![Format::Terminal]);
    }
}
