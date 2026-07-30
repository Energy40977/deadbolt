mod markers;
pub mod prompt;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::discover::{Inventory, SourceFile};
use crate::model::{
    Category, Confidence, DataCollection, Evidence, Finding, Origin, Package, PackageResearch,
    Severity,
};
use prompt::{Lens, LENSES};

const CODE_TOOLS: &str = "Read,Grep,Glob";
const RESEARCH_TOOLS: &str = "Read,Grep,Glob,WebSearch,WebFetch";
const MAX_FILES_LISTED: usize = 720;
/// Files per subagent.
///
/// Measured on a 912-file monorepo: a shard costs about $3.4 regardless of whether
/// it holds 70 files or 240, because the cost sits in reasoning rather than in the
/// listing. Small shards therefore multiply spend without buying much latency —
/// 70-file shards turned one audit into 64 subagents and $220. Wide shards with a
/// low cap keep the parallelism that matters and the bill close to the old one.
const SHARD_TARGET_FILES: usize = 180;
const MAX_SHARDS_PER_LENS: usize = 3;
/// Observed mean cost of one lens subagent, used only to warn before spending.
const COST_PER_JOB_USD: f64 = 3.4;

/// One unit of AI work: a lens over a slice of the file list.
///
/// A lens over 700 files spends most of its turn allowance discovering where to
/// look, and the wall clock is the sum of that discovery. Splitting the same lens
/// across several subagents that each own a slice turns the sum into a maximum,
/// and each subagent has turns left for reasoning instead of listing.
struct Job<'a> {
    lens: &'a Lens,
    /// `1/3`, or empty when the lens is not split.
    shard: String,
    files: Vec<String>,
}

/// Splits a file list into directory-local slices.
///
/// The list is sorted by path first, so consecutive entries share a directory and
/// each subagent sees a coherent part of the system rather than a random sample.
fn shard_files(files: Vec<String>) -> Vec<(String, Vec<String>)> {
    if files.len() <= SHARD_TARGET_FILES {
        return vec![(String::new(), files)];
    }
    let mut sorted = files;
    sorted.sort();

    let count = sorted
        .len()
        .div_ceil(SHARD_TARGET_FILES)
        .min(MAX_SHARDS_PER_LENS);
    let per = sorted.len().div_ceil(count);

    sorted
        .chunks(per)
        .enumerate()
        .map(|(index, chunk)| (format!("{}/{}", index + 1, count), chunk.to_vec()))
        .collect()
}

/// Default reasoning model. Minimum supported tier is `claude-opus-4-7`.
pub const DEFAULT_MODEL: &str = "claude-opus-5";
/// Anything below this tier is rejected with a warning rather than silently used.
pub const MODEL_FLOOR: &[&str] = &["claude-opus-5", "claude-opus-4-7", "claude-opus-4-8"];

/// Live progress events. The AI phase runs for minutes with nothing to show;
/// the caller decides how to render these (bar, log line, or nothing at all).
pub enum Event {
    ReconStarted,
    VerifyPlan {
        total: usize,
    },
    VerifyDone {
        title: String,
        kept: bool,
        cost_usd: f64,
    },
    ReconDone {
        lines: usize,
        cost_usd: f64,
        cached: bool,
    },
    /// Emitted once, after lens selection, so a bar can be sized.
    LensPlan {
        total: usize,
        estimate_usd: f64,
    },
    LensStarted {
        name: &'static str,
        files: usize,
    },
    LensDone {
        name: &'static str,
        findings: usize,
        cost_usd: f64,
        cached: bool,
        tokens: u64,
        turns: u32,
    },
    LensFailed {
        name: &'static str,
        error: String,
    },
    LensSkipped {
        name: &'static str,
    },
    ResearchDone {
        name: String,
        ok: bool,
        cost_usd: f64,
    },
}

pub type EventSink = Arc<dyn Fn(Event) + Send + Sync>;

/// Turn allowance for the recon pass: it reads widely but answers once.
const RECON_TURNS: u32 = 60;
/// Marker regions quoted into a lens prompt.
///
/// Enough to work from, bounded so the prompt cannot itself become the cost.
const EXCERPT_BUDGET: usize = 60;
/// Below this file count the lenses can discover the layout themselves, and a
/// recon pass would cost more than it saves.
const RECON_MIN_FILES: usize = 40;
/// Refuters per finding. Two independent attempts, and a finding survives only if
/// neither of them can refute it.
const REFUTERS: usize = 2;
/// Verification runs on the severe findings only: a low-severity claim is not
/// worth two extra calls, and it never blocks a pipeline anyway.
const VERIFY_MAX: usize = 60;
const REFUTE_TURNS: u32 = 12;

pub struct AiOptions {
    pub model: String,
    pub concurrency: usize,
    pub timeout: Duration,
    pub max_turns: u32,
    pub budget_usd: Option<f64>,
    pub cache_dir: PathBuf,
    pub lenses: Vec<String>,
    /// Paths excluded from the file listing handed to a lens.
    pub forbidden_paths: Vec<String>,
    pub cache: bool,
    pub verbose: bool,
    pub events: Option<EventSink>,
    /// Adversarial verification of severe AI findings.
    pub verify: bool,
    /// Verify findings at this severity or worse. Defaults to the gate threshold, so
    /// the spend follows what the run would actually block on.
    pub verify_above: Severity,
}

impl AiOptions {
    pub fn new(root: &Path) -> Self {
        Self {
            model: DEFAULT_MODEL.to_string(),
            concurrency: 8,
            timeout: Duration::from_secs(600),
            max_turns: 22,
            budget_usd: None,
            cache_dir: root.join(".deadbolt-cache"),
            lenses: Vec::new(),
            forbidden_paths: Vec::new(),
            cache: true,
            verbose: false,
            events: None,
            verify: true,
            verify_above: Severity::High,
        }
    }
}

#[derive(Default)]
pub struct AiOutcome {
    pub findings: Vec<Finding>,
    pub lenses_run: Vec<String>,
    pub cost_usd: f64,
    pub warnings: Vec<String>,
}

pub fn cli_available() -> bool {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|directory| directory.join("claude").is_file())
        })
        .unwrap_or(false)
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    result: String,
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    subtype: String,
    #[serde(default)]
    total_cost_usd: f64,
    #[serde(default)]
    errors: Vec<String>,
    #[serde(default)]
    num_turns: u32,
    #[serde(default)]
    usage: Usage,
}

/// Token accounting from the CLI envelope.
///
/// Cost was the only number being read, which made it impossible to tell whether a
/// subagent was expensive because of the prompt or because of its own reading. The
/// prompt is about eleven thousand tokens; the loop is what costs money, and that
/// only becomes visible once these are recorded.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

impl Usage {
    fn total(&self) -> u64 {
        self.input_tokens
            + self.output_tokens
            + self.cache_read_input_tokens
            + self.cache_creation_input_tokens
    }
}

struct Invocation {
    text: String,
    cost_usd: f64,
    usage: Usage,
    turns: u32,
}

/// Marker returned by a lens that never ran because the budget was already
/// spent; aggregated into one warning instead of one per lens.
const BUDGET_SKIP: &str = "__budget__";

fn emit(options: &AiOptions, event: Event) {
    if let Some(sink) = &options.events {
        sink(event);
    }
}

/// Package research is web-bound: a handful of searches plus a few fetches.
const RESEARCH_TURNS: u32 = 20;

/// `error_max_turns` means the agent spent its whole allowance reading and never
/// emitted an answer — the work is lost, not partial. Repeating the same prompt
/// fails the same way, so the retry states a hard reading limit, insists on an
/// answer, and doubles the turn allowance.
async fn invoke_answering(
    root: &Path,
    prompt: &str,
    tools: &str,
    options: &AiOptions,
    max_turns: u32,
) -> Result<Invocation, (String, f64)> {
    let first = invoke(root, prompt, tools, options, max_turns).await;
    let (error, spent) = match first {
        Err((error, spent)) if error.starts_with("error_max_turns") => (error, spent),
        other => return other,
    };

    let nudge = format!(
        "{prompt}\n\nSTEP LIMIT: read at most {reads} files, then return the final JSON IMMEDIATELY. \
Do not try to read everything. Mark anything you are not certain about as `confidence: \"possible\"` \
— but you must answer; an empty answer is not accepted.",
        reads = (max_turns / 3).max(3)
    );
    match invoke(root, &nudge, tools, options, (max_turns * 2).min(120)).await {
        Ok(mut invocation) => {
            invocation.cost_usd += spent;
            Ok(invocation)
        }
        Err((second, extra)) => Err((format!("{second} (first attempt: {error})"), spent + extra)),
    }
}

async fn invoke(
    root: &Path,
    prompt: &str,
    tools: &str,
    options: &AiOptions,
    max_turns: u32,
) -> Result<Invocation, (String, f64)> {
    let mut command = Command::new("claude");
    command
        .arg("-p")
        .arg(prompt)
        .arg("--output-format")
        .arg("json")
        .arg("--model")
        .arg(&options.model)
        .arg("--max-turns")
        .arg(max_turns.to_string())
        .arg("--allowedTools")
        .arg(tools)
        .current_dir(root)
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command
        .spawn()
        .map_err(|error| (format!("Could Not Start 'claude': {error}"), 0.0))?;

    let output = match tokio::time::timeout(options.timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err((format!("Process Error: {error}"), 0.0)),
        Err(_) => {
            return Err((
                format!("Timed Out After {}s", options.timeout.as_secs()),
                0.0,
            ))
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let envelope: Option<Envelope> = serde_json::from_str(&stdout).ok();

    match envelope {
        Some(envelope) if !envelope.is_error => Ok(Invocation {
            text: envelope.result,
            cost_usd: envelope.total_cost_usd,
            usage: envelope.usage,
            turns: envelope.num_turns,
        }),
        Some(envelope) => {
            let detail = envelope
                .errors
                .first()
                .cloned()
                .unwrap_or_else(|| envelope.result.chars().take(160).collect());
            Err((
                format!("{}: {}", envelope.subtype, detail),
                envelope.total_cost_usd,
            ))
        }
        None if output.status.success() && !stdout.trim().is_empty() => Ok(Invocation {
            text: stdout.into_owned(),
            cost_usd: 0.0,
            usage: Usage::default(),
            turns: 0,
        }),
        None => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail = stderr.lines().last().unwrap_or("Reason Unknown");
            Err((
                format!(
                    "exit {:?}: {}",
                    output.status.code(),
                    &tail[..tail.len().min(160)]
                ),
                0.0,
            ))
        }
    }
}

/// Strip fences and locate the first JSON value in a model response.
fn extract_json(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    let without_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|rest| rest.trim_start())
        .unwrap_or(trimmed);
    let cleaned = without_fence
        .strip_suffix("```")
        .unwrap_or(without_fence)
        .trim();

    let start = cleaned.find(['[', '{'])?;
    let opener = cleaned.as_bytes()[start];
    let closer = if opener == b'[' { b']' } else { b'}' };
    let end = cleaned.rfind(closer as char)?;
    (end > start).then(|| &cleaned[start..=end])
}

/// Content fingerprint of the files a job owns.
///
/// The prompt only names paths and line counts, so an edit that keeps the line
/// count would reuse a stale answer. Hashing the contents makes the cache
/// content-addressed: unchanged slices are free and instant on the next run,
/// changed ones re-run. That is what makes a second audit cheap.
fn content_fingerprint(inventory: &Inventory, files: &[String]) -> String {
    let mut hasher = Sha256::new();
    for entry in files {
        let path = entry.split(" (").next().unwrap_or(entry);
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        if let Some(file) = inventory
            .files
            .iter()
            .find(|candidate| candidate.rel_path == path)
        {
            hasher.update(file.content.as_bytes());
        }
        hasher.update(b"\n");
    }
    crate::model::hex(&hasher.finalize())
}

fn cache_key(kind: &str, model: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{kind}|{model}|{payload}").as_bytes());
    format!("{kind}-{}", crate::model::hex(&hasher.finalize()))[..40.min(kind.len() + 33)]
        .to_string()
}

fn cache_read(options: &AiOptions, key: &str) -> Option<String> {
    if !options.cache {
        return None;
    }
    std::fs::read_to_string(options.cache_dir.join(format!("{key}.json"))).ok()
}

fn cache_write(options: &AiOptions, key: &str, value: &str) {
    if !options.cache {
        return;
    }
    if std::fs::create_dir_all(&options.cache_dir).is_ok() {
        let _ = std::fs::write(options.cache_dir.join(format!("{key}.json")), value);
    }
}

#[derive(Deserialize)]
struct RawFinding {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    impact: String,
    #[serde(default)]
    scenario: String,
    #[serde(default)]
    remediation: String,
    #[serde(default)]
    cwe: Option<u32>,
}

fn lens_category(lens: &str) -> Category {
    match lens {
        "authz" => Category::Authorization,
        "data" => Category::DataProtection,
        "failure" => Category::ErrorHandling,
        "crypto" => Category::Cryptography,
        "migration" => Category::Database,
        "api" => Category::ApiContract,
        "frontend" => Category::Frontend,
        "infra" => Category::Infrastructure,
        _ => Category::Compliance,
    }
}

/// A project may replace any lens methodology by dropping its own
/// `.deadbolt/skills/<lens>.md`. Falls back to the embedded skill.
fn load_skill(root: &Path, lens: &Lens) -> (String, bool) {
    let override_path = root
        .join(".deadbolt/skills")
        .join(format!("{}.md", lens.name));
    match std::fs::read_to_string(&override_path) {
        Ok(body) if !body.trim().is_empty() => (body, true),
        _ => (lens.skill.to_string(), false),
    }
}

/// Lines in this slice that the lens actually cares about, with a little context.
///
/// The prompt used to name files and leave the agent to read them. Reading is what
/// costs: every file pulled into context is re-sent on every following turn, so a
/// forty-turn agent pays for the same file dozens of times. Handing it the matching
/// lines up front turns most of that reading into verification of something it can
/// already see.
fn evidence_excerpts(
    inventory: &Inventory,
    lens: &Lens,
    files: &[String],
    budget: usize,
) -> (String, usize) {
    const CONTEXT: usize = 3;
    let mut out = String::new();
    let mut shown = 0usize;

    for entry in files {
        if shown >= budget {
            break;
        }
        let path = entry.split(" (").next().unwrap_or(entry);
        let Some(file) = inventory
            .files
            .iter()
            .find(|candidate| candidate.rel_path == path)
        else {
            continue;
        };

        let lines: Vec<&str> = file.content.lines().collect();
        let mut hits: Vec<usize> = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if lens.markers.iter().any(|marker| line.contains(marker)) {
                hits.push(index);
            }
        }
        if hits.is_empty() {
            continue;
        }

        // Merge neighbouring hits so one region is quoted once rather than three
        // overlapping times.
        let mut regions: Vec<(usize, usize)> = Vec::new();
        for hit in hits {
            let start = hit.saturating_sub(CONTEXT);
            let end = (hit + CONTEXT).min(lines.len().saturating_sub(1));
            match regions.last_mut() {
                Some(last) if start <= last.1 + 1 => last.1 = end.max(last.1),
                _ => regions.push((start, end)),
            }
        }

        out.push_str(&format!("\n--- {path}\n"));
        for (start, end) in regions {
            if shown >= budget {
                break;
            }
            for (offset, line) in lines[start..=end].iter().enumerate() {
                out.push_str(&format!("{:>5}| {line}\n", start + offset + 1));
            }
            out.push_str("      ...\n");
            shown += 1;
        }
    }

    (out, shown)
}

/// Keeps only the files this lens has a reason to look at, and reports how many were
/// dropped.
///
/// A file with none of the lens's markers cannot produce a finding for it, so paying
/// a subagent to read it buys nothing. The saving is in the slice count: fewer files
/// means fewer slices, and a slice is a whole subagent.
fn narrow_to_signal(
    inventory: &Inventory,
    lens: &Lens,
    files: Vec<String>,
) -> (Vec<String>, usize) {
    if lens.markers.is_empty() {
        return (files, 0);
    }
    let before = files.len();
    let kept: Vec<String> = files
        .into_iter()
        .filter(|entry| {
            let path = entry.split(" (").next().unwrap_or(entry);
            inventory
                .files
                .iter()
                .find(|candidate| candidate.rel_path == path)
                .is_some_and(|file| {
                    lens.markers
                        .iter()
                        .any(|marker| file.content.contains(marker))
                })
        })
        .collect();
    let dropped = before - kept.len();
    (kept, dropped)
}

fn relevant_files(inventory: &Inventory, lens: &Lens, forbidden: &[String]) -> Vec<String> {
    let mut paths: Vec<&SourceFile> = inventory
        .files
        .iter()
        .filter(|file| {
            if file.is_test() {
                return false;
            }
            if crate::glob_any(forbidden, &file.rel_path) {
                return false;
            }
            if lens.hints.is_empty() {
                return crate::scan::is_code_language(file.language);
            }
            let lowered = file.rel_path.to_lowercase();
            lens.hints.iter().any(|hint| lowered.contains(hint))
        })
        .collect();

    paths.sort_by_key(|file| std::cmp::Reverse(file.lines));
    paths
        .into_iter()
        .take(MAX_FILES_LISTED)
        .map(|file| format!("{} ({} lines)", file.rel_path, file.lines))
        .collect()
}

fn to_finding(raw: RawFinding, lens: &str, known: &HashSet<String>) -> Option<Finding> {
    if raw.title.trim().is_empty() {
        return None;
    }

    let mut confidence = Confidence::parse(&raw.confidence);
    let file = raw.file.trim().to_string();

    if !file.is_empty() && !known.contains(&file) {
        confidence = Confidence::Possible;
    }

    let mut severity = Severity::parse(&raw.severity);
    if severity == Severity::Info {
        severity = Severity::Low;
    }
    if confidence == Confidence::Possible && severity < Severity::Medium {
        severity = Severity::Medium;
    }

    let mut builder = Finding::builder(format!("AI-{lens}"), lens_category(lens), severity)
        .title(raw.title.trim())
        .description(raw.description.trim())
        .impact(raw.impact.trim())
        .scenario(raw.scenario.trim())
        .remediation(raw.remediation.trim())
        .origin(Origin::Ai)
        .lens(lens)
        .confidence(confidence)
        .evidence(Evidence::new(
            if file.is_empty() {
                "<project>".to_string()
            } else {
                file
            },
            raw.line.filter(|line| *line > 0),
            String::new(),
        ));

    if let Some(cwe) = raw.cwe.filter(|cwe| *cwe > 0) {
        builder = builder.cwe(cwe);
        builder = builder.reference(format!("https://cwe.mitre.org/data/definitions/{cwe}.html"));
    }

    Some(builder.build())
}

/// Warn — but do not block — when a model below the supported tier is requested.
/// The user may have a reason; they should just know the trade-off they are making.
pub fn model_warning(model: &str) -> Option<String> {
    if MODEL_FLOOR.iter().any(|allowed| model.starts_with(allowed)) {
        return None;
    }
    Some(format!(
        "Model '{model}' Is Below The Recommended Tier (Minimum: claude-opus-4-7). \
The Lenses Have To Reason About Reachability; Smaller Models Produce Plausible-Looking \
Findings That Fail Verification."
    ))
}

/// One pass that maps routes, defences, models and sinks for every lens to reuse.
///
/// Without it each lens spends most of its turn allowance rediscovering the same
/// structure, and eight lenses over eight shards repeat that work sixty-four
/// times. The map is cached on the file inventory, so a second run is free.
async fn recon(inventory: &Inventory, options: &AiOptions) -> (Option<String>, f64, Vec<String>) {
    let files = relevant_files_all(inventory, &options.forbidden_paths);
    if files.len() < RECON_MIN_FILES {
        return (None, 0.0, Vec::new());
    }

    let prompt = prompt::build_recon_prompt(&inventory.stack, &files);
    let key = cache_key(
        "recon",
        &options.model,
        &format!("{prompt}|{}", content_fingerprint(inventory, &files)),
    );

    if let Some(cached) = cache_read(options, &key) {
        emit(
            options,
            Event::ReconDone {
                lines: cached.lines().count(),
                cost_usd: 0.0,
                cached: true,
            },
        );
        return (Some(cached), 0.0, Vec::new());
    }

    emit(options, Event::ReconStarted);
    match invoke_answering(&inventory.root, &prompt, CODE_TOOLS, options, RECON_TURNS).await {
        Ok(invocation) => {
            let map = invocation.text.trim().to_string();
            cache_write(options, &key, &map);
            emit(
                options,
                Event::ReconDone {
                    lines: map.lines().count(),
                    cost_usd: invocation.cost_usd,
                    cached: false,
                },
            );
            (Some(map), invocation.cost_usd, Vec::new())
        }
        Err((error, cost)) => (
            None,
            cost,
            vec![format!(
                "Recon Pass Failed ({error}) — The Lenses Run Without A Map, Which Costs Coverage"
            )],
        ),
    }
}

/// Every code file, for the recon pass. Lenses get filtered subsets; the map has
/// to see the whole system or it will describe half of it.
fn relevant_files_all(inventory: &Inventory, forbidden: &[String]) -> Vec<String> {
    let mut paths: Vec<&SourceFile> = inventory
        .files
        .iter()
        .filter(|file| {
            !file.is_test()
                && !crate::glob_any(forbidden, &file.rel_path)
                && crate::scan::is_code_language(file.language)
        })
        .collect();
    paths.sort_by_key(|file| std::cmp::Reverse(file.lines));
    paths
        .into_iter()
        .take(MAX_FILES_LISTED)
        .map(|file| format!("{} ({} lines)", file.rel_path, file.lines))
        .collect()
}

#[derive(Deserialize)]
struct RawVerdict {
    #[serde(default)]
    refuted: bool,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    severity_should_be: String,
}

/// Adversarial verification: every severe AI finding is handed to independent
/// refuters, and it survives only if none of them can knock it down.
///
/// This is the difference between a tool that produces plausible findings and one
/// whose findings can be acted on without a second opinion. Runs concurrently, so
/// the wall-clock cost is one extra round rather than one round per finding.
async fn verify(
    inventory: &Inventory,
    options: &AiOptions,
    findings: Vec<Finding>,
) -> (Vec<Finding>, f64, Vec<String>) {
    // Verify what would block a pipeline, not everything severe. A medium finding
    // that nothing gates on does not justify two more subagents, and the confidence
    // it carries already says it is unconfirmed.
    let (mut candidates, mut passthrough): (Vec<Finding>, Vec<Finding>) =
        findings.into_iter().partition(|finding| {
            finding.origin == Origin::Ai && finding.severity <= options.verify_above
        });

    if candidates.is_empty() {
        return (passthrough, 0.0, Vec::new());
    }

    let mut warnings = Vec::new();
    if candidates.len() > VERIFY_MAX {
        candidates.sort_by_key(|finding| finding.severity);
        let dropped = candidates.split_off(VERIFY_MAX);
        warnings.push(format!(
            "{} AI Findings Were Not Adversarially Verified (Limit {VERIFY_MAX}) — They Are \
Reported With Their Original Confidence",
            dropped.len()
        ));
        passthrough.extend(dropped);
    }

    emit(
        options,
        Event::VerifyPlan {
            total: candidates.len(),
        },
    );

    let results = stream::iter(candidates)
        .map(|finding| async move {
            let evidence = finding.evidence.first();
            let prompt = prompt::build_refute_prompt(
                &finding.title,
                evidence.map(|e| e.file.as_str()).unwrap_or("(unknown)"),
                evidence.and_then(|e| e.line),
                &finding.description,
                &finding.scenario,
                &finding.lens,
            );

            let votes = stream::iter(0..REFUTERS)
                .map(|_| {
                    let prompt = prompt.clone();
                    async move {
                        invoke_answering(
                            &inventory.root,
                            &prompt,
                            CODE_TOOLS,
                            options,
                            REFUTE_TURNS,
                        )
                        .await
                    }
                })
                .buffer_unordered(REFUTERS)
                .collect::<Vec<_>>()
                .await;

            let mut cost = 0.0;
            let mut refutations: Vec<String> = Vec::new();
            let mut downgrade: Option<Severity> = None;
            let mut answered = 0usize;

            for vote in votes {
                match vote {
                    Ok(invocation) => {
                        cost += invocation.cost_usd;
                        let json = extract_json(&invocation.text).unwrap_or("{}");
                        if let Ok(verdict) = serde_json::from_str::<RawVerdict>(json) {
                            answered += 1;
                            if verdict.refuted {
                                refutations.push(verdict.reason);
                            } else if !verdict.severity_should_be.trim().is_empty() {
                                let proposed = Severity::parse(&verdict.severity_should_be);
                                if proposed > finding.severity {
                                    downgrade = Some(match downgrade {
                                        Some(current) if current > proposed => current,
                                        _ => proposed,
                                    });
                                }
                            }
                        }
                    }
                    Err((_, spent)) => cost += spent,
                }
            }

            (finding, refutations, downgrade, answered, cost)
        })
        .buffer_unordered(options.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut total_cost = 0.0;
    let mut refuted = 0usize;
    let mut kept = Vec::new();

    for (mut finding, refutations, downgrade, answered, cost) in results {
        total_cost += cost;

        if !refutations.is_empty() {
            refuted += 1;
            emit(
                options,
                Event::VerifyDone {
                    title: finding.title.clone(),
                    kept: false,
                    cost_usd: cost,
                },
            );
            continue;
        }

        if answered == 0 {
            // Nobody could be reached, so nothing was proven either way: the
            // finding stays, but it must not claim verified status.
            finding.confidence = Confidence::Possible;
        } else {
            finding.confidence = Confidence::Confirmed;
            finding.description = format!(
                "{} [Verified: {answered} independent reviewers could not refute this.]",
                finding.description
            );
        }
        if let Some(severity) = downgrade {
            finding.severity = severity;
        }

        emit(
            options,
            Event::VerifyDone {
                title: finding.title.clone(),
                kept: true,
                cost_usd: cost,
            },
        );
        kept.push(finding);
    }

    if refuted > 0 {
        warnings.push(format!(
            "{refuted} AI Findings Were Refuted During Verification And Removed From The Report"
        ));
    }

    kept.extend(passthrough);
    (kept, total_cost, warnings)
}

pub async fn review(inventory: &Inventory, options: &AiOptions) -> AiOutcome {
    if !cli_available() {
        return AiOutcome {
            warnings: vec!["'claude' CLI Not Found — AI Layer Skipped".to_string()],
            ..Default::default()
        };
    }

    let mut early_warnings = Vec::new();
    if let Some(warning) = model_warning(&options.model) {
        early_warnings.push(warning);
    }

    let selected: Vec<&Lens> = LENSES
        .iter()
        .filter(|lens| {
            if !options.lenses.is_empty() {
                return options.lenses.iter().any(|name| name == lens.name);
            }
            lens.hints.is_empty()
                || lens
                    .hints
                    .iter()
                    .any(|hint| inventory.has_path_containing(hint))
        })
        .collect();

    if selected.is_empty() {
        return AiOutcome {
            warnings: vec!["No Matching AI Lens Found".to_string()],
            ..Default::default()
        };
    }

    let (recon_map, recon_cost, recon_warnings) = recon(inventory, options).await;
    let recon_map: Option<Arc<str>> = recon_map.map(|map| Arc::from(map.as_str()));
    early_warnings.extend(recon_warnings);

    let mut dropped_files = 0usize;
    let jobs: Vec<Job> = selected
        .iter()
        .flat_map(|lens| {
            let all = relevant_files(inventory, lens, &options.forbidden_paths);
            // Filtering by marker per *file* rather than per slice is what removes
            // subagents. Gating whole slices saved almost nothing: at a hundred and
            // eighty files a slice, one marker is always somewhere in it. Dropping the
            // files that hold no marker shrinks the slice count instead — on a
            // 7000-file monorepo, nineteen subagents become eleven.
            let narrowed = narrow_to_signal(inventory, lens, all);
            dropped_files += narrowed.1;
            shard_files(narrowed.0)
                .into_iter()
                .filter(|(_, files)| !files.is_empty())
                .map(|(shard, files)| Job { lens, shard, files })
                .collect::<Vec<_>>()
        })
        .collect();

    if jobs.is_empty() {
        return AiOutcome {
            warnings: vec!["No File Matched Any AI Lens".to_string()],
            ..Default::default()
        };
    }

    if dropped_files > 0 {
        early_warnings.push(format!(
            "{dropped_files} File-Lens Pairs Were Dropped Because The File Holds None Of That \
Lens's Markers, Which Is What Keeps The Subagent Count Down"
        ));
    }

    emit(
        options,
        Event::LensPlan {
            total: jobs.len(),
            estimate_usd: jobs.len() as f64 * COST_PER_JOB_USD,
        },
    );

    let known: Arc<HashSet<String>> = Arc::new(
        inventory
            .files
            .iter()
            .map(|file| file.rel_path.clone())
            .collect(),
    );
    let spent_micros = Arc::new(AtomicU64::new(0));
    let budget_micros = options
        .budget_usd
        .map(|budget| (budget * 1_000_000.0) as u64);

    let results = stream::iter(jobs.iter())
        .map(|job| {
            let known = Arc::clone(&known);
            let spent = Arc::clone(&spent_micros);
            let recon_map = recon_map.clone();
            let lens = job.lens;
            async move {
                if let Some(limit) = budget_micros {
                    if spent.load(Ordering::Relaxed) >= limit {
                        emit(options, Event::LensSkipped { name: lens.name });
                        return (
                            lens.name,
                            Vec::new(),
                            0.0,
                            Some(BUDGET_SKIP.to_string()),
                        );
                    }
                }

                let files = &job.files;

                emit(
                    options,
                    Event::LensStarted {
                        name: lens.name,
                        files: files.len(),
                    },
                );
                let (skill, overridden) = load_skill(&inventory.root, lens);
                if overridden && options.verbose {
                    eprintln!("   lens {:<9} using local skill", lens.name);
                }
                let (excerpts, regions) =
                    evidence_excerpts(inventory, lens, files, EXCERPT_BUDGET);
                let mut text = prompt::build_lens_prompt(
                    lens,
                    &skill,
                    &inventory.stack,
                    files,
                    recon_map.as_deref(),
                    &excerpts,
                );
                let _ = regions;
                if !job.shard.is_empty() {
                    // Several subagents share this lens. Each one owns its slice for
                    // reporting, but may Grep anywhere: a control that protects the
                    // slice often lives outside it.
                    text.push_str(&format!(
                        "\n\nASSIGNED SLICE: {} of this lens. Report findings for the files \
listed above only. You may Grep and Read anywhere in the repository to verify whether a \
control exists — but do not report defects that belong to another slice.\n",
                        job.shard
                    ));
                }
                if !options.forbidden_paths.is_empty() {
                    text.push_str(&format!(
                        "\n\nOUT OF SCOPE: do NOT look at the following paths and do not report findings about them:\n{}\n",
                        options.forbidden_paths.join("\n")
                    ));
                }
                let key = cache_key(
                    lens.name,
                    &options.model,
                    &format!("{text}|{}", content_fingerprint(inventory, files)),
                );

                if let Some(cached) = cache_read(options, &key) {
                    let parsed: Vec<RawFinding> =
                        serde_json::from_str(&cached).unwrap_or_default();
                    let findings: Vec<Finding> = parsed
                        .into_iter()
                        .filter_map(|raw| to_finding(raw, lens.name, &known))
                        .collect();
                    emit(
                        options,
                        Event::LensDone {
                            name: lens.name,
                            findings: findings.len(),
                            cost_usd: 0.0,
                            cached: true,
                            tokens: 0,
                            turns: 0,
                        },
                    );
                    return (lens.name, findings, 0.0, None);
                }

                match invoke_answering(&inventory.root, &text, CODE_TOOLS, options, options.max_turns)
                    .await
                {
                    Ok(invocation) => {
                        spent.fetch_add(
                            (invocation.cost_usd * 1_000_000.0) as u64,
                            Ordering::Relaxed,
                        );
                        let json = extract_json(&invocation.text).unwrap_or("[]");
                        let parsed: Vec<RawFinding> = serde_json::from_str(json).unwrap_or_default();
                        cache_write(options, &key, json);
                        let findings: Vec<Finding> = parsed
                            .into_iter()
                            .filter_map(|raw| to_finding(raw, lens.name, &known))
                            .collect();
                        if options.verbose {
                            eprintln!(
                                "   lens {:<9} {:<5} {} findings  ${:.4}",
                                lens.name,
                                job.shard,
                                findings.len(),
                                invocation.cost_usd
                            );
                        }
                        emit(
                            options,
                            Event::LensDone {
                                name: lens.name,
                                findings: findings.len(),
                                cost_usd: invocation.cost_usd,
                                cached: false,
                                tokens: invocation.usage.total(),
                                turns: invocation.turns,
                            },
                        );
                        (lens.name, findings, invocation.cost_usd, None)
                    }
                    Err((error, cost)) => {
                        spent.fetch_add((cost * 1_000_000.0) as u64, Ordering::Relaxed);
                        emit(
                            options,
                            Event::LensFailed {
                                name: lens.name,
                                error: error.clone(),
                            },
                        );
                        (
                            lens.name,
                            Vec::new(),
                            cost,
                            Some(format!("lens {}: {error}", lens.name)),
                        )
                    }
                }
            }
        })
        .buffer_unordered(options.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut outcome = AiOutcome::default();
    outcome.cost_usd += recon_cost;
    outcome.warnings.extend(early_warnings);
    let mut budget_skipped: Vec<&str> = Vec::new();
    for (lens, findings, cost, warning) in results {
        outcome.cost_usd += cost;
        match warning.as_deref() {
            Some(BUDGET_SKIP) => budget_skipped.push(lens),
            Some(_) => outcome.warnings.push(warning.unwrap_or_default()),
            None => outcome.lenses_run.push(lens.to_string()),
        }
        outcome.findings.extend(findings);
    }

    budget_skipped.sort_unstable();
    budget_skipped.dedup();
    if !budget_skipped.is_empty() {
        let ran = outcome.lenses_run.len();
        let estimate = if ran > 0 {
            let per_lens = outcome.cost_usd / ran as f64;
            outcome.cost_usd + per_lens * budget_skipped.len() as f64
        } else {
            outcome.cost_usd
        };
        outcome.warnings.push(format!(
            "The AI Cost Limit (${:.2}) Was Reached — {} Lenses Did Not Run: {}. The Lenses That \
Ran Cost ${:.2}; Roughly ${:.2} Is Needed For All Of Them (`--budget {:.0}`).",
            options.budget_usd.unwrap_or(0.0),
            budget_skipped.len(),
            budget_skipped.join(", "),
            outcome.cost_usd,
            estimate,
            estimate.ceil().max(1.0),
        ));
    }
    outcome.lenses_run.sort();
    outcome.lenses_run.dedup();

    if options.verify {
        let (kept, cost, warnings) =
            verify(inventory, options, std::mem::take(&mut outcome.findings)).await;
        outcome.findings = kept;
        outcome.cost_usd += cost;
        outcome.warnings.extend(warnings);
    }

    // Sharded subagents can land on the same defect from two sides, and a repo-wide
    // absence ("no rate limiting anywhere") is reported by whichever slice noticed.
    let mut seen: HashSet<String> = HashSet::new();
    outcome.findings.retain(|finding| {
        seen.insert(format!(
            "{}|{}|{}",
            finding.rule,
            finding.primary_location(),
            finding.title.to_lowercase()
        ))
    });
    outcome
}

#[derive(Deserialize)]
struct RawResearch {
    #[serde(default)]
    collects_personal_data: String,
    #[serde(default)]
    data_collected: String,
    #[serde(default)]
    endpoints: String,
    #[serde(default)]
    opt_out: String,
    #[serde(default)]
    maintenance_status: String,
    #[serde(default)]
    incidents: String,
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    recommendation: String,
    #[serde(default)]
    sources: Vec<String>,
}

/// Deep tier: one headless call per shortlisted package, with web access.
pub async fn research_packages(
    root: &Path,
    packages: &[Package],
    signals: &[Vec<String>],
    options: &AiOptions,
) -> (Vec<(String, PackageResearch)>, f64, Vec<String>) {
    if packages.is_empty() || !cli_available() {
        return (Vec::new(), 0.0, Vec::new());
    }

    let spent_micros = Arc::new(AtomicU64::new(0));
    let budget_micros = options
        .budget_usd
        .map(|budget| (budget * 1_000_000.0) as u64);

    let jobs: Vec<(Package, Vec<String>)> = packages
        .iter()
        .cloned()
        .zip(signals.iter().cloned())
        .collect();

    let results = stream::iter(jobs)
        .map(|(package, signal_labels)| {
            let spent = Arc::clone(&spent_micros);
            async move {
                if let Some(limit) = budget_micros {
                    if spent.load(Ordering::Relaxed) >= limit {
                        return (package.name.clone(), None, 0.0, None);
                    }
                }

                let text = prompt::build_research_prompt(
                    &package.name,
                    &package.version,
                    &package.ecosystem,
                    &signal_labels,
                );
                let key = cache_key("pkg", &options.model, &text);

                if let Some(cached) = cache_read(options, &key) {
                    if let Ok(raw) = serde_json::from_str::<RawResearch>(&cached) {
                        return (package.name.clone(), Some(convert(raw)), 0.0, None);
                    }
                }

                match invoke_answering(root, &text, RESEARCH_TOOLS, options, RESEARCH_TURNS).await {
                    Ok(invocation) => {
                        spent.fetch_add(
                            (invocation.cost_usd * 1_000_000.0) as u64,
                            Ordering::Relaxed,
                        );
                        let json = extract_json(&invocation.text).unwrap_or("{}");
                        match serde_json::from_str::<RawResearch>(json) {
                            Ok(raw) => {
                                cache_write(options, &key, json);
                                if options.verbose {
                                    eprintln!(
                                        "   package {:<28} ${:.4}",
                                        package.name, invocation.cost_usd
                                    );
                                }
                                emit(
                                    options,
                                    Event::ResearchDone {
                                        name: package.name.clone(),
                                        ok: true,
                                        cost_usd: invocation.cost_usd,
                                    },
                                );
                                (
                                    package.name.clone(),
                                    Some(convert(raw)),
                                    invocation.cost_usd,
                                    None,
                                )
                            }
                            Err(error) => (
                                package.name.clone(),
                                None,
                                invocation.cost_usd,
                                Some(format!(
                                    "{}: Could Not Read The Response ({error})",
                                    package.name
                                )),
                            ),
                        }
                    }
                    Err((error, cost)) => {
                        spent.fetch_add((cost * 1_000_000.0) as u64, Ordering::Relaxed);
                        emit(
                            options,
                            Event::ResearchDone {
                                name: package.name.clone(),
                                ok: false,
                                cost_usd: cost,
                            },
                        );
                        (
                            package.name.clone(),
                            None,
                            cost,
                            Some(format!("{}: {error}", package.name)),
                        )
                    }
                }
            }
        })
        .buffer_unordered(options.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut research = Vec::new();
    let mut total_cost = 0.0;
    let mut failed: Vec<String> = Vec::new();
    for (name, outcome, cost, warning) in results {
        total_cost += cost;
        if warning.is_some() {
            failed.push(name.clone());
        }
        if let Some(outcome) = outcome {
            research.push((name, outcome));
        }
    }

    let mut warnings = Vec::new();
    if !failed.is_empty() {
        let shown: Vec<&str> = failed.iter().take(5).map(String::as_str).collect();
        let rest = failed.len().saturating_sub(shown.len());
        warnings.push(format!(
            "{} Packages Could Not Be Researched Deeply: {}{}. They Stay \"Unknown\" In The Report \
— The Vulnerability Lookup (OSV) Still Ran For Them. To Retry, Lower `--research-limit` \
Or Run Without `--exhaustive`.",
            failed.len(),
            shown.join(", "),
            if rest > 0 {
                format!(" And {rest} More")
            } else {
                String::new()
            }
        ));
    }
    (research, total_cost, warnings)
}

fn convert(raw: RawResearch) -> PackageResearch {
    PackageResearch {
        collects_personal_data: DataCollection::parse(&raw.collects_personal_data),
        data_collected: raw.data_collected.trim().to_string(),
        endpoints: raw.endpoints.trim().to_string(),
        opt_out: raw.opt_out.trim().to_string(),
        maintenance_status: raw.maintenance_status.trim().to_string(),
        incidents: raw.incidents.trim().to_string(),
        verdict: raw.verdict.trim().to_string(),
        recommendation: raw.recommendation.trim().to_string(),
        sources: raw.sources,
    }
}

#[cfg(test)]
mod shard_tests {
    use super::*;

    fn files(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("apps/web/src/f{i:03}.ts"))
            .collect()
    }

    #[test]
    fn a_small_lens_is_not_split() {
        let shards = shard_files(files(40));
        assert_eq!(shards.len(), 1);
        assert!(
            shards[0].0.is_empty(),
            "an unsplit lens carries no shard label"
        );
        assert_eq!(shards[0].1.len(), 40);
    }

    #[test]
    fn a_large_lens_is_split_without_losing_a_file() {
        let count = SHARD_TARGET_FILES * 2 + 1;
        let shards = shard_files(files(count));
        assert_eq!(
            shards.len(),
            3,
            "just over two target slices must produce three"
        );
        let total: usize = shards.iter().map(|(_, files)| files.len()).sum();
        assert_eq!(total, count, "splitting must not drop a file");
        assert_eq!(shards[0].0, "1/3");
        assert_eq!(shards[2].0, "3/3");
    }

    #[test]
    fn the_shard_count_is_capped() {
        let shards = shard_files(files(4000));
        assert_eq!(shards.len(), MAX_SHARDS_PER_LENS);
        let total: usize = shards.iter().map(|(_, files)| files.len()).sum();
        assert_eq!(total, 4000, "capping the count must not drop files");
    }

    #[test]
    fn slices_stay_directory_local() {
        let mut mixed = vec![
            "backend/app/a.py".to_string(),
            "apps/web/z.ts".to_string(),
            "backend/app/b.py".to_string(),
            "apps/web/y.ts".to_string(),
        ];
        mixed.extend(files(SHARD_TARGET_FILES * 2));
        let shards = shard_files(mixed);
        assert!(shards.len() > 1, "the input must be large enough to split");
        let first = &shards[0].1;
        assert!(
            first.iter().all(|path| path.starts_with("apps/")),
            "the first slice must not mix top-level directories: {first:?}"
        );
    }
}

#[cfg(test)]
mod cost_tests {
    use super::*;
    use crate::discover::SourceFile;
    use crate::model::StackProfile;
    use std::path::PathBuf;

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            rel_path: path.to_string(),
            abs_path: PathBuf::from(path),
            language: "Python",
            size: content.len() as u64,
            lines: content.lines().count(),
            content: content.to_string(),
            truncated: false,
        }
    }

    fn inventory(files: Vec<SourceFile>) -> Inventory {
        Inventory {
            root: PathBuf::from("/tmp/x"),
            files,
            stack: StackProfile::default(),
            manifests: Vec::new(),
            skipped_large: 0,
            skipped_large_names: Vec::new(),
        }
    }

    fn lens() -> Lens {
        Lens {
            name: "test",
            skill: "",
            hints: &[],
            markers: &["current_user", "get_object_or_404"],
        }
    }

    #[test]
    fn a_file_without_a_marker_is_dropped_and_one_with_it_is_kept() {
        let store = inventory(vec![
            file("app/util.py", "def add(a, b):\n    return a + b\n"),
            file("app/view.py", "obj = get_object_or_404(Order, pk=pk)\n"),
        ]);
        let (kept, dropped) = narrow_to_signal(
            &store,
            &lens(),
            vec!["app/util.py".to_string(), "app/view.py".to_string()],
        );
        assert_eq!(kept, vec!["app/view.py".to_string()]);
        assert_eq!(
            dropped, 1,
            "the file with no marker cannot produce a finding"
        );
    }

    #[test]
    fn a_lens_without_markers_keeps_everything() {
        let store = inventory(vec![file("app/util.py", "x = 1\n")]);
        let bare = Lens {
            name: "bare",
            skill: "",
            hints: &[],
            markers: &[],
        };
        let (kept, dropped) = narrow_to_signal(&store, &bare, vec!["app/util.py".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn excerpts_carry_the_matching_line_with_context_and_a_line_number() {
        let body = (1..=20)
            .map(|n| {
                if n == 10 {
                    "    obj = get_object_or_404(Order, pk=pk)".to_string()
                } else {
                    format!("    x{n} = {n}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let store = inventory(vec![file("app/view.py", &body)]);
        let (text, regions) = evidence_excerpts(&store, &lens(), &["app/view.py".to_string()], 10);

        assert_eq!(regions, 1);
        assert!(text.contains("app/view.py"));
        assert!(
            text.contains("   10| "),
            "the hit keeps its line number: {text}"
        );
        assert!(text.contains("    7| "), "three lines of context above");
        assert!(text.contains("   13| "), "three lines of context below");
        assert!(!text.contains("    6| "), "and no more than that");
    }

    #[test]
    fn neighbouring_hits_are_quoted_once() {
        let body = "a\ncurrent_user\nb\ncurrent_user\nc\n";
        let store = inventory(vec![file("app/view.py", body)]);
        let (_, regions) = evidence_excerpts(&store, &lens(), &["app/view.py".to_string()], 10);
        assert_eq!(regions, 1, "two hits three lines apart are one region");
    }

    #[test]
    fn the_excerpt_budget_is_respected() {
        let body = (0..200)
            .map(|n| format!("current_user  # {n}\n\n\n\n\n\n\n\n"))
            .collect::<String>();
        let store = inventory(vec![file("app/view.py", &body)]);
        let (_, regions) = evidence_excerpts(&store, &lens(), &["app/view.py".to_string()], 5);
        assert!(regions <= 5, "budget honoured, got {regions}");
    }
}
