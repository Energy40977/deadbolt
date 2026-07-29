pub mod catalog;
pub mod repo;
pub mod ruledef;

use anyhow::Result;
use regex::{Regex, RegexSet};

use crate::discover::{Inventory, SourceFile};
use crate::model::{Confidence, Evidence, Finding, Origin, Severity};
use catalog::{Scope, RULES};
use ruledef::{RuleDef, RulePack, RuleSource};

/// Beyond this, extra hits of the same rule in one file are collapsed.
const MAX_PER_RULE_PER_FILE: usize = 3;
/// Beyond this, extra hits of the same rule across the repo are collapsed.
const MAX_PER_RULE_TOTAL: usize = 40;

struct CompiledRule {
    rule: RuleDef,
    pattern: Regex,
    negate: Option<Regex>,
}

pub struct Engine {
    rules: Vec<CompiledRule>,
    prefilter: RegexSet,
}

impl Engine {
    /// Built-in catalogue only.
    pub fn new() -> Result<Self> {
        Self::with_rules(RULES.iter().map(RuleDef::from).collect())
    }

    /// Built-in catalogue plus user rule packs discovered under the target.
    /// A broken pack is reported as a warning, never a hard failure: one bad
    /// user rule must not take the whole audit down.
    pub fn with_user_packs(
        root: &std::path::Path,
        explicit: &[String],
    ) -> (Result<Self>, Vec<String>) {
        let mut defs: Vec<RuleDef> = RULES.iter().map(RuleDef::from).collect();
        let mut warnings = Vec::new();

        for path in ruledef::discover_packs(root, explicit) {
            match RulePack::load(&path).and_then(RulePack::into_defs) {
                Ok(loaded) => {
                    for def in loaded {
                        if defs.iter().any(|existing| existing.id == def.id) {
                            warnings.push(format!(
                                "Duplicate rule id, skipping: {} ({})",
                                def.id,
                                path.display()
                            ));
                            continue;
                        }
                        defs.push(def);
                    }
                }
                Err(error) => {
                    warnings.push(format!("{}: {error:#}", path.display()));
                }
            }
        }

        (Self::with_rules(defs), warnings)
    }

    pub fn with_rules(rules: Vec<RuleDef>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        let mut prefilter_patterns = Vec::with_capacity(rules.len());

        for rule in rules {
            let pattern = Regex::new(&rule.pattern)
                .map_err(|e| anyhow::anyhow!("Rule {} pattern error: {e}", rule.id))?;
            let negate = match &rule.negate {
                Some(raw) => Some(
                    Regex::new(raw)
                        .map_err(|e| anyhow::anyhow!("Rule {} negate error: {e}", rule.id))?,
                ),
                None => None,
            };
            prefilter_patterns.push(format!("(?m){}", rule.pattern));
            compiled.push(CompiledRule {
                rule,
                pattern,
                negate,
            });
        }

        let prefilter = RegexSet::new(&prefilter_patterns)?;
        Ok(Self {
            rules: compiled,
            prefilter,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Fingerprint of the active rule set. A cache entry produced by a
    /// different rule set must never be reused, or a newly added rule would
    /// silently not apply to unchanged files.
    /// Bumped when scan *semantics* change without any rule text changing.
    ///
    /// The fingerprint used to cover rule ids, patterns and text only, so an engine
    /// change — a new false-positive guard, a new test-region boundary — left the
    /// cache valid and served answers the current engine would never produce.
    const ENGINE_REVISION: &'static str = "5";

    pub fn rules_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(Self::ENGINE_REVISION.as_bytes());
        hasher.update(b"\0");
        for compiled in &self.rules {
            hasher.update(compiled.rule.id.as_bytes());
            hasher.update(b"\0");
            hasher.update(compiled.rule.pattern.as_bytes());
            hasher.update(b"\0");
            hasher.update(compiled.rule.title.as_bytes());
            hasher.update(b"\0");
            hasher.update(compiled.rule.remediation.as_bytes());
            hasher.update(b"\0");
            if let Some(negate) = &compiled.rule.negate {
                hasher.update(negate.as_bytes());
            }
            hasher.update(b"\n");
        }
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    pub fn user_rule_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|compiled| compiled.rule.source != RuleSource::BuiltIn)
            .count()
    }

    /// Scans every file, in parallel when there is enough work to justify it.
    ///
    /// Determinism matters more than raw speed here: results are sorted after
    /// the merge, and the per-rule global cap is applied afterwards, so the
    /// output does not depend on thread scheduling.
    pub fn run(&self, inventory: &Inventory) -> Vec<Finding> {
        let workers = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
            .min(8);

        let mut findings = if workers > 1 && inventory.files.len() > 64 {
            let chunk_size = inventory.files.len().div_ceil(workers);
            std::thread::scope(|scope| {
                let handles: Vec<_> = inventory
                    .files
                    .chunks(chunk_size)
                    .map(|chunk| scope.spawn(move || self.run_files(chunk)))
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|handle| handle.join().ok())
                    .flatten()
                    .collect::<Vec<Finding>>()
            })
        } else {
            self.run_files(&inventory.files)
        };

        findings.sort_by(|a, b| {
            a.primary_location()
                .cmp(&b.primary_location())
                .then(a.rule.cmp(&b.rule))
        });

        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        findings.retain(|finding| {
            let counter = seen.entry(finding.rule.clone()).or_insert(0);
            *counter += 1;
            *counter <= MAX_PER_RULE_TOTAL
        });
        findings
    }

    /// Scans one slice of files. Caps here are per file only.
    fn run_files(&self, files: &[SourceFile]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        for file in files {
            if file.content.is_empty() {
                continue;
            }
            let candidates = self.prefilter.matches(&file.content);
            if !candidates.matched_any() {
                continue;
            }

            for index in candidates.iter() {
                let compiled = &self.rules[index];
                let rule = &compiled.rule;

                if !applies(rule, file) {
                    continue;
                }

                let rollback_from = if rule.scope == Scope::Migration {
                    rollback_start(file)
                } else {
                    None
                };
                let tests_from = test_region_start(file);

                let mut hits_in_file = 0usize;
                for (line_no, line) in file.lines_iter() {
                    if hits_in_file >= MAX_PER_RULE_PER_FILE {
                        break;
                    }
                    // An in-file test module runs to end of file, so once the
                    // boundary is passed either every remaining hit is a fixture
                    // (skip) or it needs the same softening a test file gets.
                    if let Some(boundary) = tests_from {
                        if line_no >= boundary && rule.skip_tests {
                            break;
                        }
                    }
                    if let Some(boundary) = rollback_from {
                        if line_no >= boundary {
                            break;
                        }
                    }
                    if line.len() > 2000 {
                        continue; // minified or generated content
                    }
                    if !compiled.pattern.is_match(line) {
                        continue;
                    }
                    if let Some(negate) = &compiled.negate {
                        if negate.is_match(line) {
                            continue;
                        }
                    }
                    if is_commented_out(line, file.language) {
                        continue;
                    }
                    if VALUE_GATED_RULES.contains(&rule.id.as_str())
                        && !secret_value_plausible(line)
                    {
                        continue;
                    }
                    if ENTROPY_GATED_RULES.contains(&rule.id.as_str())
                        && !high_entropy_literal(line)
                    {
                        continue;
                    }

                    hits_in_file += 1;
                    let in_test_region = tests_from.is_some_and(|boundary| line_no >= boundary);
                    findings.push(adjust_for_context(
                        build_finding(rule, file, line_no, line),
                        file,
                        in_test_region,
                    ));
                }
            }
        }

        findings
    }
}

/// Rules whose match only counts if the captured literal is plausibly a secret.
const VALUE_GATED_RULES: &[&str] = &["DB-SEC-001", "DB-INF-003"];
/// Rules gated on Shannon entropy rather than on a name/value shape.
const ENTROPY_GATED_RULES: &[&str] = &["DB-SEC-005"];
/// Below this, a long literal is far more likely to be an identifier than a key.
const MIN_ENTROPY_BITS: f64 = 3.6;

/// First line of a migration's rollback block, if any.
/// First line of an in-file test region, if the language keeps tests beside the
/// code they cover.
///
/// Path-based detection misses this entirely: Rust, Go and Zig put unit tests in
/// the same file under a `#[cfg(test)]` module, conventionally at the end. Every
/// fixture in such a module — a fake API key, an interpolated SQL string, a
/// deliberately broken JWT call — then reads as a live defect. The module runs to
/// end of file by convention, so the first marker is the boundary.
/// Number of repo-level checks, so `doctor` can state total coverage rather than
/// only the line-rule half of it.
pub fn repo_check_count() -> usize {
    repo::REPO_RULE_IDS.len()
}

pub fn test_region_start(file: &SourceFile) -> Option<u32> {
    let markers: &[&str] = match file.language {
        "Rust" => &["#[cfg(test)]", "#[test]"],
        "Go" => &["func Test", "func Benchmark", "func Fuzz"],
        "Zig" => &["test \""],
        _ => return None,
    };
    file.lines_iter().find_map(|(line_no, line)| {
        let trimmed = line.trim_start();
        markers
            .iter()
            .any(|marker| trimmed.starts_with(marker))
            .then_some(line_no)
    })
}

fn rollback_start(file: &SourceFile) -> Option<u32> {
    let markers = [
        "def downgrade",
        "exports.down",
        "function down",
        "async function down",
        "public function down",
        "-- +migrate down",
        "-- +goose down",
        "--rollback",
        "-- down",
        "// +migrate down",
        "@Override public void down",
    ];
    file.lines_iter().find_map(|(line_no, line)| {
        let lowered = line.trim_start().to_lowercase();
        markers
            .iter()
            .any(|marker| lowered.starts_with(marker))
            .then_some(line_no)
    })
}

/// Extract single- and double-quoted literals from a line.
fn quoted_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' && ch != '\'' && ch != '`' {
            continue;
        }
        let quote = ch;
        let mut buffer = String::new();
        while let Some(next) = chars.next() {
            if next == '\\' {
                chars.next();
                continue;
            }
            if next == quote {
                break;
            }
            buffer.push(next);
        }
        if !buffer.is_empty() {
            out.push(buffer);
        }
    }
    out
}

/// Distinguishes a real credential from a configuration key name.
///
/// `accessToken: 'app.access_token'` is a storage key, not a secret; treating
/// every quoted string next to a secret-ish name as a leak is the single
/// largest source of noise in this rule class.
fn secret_value_plausible(line: &str) -> bool {
    quoted_literals(line).iter().any(|value| {
        let length = value.chars().count();
        if length < 12 || value.contains(' ') || value.contains("://") {
            return false;
        }
        let digits = value.chars().filter(char::is_ascii_digit).count();
        let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
        let has_symbol = value.chars().any(|c| "+/=%!$#@^&*".contains(c));

        let identifier_like = value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));

        if identifier_like && !has_upper {
            let dense = length >= 24 && (digits as f64 / length as f64) > 0.15;
            let segmented = value.contains('.') || value.contains('-');
            return dense && !segmented;
        }

        digits > 0 || has_upper || has_symbol
    })
}

/// Shannon entropy per character, in bits.
fn shannon_entropy(value: &str) -> f64 {
    let length = value.chars().count();
    if length == 0 {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for character in value.chars() {
        *counts.entry(character).or_insert(0) += 1;
    }
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length as f64;
            -probability * probability.log2()
        })
        .sum()
}

/// True when a literal on this line looks random rather than structured.
///
/// The entropy floor is what separates a real key from an identifier: a
/// snake_case constant or a dotted path has low entropy even when long, while a
/// generated token approaches the maximum for its alphabet.
fn high_entropy_literal(line: &str) -> bool {
    quoted_literals(line).iter().any(|value| {
        let length = value.chars().count();
        if length < 28 || value.contains(' ') || value.contains('/') {
            return false;
        }
        let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = value.chars().any(|c| c.is_ascii_digit());
        let classes = [has_lower, has_upper, has_digit]
            .iter()
            .filter(|present| **present)
            .count();
        if classes < 2 {
            return false;
        }
        let hex_only = value.chars().all(|c| c.is_ascii_hexdigit());
        if hex_only && !(has_lower && has_upper) {
            return false;
        }
        let separators = value
            .chars()
            .filter(|c| matches!(c, '_' | '-' | '.'))
            .count();
        if separators * 6 > length {
            return false;
        }
        shannon_entropy(value) >= MIN_ENTROPY_BITS
    })
}

/// Findings in test code describe fixtures far more often than live defects.
fn adjust_for_context(finding: Finding, file: &SourceFile, in_test_region: bool) -> Finding {
    if !file.is_test() && !in_test_region {
        return finding;
    }
    let softened = match finding.severity {
        Severity::Critical => Severity::Medium,
        Severity::High => Severity::Low,
        other => other,
    };
    let mut adjusted = finding;
    adjusted.severity = softened;
    adjusted.confidence = Confidence::Probable;
    adjusted.description = format!(
        "{} (Found In Test Code — May Be A Fixture, Severity Lowered)",
        adjusted.description
    );
    adjusted
}

fn applies(rule: &RuleDef, file: &SourceFile) -> bool {
    if rule.skip_tests && file.is_test() {
        return false;
    }
    if !rule.languages.is_empty()
        && !rule
            .languages
            .iter()
            .any(|language| language == file.language)
    {
        return false;
    }
    match rule.scope {
        Scope::Any => true,
        Scope::Code => is_code_language(file.language),
        Scope::Migration => file.is_migration() || file.language == "SQL",
        Scope::Frontend => file.is_frontend(),
        Scope::Infra => {
            file.is_infra() || file.language == "Docker" || file.language == "Terraform"
        }
        Scope::Config => matches!(
            file.language,
            "YAML" | "TOML" | "JSON" | "Config" | "Env" | "XML"
        ),
    }
}

pub(crate) fn is_code_language(language: &str) -> bool {
    !matches!(
        language,
        "YAML" | "JSON" | "TOML" | "XML" | "CSS" | "HTML" | "Make" | "Env" | "Config" | "Lockfile"
    )
}

/// Commented-out code is not a live defect. Cheap, per-language heuristic.
fn is_commented_out(line: &str, language: &str) -> bool {
    let trimmed = line.trim_start();
    let markers: &[&str] = match language {
        "Python" | "Shell" | "YAML" | "Ruby" | "TOML" | "Docker" | "Terraform" | "Make" => &["#"],
        "SQL" => &["--", "/*"],
        "HTML" | "XML" => &["<!--"],
        _ => &["//", "/*", "*"],
    };
    markers.iter().any(|marker| trimmed.starts_with(marker))
}

fn build_finding(rule: &RuleDef, file: &SourceFile, line_no: u32, line: &str) -> Finding {
    let snippet = {
        let trimmed = line.trim();
        if trimmed.chars().count() > 180 {
            let cut: String = trimmed.chars().take(180).collect();
            format!("{cut}…")
        } else {
            trimmed.to_string()
        }
    };

    let mut builder = Finding::builder(&rule.id, rule.category, rule.severity)
        .title(&rule.title)
        .description(&rule.description)
        .impact(&rule.impact)
        .remediation(&rule.remediation)
        .origin(Origin::Static)
        .confidence(Confidence::Confirmed)
        .evidence(Evidence::new(&file.rel_path, Some(line_no), snippet));

    if let Some(cwe) = rule.cwe {
        builder = builder.cwe(cwe);
    }
    for control in &rule.asvs {
        builder = builder.asvs(control.as_str());
    }
    for policy in &rule.policy {
        builder = builder.policy(policy.as_str());
    }
    if let Some(cwe) = rule.cwe {
        builder = builder.reference(format!("https://cwe.mitre.org/data/definitions/{cwe}.html"));
    }

    builder.build()
}

/// Full metadata for one rule id, including user packs under `root`.
pub fn find_rule(root: &std::path::Path, id: &str) -> Option<RuleDef> {
    let (engine, _) = Engine::with_user_packs(root, &[]);
    engine
        .ok()?
        .rules
        .into_iter()
        .map(|compiled| compiled.rule)
        .find(|rule| rule.id.eq_ignore_ascii_case(id))
}

/// Every rule this build can produce, with metadata — used by `explain` and docs.
pub fn all_rules(root: &std::path::Path) -> Vec<RuleDef> {
    let (engine, _) = Engine::with_user_packs(root, &[]);
    engine
        .map(|engine| {
            engine
                .rules
                .into_iter()
                .map(|compiled| compiled.rule)
                .collect()
        })
        .unwrap_or_default()
}

/// Every deterministic rule id this build can produce.
pub fn all_rule_ids() -> Vec<&'static str> {
    RULES
        .iter()
        .map(|rule| rule.id)
        .chain(repo::REPO_RULE_IDS.iter().copied())
        .collect()
}

/// Incremental cache: findings per file, keyed by size and mtime.
///
/// Invalidated wholesale when the rule set changes — reusing an entry produced
/// by a different rule set would mean a newly added rule silently skips every
/// unchanged file, which is a correctness bug disguised as a speed-up.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanCache {
    #[serde(default)]
    rules_fingerprint: String,
    #[serde(default)]
    entries: std::collections::HashMap<String, Vec<Finding>>,
}

fn cache_key(file: &SourceFile) -> Option<String> {
    let metadata = std::fs::metadata(&file.abs_path).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(format!(
        "{}|{}|{}.{}",
        file.rel_path,
        metadata.len(),
        modified.as_secs(),
        modified.subsec_millis()
    ))
}

impl ScanCache {
    fn path(cache_dir: &std::path::Path) -> std::path::PathBuf {
        cache_dir.join("scan-v1.json")
    }

    fn load(cache_dir: &std::path::Path, fingerprint: &str) -> Self {
        std::fs::read_to_string(Self::path(cache_dir))
            .ok()
            .and_then(|body| serde_json::from_str::<Self>(&body).ok())
            .filter(|cache| cache.rules_fingerprint == fingerprint)
            .unwrap_or_else(|| Self {
                rules_fingerprint: fingerprint.to_string(),
                entries: std::collections::HashMap::new(),
            })
    }

    fn save(&self, cache_dir: &std::path::Path) {
        if std::fs::create_dir_all(cache_dir).is_err() {
            return;
        }
        if let Ok(body) = serde_json::to_string(self) {
            let _ = std::fs::write(Self::path(cache_dir), body);
        }
    }
}

impl Engine {
    /// Scans only files whose size or mtime changed; reuses the rest.
    pub fn run_incremental(
        &self,
        inventory: &Inventory,
        cache_dir: &std::path::Path,
    ) -> (Vec<Finding>, usize) {
        let fingerprint = self.rules_fingerprint();
        let previous = ScanCache::load(cache_dir, &fingerprint);

        let mut reused: Vec<Finding> = Vec::new();
        let mut to_scan: Vec<SourceFile> = Vec::new();
        let mut next = ScanCache {
            rules_fingerprint: fingerprint,
            entries: std::collections::HashMap::new(),
        };
        let mut hits = 0usize;

        for file in &inventory.files {
            match cache_key(file) {
                Some(key) => match previous.entries.get(&key) {
                    Some(cached) => {
                        hits += 1;
                        reused.extend(cached.iter().cloned());
                        next.entries.insert(key, cached.clone());
                    }
                    None => to_scan.push(file.clone()),
                },
                None => to_scan.push(file.clone()),
            }
        }

        let scanned = self.run_files(&to_scan);
        for file in &to_scan {
            if let Some(key) = cache_key(file) {
                let per_file: Vec<Finding> = scanned
                    .iter()
                    .filter(|finding| {
                        finding
                            .evidence
                            .first()
                            .map(|evidence| evidence.file == file.rel_path)
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                next.entries.insert(key, per_file);
            }
        }
        next.save(cache_dir);

        let mut findings = reused;
        findings.extend(scanned);
        findings.sort_by(|a, b| {
            a.primary_location()
                .cmp(&b.primary_location())
                .then(a.rule.cmp(&b.rule))
        });

        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        findings.retain(|finding| {
            let counter = seen.entry(finding.rule.clone()).or_insert(0);
            *counter += 1;
            *counter <= MAX_PER_RULE_TOTAL
        });

        (findings, hits)
    }
}

/// Convenience entry point: built-in rules only. Used by `watch` and tests.
pub fn scan(inventory: &Inventory) -> Result<Vec<Finding>> {
    let engine = Engine::new()?;
    let mut findings = engine.run(inventory);
    findings.extend(repo::audit(inventory));
    Ok(findings)
}

/// Entry point that also loads project rule packs. Returns warnings separately
/// so a malformed pack surfaces in the report instead of aborting the run.
/// `cache_dir` enables the incremental cache; `None` scans everything.
pub fn scan_with_options(
    inventory: &Inventory,
    explicit_packs: &[String],
    cache_dir: Option<&std::path::Path>,
) -> (Result<Vec<Finding>>, Vec<String>, usize) {
    let (engine, mut warnings) = Engine::with_user_packs(&inventory.root, explicit_packs);
    match engine {
        Ok(engine) => {
            let user_rules = engine.user_rule_count();
            let mut findings = match cache_dir {
                Some(directory) => {
                    let (findings, hits) = engine.run_incremental(inventory, directory);
                    if hits > 0 {
                        warnings.push(format!(
                            "Cache: {hits}/{} Files Unchanged, Not Rescanned",
                            inventory.files.len()
                        ));
                    }
                    findings
                }
                None => engine.run(inventory),
            };
            findings.extend(repo::audit(inventory));
            (Ok(findings), warnings, user_rules)
        }
        Err(error) => {
            warnings.push(format!("Rule Engine Failed To Load: {error:#}"));
            (Err(error), warnings, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::SourceFile;
    use crate::model::StackProfile;
    use std::path::PathBuf;

    fn inventory(name: &str, body: &str) -> Inventory {
        Inventory {
            root: PathBuf::from("/tmp/test"),
            files: vec![SourceFile {
                rel_path: name.to_string(),
                abs_path: PathBuf::from(name),
                language: if name.ends_with(".py") {
                    "Python"
                } else if name.ends_with(".sql") {
                    "SQL"
                } else {
                    "TypeScript"
                },
                size: body.len() as u64,
                lines: body.lines().count(),
                content: body.to_string(),
                truncated: false,
            }],
            stack: StackProfile::default(),
            manifests: Vec::new(),
            skipped_large: 0,
            skipped_large_names: Vec::new(),
        }
    }

    fn rules_hit(name: &str, body: &str) -> Vec<String> {
        let engine = Engine::new().expect("rules must load");
        let mut hits: Vec<String> = engine
            .run(&inventory(name, body))
            .into_iter()
            .map(|finding| finding.rule)
            .collect();
        hits.sort();
        hits.dedup();
        hits
    }

    #[test]
    fn all_rules_compile() {
        let engine = Engine::new().expect("every pattern must be valid");
        assert!(engine.rule_count() >= 40);
    }

    #[test]
    fn detects_interpolated_sql_regardless_of_driver_method() {
        for call in [
            r#"await db.fetch_one(f"SELECT * FROM orders WHERE id={oid}")"#,
            r#"cur.execute(f"DELETE FROM sessions WHERE user={uid}")"#,
            r#"conn.fetchrow(f"UPDATE users SET name={n} WHERE id={i}")"#,
        ] {
            assert!(
                rules_hit("app/x.py", call).contains(&"DB-INJ-001".to_string()),
                "should have been detected: {call}"
            );
        }
    }

    #[test]
    fn parameterised_queries_and_plain_messages_are_not_sql_injection() {
        let safe = r#"
db.execute("SELECT * FROM users WHERE id = :id", {"id": uid})
db.execute("SELECT * FROM users WHERE id = %s", (uid,))
cur.execute("INSERT INTO t (a,b) VALUES (?, ?)", (a, b))
label = f"UPDATE {count} records"
message = f"DELETE requested by {user}"
"#;
        assert!(
            !rules_hit("app/x.py", safe).contains(&"DB-INJ-001".to_string()),
            "yalan pozitiv: {:?}",
            rules_hit("app/x.py", safe)
        );
    }

    #[test]
    fn template_literal_sql_is_detected() {
        let body = "const r = await sql(`SELECT * FROM t WHERE id = ${id}`);";
        assert!(rules_hit("app/x.ts", body).contains(&"DB-INJ-001".to_string()));
    }

    #[test]
    fn commented_out_code_is_ignored() {
        let body = "# db.execute(f\"SELECT * FROM users WHERE n={n}\")\n";
        assert!(rules_hit("app/x.py", body).is_empty());
    }

    #[test]
    fn migration_rollback_block_is_not_flagged() {
        let body = "def upgrade():\n    op.add_column('users', 'x')\n\ndef downgrade():\n    op.drop_column('users', 'x')\n";
        assert!(!rules_hit("migrations/001.py", body).contains(&"DB-MIG-002".to_string()));
    }

    #[test]
    fn migration_upgrade_block_is_flagged() {
        let body =
            "def upgrade():\n    op.drop_column('users', 'old')\n\ndef downgrade():\n    pass\n";
        assert!(rules_hit("migrations/001.py", body).contains(&"DB-MIG-002".to_string()));
    }

    #[test]
    fn storage_key_names_are_not_secrets() {
        let body =
            "const KEYS = { accessToken: 'app.access_token', refreshToken: 'app.refresh_token' };";
        assert!(!rules_hit("app/storage.ts", body).contains(&"DB-SEC-001".to_string()));
    }

    #[test]
    fn real_credentials_are_secrets() {
        let body = r#"API_KEY = "sk_live_aB3xY9zQ7mN2pL5kR8wT1vC4""#;
        let hits = rules_hit("app/config.py", body);
        assert!(
            hits.contains(&"DB-SEC-001".to_string()) || hits.contains(&"DB-SEC-003".to_string())
        );
    }

    #[test]
    fn word_boundaries_prevent_acronym_collisions() {
        let body = r#"@router.post("/trades/{offer_id}/accept")"#;
        assert!(!rules_hit("app/api.py", body).contains(&"DB-CRY-003".to_string()));
    }
}

#[cfg(test)]
mod entropy_tests {
    use super::*;

    #[test]
    fn generated_tokens_have_high_entropy() {
        assert!(high_entropy_literal(
            r#"TOKEN = "aB3xY9zQ7mN2pL5kR8wT1vC4dF6gH0jK""#
        ));
        assert!(high_entropy_literal(
            r#"key: "Zm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRkdI""#
        ));
    }

    #[test]
    fn identifiers_and_hashes_are_not_flagged() {
        assert!(!high_entropy_literal(
            r#"KEY = "application.user.session.storage.key""#
        ));
        assert!(!high_entropy_literal(
            r#"h = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#
        ));
        assert!(!high_entropy_literal(
            r#"sum = "abcdef0123456789abcdef0123456789""#
        ));
        assert!(!high_entropy_literal(
            r#"msg = "this is a long human readable sentence""#
        ));
        assert!(!high_entropy_literal(
            r#"p = "/very/long/path/that/keeps/going/on""#
        ));
    }

    #[test]
    fn short_literals_are_ignored() {
        assert!(!high_entropy_literal(r#"k = "aB3xY9zQ""#));
    }

    #[test]
    fn entropy_is_computed_over_the_alphabet() {
        assert!(shannon_entropy("aaaa") < 0.1);
        assert!(shannon_entropy("abcd") > 1.9);
    }
}
