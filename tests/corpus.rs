//! Known-bad corpus: proof that the engine still finds what it claims to find.
//!
//! Unit tests check a regex against a string. They cannot catch the failure that
//! matters most in a scanner — a rule that silently stops firing end to end, because
//! a false-positive guard grew too wide, a scope check changed, or a severity was
//! softened by a context heuristic. A clean report then reads as "nothing wrong"
//! when it means "nothing looked".
//!
//! So this runs the real binary over `corpus/`, a tree of deliberately vulnerable
//! files, each defect annotated in place:
//!
//! ```text
//! # deadbolt-expect DB-SEC-001:critical      the NEXT code line must produce this
//! # deadbolt-expect DB-SEC-003:critical DB-SEC-005:high   several rules, one line
//! # deadbolt-gap DB-INF-002                  a KNOWN miss, pinned so it cannot be forgotten
//! # deadbolt-noise DB-AUN-001:high           a KNOWN over-report, pinned the same way
//! # deadbolt-clean                           file level: this file must stay silent
//! ```
//!
//! `gap` and `noise` are the two halves of the same idea: today's wrong answer,
//! written down. Both fail when the engine changes its mind, so improving a pattern
//! shows up as a failing assertion to delete rather than as a silent difference.
//!
//! Reachability weighting and chain correlation are switched off for the run. Both
//! reason across files, and every case here is one isolated file, so leaving them on
//! would pin "unreferenced module" arithmetic instead of the severity each rule
//! actually carries. They have their own tests.
//!
//! The corpus is copied into a temporary directory before the scan, for two reasons.
//! `corpus/**` is excluded in `.deadbolt.toml` so the self-audit does not report the
//! planted defects as its own; scanning the copy bypasses that exclusion. And a path
//! containing `test` or `fixtures` makes `SourceFile::is_test` true, which skips
//! `skip_tests` rules and softens the rest — the copy lands on neutral paths, so the
//! severities asserted here are the production ones.
//!
//! Scope: the comparison covers the rules the corpus asserts. A finding from any
//! other rule (repository-level, taint, chain) is ignored rather than reported as
//! unexpected, so those can evolve without editing this file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Cargo builds the binary for this target and hands over its path.
const DEADBOLT: &str = env!("CARGO_BIN_EXE_deadbolt");

const EXPECT_MARKER: &str = "deadbolt-expect";
const NOISE_MARKER: &str = "deadbolt-noise";
const GAP_MARKER: &str = "deadbolt-gap";
const CLEAN_MARKER: &str = "deadbolt-clean";

/// Written into the staged copy: the corpus pins rule behaviour, not cross-file
/// weighting. `deny_unknown_fields` is on in the settings loader, so this stays
/// minimal on purpose.
const STAGED_SETTINGS: &str = "\
[reach]
enabled = false

[chains]
enabled = false

[trend]
record = false
";

/// One `rule:severity` pair pinned to one line.
type Pin = (u32, String);

#[derive(Default)]
struct Corpus {
    /// (file, line, rule) that must be reported, with the severity it must carry.
    /// Over-reports pinned with `deadbolt-noise` live here too — the assertion is
    /// the same, only the failure message differs.
    expected: BTreeMap<String, BTreeMap<Pin, String>>,
    /// The subset of `expected` that is a known over-report rather than a real defect.
    noise: BTreeSet<(String, u32, String)>,
    /// (file, line, rule) that is known NOT to be reported today.
    gaps: BTreeMap<String, BTreeSet<Pin>>,
    /// Every rule the corpus makes a claim about, in either direction.
    rules_under_test: BTreeSet<String>,
    /// Files carrying the file-level clean marker, for the summary line only.
    clean_files: BTreeSet<String>,
}

fn main_corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

/// Files the scanner reads. Markdown is documentation: it explains the annotation
/// syntax, so parsing it would invent expectations out of its own examples.
fn is_case_file(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) != Some("md")
}

fn case_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect(root, &mut files);
    files.sort();
    files
}

fn collect(directory: &Path, into: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|e| panic!("read {}: {e}", directory.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect(&path, into);
        } else if is_case_file(&path) {
            into.push(path);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("path under corpus root")
        .to_string_lossy()
        .replace('\\', "/")
}

/// Splits `DB-SEC-001:critical` into its two halves.
fn split_pin(token: &str, file: &str, line_no: u32) -> (String, String) {
    let (rule, severity) = token.split_once(':').unwrap_or_else(|| {
        panic!("{file}:{line_no}: annotation token {token:?} is not RULE:SEVERITY")
    });
    (rule.to_string(), severity.to_lowercase())
}

/// Reads the annotations of one file. An annotation applies to the next line that
/// is neither blank nor an annotation itself.
fn parse_case(rel: &str, body: &str, corpus: &mut Corpus) {
    let mut pending_expect: Vec<(String, String, bool)> = Vec::new();
    let mut pending_gap: Vec<String> = Vec::new();

    for (index, line) in body.lines().enumerate() {
        let line_no = index as u32 + 1;

        if line.contains(CLEAN_MARKER) {
            corpus.clean_files.insert(rel.to_string());
            continue;
        }
        let presence = line
            .split_once(EXPECT_MARKER)
            .map(|(_, rest)| (rest, false))
            .or_else(|| line.split_once(NOISE_MARKER).map(|(_, rest)| (rest, true)));
        if let Some((rest, is_noise)) = presence {
            for token in rest.split_whitespace() {
                let token = token.trim_end_matches("-->").trim_end_matches('*');
                if token.is_empty() {
                    continue;
                }
                let (rule, severity) = split_pin(token, rel, line_no);
                pending_expect.push((rule, severity, is_noise));
            }
            continue;
        }
        if let Some((_, rest)) = line.split_once(GAP_MARKER) {
            for token in rest.split_whitespace() {
                let token = token.trim_end_matches("-->").trim_end_matches('*');
                if !token.is_empty() {
                    pending_gap.push(token.to_string());
                }
            }
            continue;
        }
        if line.trim().is_empty() || (pending_expect.is_empty() && pending_gap.is_empty()) {
            continue;
        }

        for (rule, severity, is_noise) in pending_expect.drain(..) {
            corpus.rules_under_test.insert(rule.clone());
            if is_noise {
                corpus
                    .noise
                    .insert((rel.to_string(), line_no, rule.clone()));
            }
            corpus
                .expected
                .entry(rel.to_string())
                .or_default()
                .insert((line_no, rule), severity);
        }
        for rule in pending_gap.drain(..) {
            corpus.rules_under_test.insert(rule.clone());
            corpus
                .gaps
                .entry(rel.to_string())
                .or_default()
                .insert((line_no, rule));
        }
    }

    assert!(
        pending_expect.is_empty() && pending_gap.is_empty(),
        "{rel}: annotation at end of file has no line to apply to"
    );
}

/// Copies the corpus onto neutral paths and returns what it claims.
fn stage(root: &Path) -> Corpus {
    let source = main_corpus_dir();
    assert!(
        source.is_dir(),
        "corpus directory is missing: {}",
        source.display()
    );

    let mut corpus = Corpus::default();
    for path in case_files(&source) {
        let rel = relative(&source, &path);
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        parse_case(&rel, &body, &mut corpus);

        let destination = root.join(&rel);
        std::fs::create_dir_all(destination.parent().expect("case file has a parent"))
            .expect("create case directory");
        std::fs::write(&destination, &body).expect("write case file");
    }

    std::fs::write(root.join(".deadbolt.toml"), STAGED_SETTINGS).expect("write staged settings");

    assert!(
        !corpus.expected.is_empty(),
        "no expectations parsed — the annotation syntax or the corpus layout changed"
    );
    corpus
}

/// (file, line, rule) -> severity, for the deterministic findings of one scan.
fn scan(target: &Path, reports: &Path) -> BTreeMap<(String, u32, String), String> {
    let output = Command::new(DEADBOLT)
        .arg("scan")
        .arg(target)
        .args(["--offline", "--no-baseline", "--no-open", "--no-color"])
        .args(["--fail-on", "never"])
        .args(["--format", "json"])
        .arg("--out")
        .arg(reports)
        .output()
        .unwrap_or_else(|e| panic!("run {DEADBOLT}: {e}"));

    // 0 clean, 1 blocking, 3 degraded (offline by design). 2 is a tool error, and
    // anything else is a crash — either means this test proves nothing.
    let code = output.status.code().unwrap_or(-1);
    assert!(
        matches!(code, 0 | 1 | 3),
        "deadbolt exited {code}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let path = reports.join("deadbolt-report.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\nstdout:\n{}",
            path.display(),
            String::from_utf8_lossy(&output.stdout)
        )
    });
    let report: serde_json::Value = serde_json::from_str(&raw).expect("report is valid JSON");

    let mut found = BTreeMap::new();
    let findings = report["findings"]
        .as_array()
        .expect("report carries a findings array");
    for finding in findings {
        let rule = finding["rule"].as_str().unwrap_or_default().to_string();
        let severity = finding["severity"].as_str().unwrap_or_default().to_string();
        let evidence = match finding["evidence"].as_array() {
            Some(items) => items,
            None => continue,
        };
        for item in evidence {
            let (Some(file), Some(line)) = (item["file"].as_str(), item["line"].as_u64()) else {
                continue;
            };
            found.insert(
                (file.replace('\\', "/"), line as u32, rule.clone()),
                severity.clone(),
            );
        }
    }
    found
}

#[test]
fn corpus_findings_match_their_annotations() {
    let target = tempfile::tempdir().expect("temporary target");
    let reports = tempfile::tempdir().expect("temporary report directory");
    let corpus = stage(target.path());
    let found = scan(target.path(), reports.path());

    let mut missing = Vec::new();
    let mut wrong_severity = Vec::new();
    let mut unexpected = Vec::new();
    let mut closed_gaps = Vec::new();

    for (file, pins) in &corpus.expected {
        for ((line, rule), severity) in pins {
            let key = (file.clone(), *line, rule.clone());
            let is_noise = corpus.noise.contains(&key);
            match found.get(&key) {
                None if is_noise => closed_gaps.push(format!(
                    "{file}:{line} {rule} is no longer over-reported — \
                     remove the {NOISE_MARKER} annotation"
                )),
                None => missing.push(format!("{file}:{line} {rule} ({severity}) not reported")),
                Some(actual) if actual != severity => wrong_severity.push(format!(
                    "{file}:{line} {rule} reported as {actual}, annotated {severity}"
                )),
                Some(_) => {}
            }
        }
    }

    for (file, pins) in &corpus.gaps {
        for (line, rule) in pins {
            if found.contains_key(&(file.clone(), *line, rule.clone())) {
                closed_gaps.push(format!(
                    "{file}:{line} {rule} is now reported — remove the {GAP_MARKER} annotation"
                ));
            }
        }
    }

    let corpus_files: BTreeSet<&String> = corpus
        .expected
        .keys()
        .chain(corpus.gaps.keys())
        .chain(corpus.clean_files.iter())
        .collect();
    for ((file, line, rule), severity) in &found {
        if !corpus.rules_under_test.contains(rule) {
            continue; // out of scope: repository-level, taint, chain
        }
        let claimed = corpus
            .expected
            .get(file)
            .is_some_and(|pins| pins.contains_key(&(*line, rule.clone())));
        if claimed || !corpus_files.contains(&file) {
            continue;
        }
        unexpected.push(format!(
            "{file}:{line} {rule} ({severity}) reported with no annotation"
        ));
    }

    let problems: Vec<&String> = missing
        .iter()
        .chain(wrong_severity.iter())
        .chain(unexpected.iter())
        .chain(closed_gaps.iter())
        .collect();

    assert!(
        problems.is_empty(),
        "the known-bad corpus disagrees with the scan.\n\
         A rule that stopped firing means every clean report since is worth less \
         than it looked.\n\n\
         not reported ({}):\n{}\n\
         wrong severity ({}):\n{}\n\
         reported without an annotation ({}):\n{}\n\
         engine changed its mind about a pinned gap or over-report ({}):\n{}\n\
         corpus: {} rules, {} pinned findings, {} silent files",
        missing.len(),
        indent(&missing),
        wrong_severity.len(),
        indent(&wrong_severity),
        unexpected.len(),
        indent(&unexpected),
        closed_gaps.len(),
        indent(&closed_gaps),
        corpus.rules_under_test.len(),
        corpus.expected.values().map(BTreeMap::len).sum::<usize>(),
        corpus.clean_files.len(),
    );
}

fn indent(lines: &[String]) -> String {
    if lines.is_empty() {
        return "  —\n".to_string();
    }
    lines
        .iter()
        .map(|line| format!("  {line}\n"))
        .collect::<String>()
}
