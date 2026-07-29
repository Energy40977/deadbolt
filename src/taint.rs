use std::collections::HashMap;

use regex::Regex;

use crate::discover::{Inventory, SourceFile};
use crate::model::{Category, Confidence, Evidence, Finding, Origin, Severity};

/// Where untrusted data enters a function.
const SOURCES: &[&str] = &[
    r"request\.(?:args|form|json|data|values|files|cookies|headers|GET|POST|body|query|params)",
    r"\breq\.(?:body|query|params|headers|cookies)",
    r"\bctx\.request\.(?:body|query)",
    r"\bparams\[|\bquery\[|\bbody\[",
    r"\bgetParameter\s*\(|\bgetHeader\s*\(",
    r"\bos\.environ\.get\s*\(\s*['\x22](?:USER|INPUT)",
    r"\binput\s*\(\s*\)",
    r"\bsys\.argv\b",
    r"\bc\.Query\s*\(|\bc\.Param\s*\(|\bc\.PostForm\s*\(",
    r"\bFormValue\s*\(|\bURL\.Query\(\)",
];

struct Sink {
    id: &'static str,
    pattern: &'static str,
    category: Category,
    severity: Severity,
    title: &'static str,
    impact: &'static str,
    remediation: &'static str,
    cwe: u32,
    /// A parameterised call is safe even though the sink name matches.
    safe: Option<&'static str>,
}

const SINKS: &[Sink] = &[
    Sink {
        id: "DB-FLOW-001",
        pattern: r"(?:execute|executemany|executescript|query|raw|fetch_one|fetch_all|fetchrow|fetchval|scalar|queryRow|Query)\s*\(",
        category: Category::Injection,
        severity: Severity::Critical,
        title: "User Input Flows Into A Database Query",
        impact: "SQL injection: the database can be read, modified or dropped, and authentication bypassed.",
        remediation: "Switch to a parameterised query and never concatenate the value into the query text.",
        cwe: 89,
        safe: Some(r"%s\b|\?|:\w+\b|\$\d"),
    },
    Sink {
        id: "DB-FLOW-002",
        pattern: r"(?:os\.system|subprocess\.[a-z_]+|child_process\.exec|Runtime\.getRuntime\(\)\.exec|shell_exec|passthru|exec\.Command)\s*\(",
        category: Category::Injection,
        severity: Severity::Critical,
        title: "User Input Flows Into A System Command",
        impact: "Command injection: arbitrary commands run on the server, which means full compromise.",
        remediation: "Call the binary with an argument list and no shell, and validate the input against an allowlist.",
        cwe: 78,
        safe: None,
    },
    Sink {
        id: "DB-FLOW-003",
        pattern: r"(?:open|readFile|readFileSync|sendFile|serveFile|createReadStream|File)\s*\(",
        category: Category::Injection,
        severity: Severity::High,
        title: "User Input Flows Into A File Path",
        impact: "Path traversal: system files can be read or written with `../` (`/etc/passwd`, `.env`).",
        remediation: "Canonicalise the path, verify it stays inside the allowed directory, and choose the file name yourself.",
        cwe: 22,
        safe: Some(r"basename|secure_filename|realpath|canonical|resolve\(\)|sanitize"),
    },
    Sink {
        id: "DB-FLOW-004",
        pattern: r"(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post)|urlopen|fetch|axios\.(?:get|post)|http\.Get)\s*\(",
        category: Category::Injection,
        severity: Severity::High,
        title: "User Input Flows Into An Outbound Request URL",
        impact: "SSRF: requests reach the internal network and the cloud metadata service, which leaks credentials.",
        remediation: "Restrict the target with an allowlist, block internal ranges, and do not follow redirects.",
        cwe: 918,
        safe: Some(r"allowlist|allowed_hosts|whitelist"),
    },
    Sink {
        id: "DB-FLOW-005",
        pattern: r"(?:eval|exec|new Function|setTimeout|setInterval)\s*\(",
        category: Category::Injection,
        severity: Severity::Critical,
        title: "User Input Flows Into Dynamic Code Execution",
        impact: "An attacker executes arbitrary code inside the process.",
        remediation: "Remove the dynamic execution entirely and use schema-based parsing or an allowlist.",
        cwe: 95,
        safe: None,
    },
    Sink {
        id: "DB-FLOW-006",
        pattern: r"(?:innerHTML|dangerouslySetInnerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*[=(]",
        category: Category::Frontend,
        severity: Severity::High,
        title: "User Input Flows Into An HTML Sink",
        impact: "XSS: the attacker's script runs in other users' browsers, which means session theft.",
        remediation: "Insert it as text (textContent) or apply a sanitisation library.",
        cwe: 79,
        safe: Some(r"DOMPurify|sanitize|escapeHtml"),
    },
];

/// Identifier assignment: `name = ...`, `let name = ...`, `const name = ...`.
const ASSIGNMENT: &str =
    r"^\s*(?:let|const|var|final|val)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]{0,60})?=\s*(.+)$";

struct Engine {
    sources: Vec<Regex>,
    sinks: Vec<(&'static Sink, Regex, Option<Regex>)>,
    assignment: Regex,
}

impl Engine {
    fn new() -> Option<Self> {
        Some(Self {
            sources: SOURCES
                .iter()
                .map(|pattern| Regex::new(pattern).ok())
                .collect::<Option<Vec<_>>>()?,
            sinks: SINKS
                .iter()
                .map(|sink| {
                    let pattern = Regex::new(sink.pattern).ok()?;
                    let safe = match sink.safe {
                        Some(raw) => Some(Regex::new(raw).ok()?),
                        None => None,
                    };
                    Some((sink, pattern, safe))
                })
                .collect::<Option<Vec<_>>>()?,
            assignment: Regex::new(ASSIGNMENT).ok()?,
        })
    }

    fn is_source(&self, text: &str) -> bool {
        self.sources.iter().any(|pattern| pattern.is_match(text))
    }
}

/// One step in a taint chain, kept so the report can show the whole path.
#[derive(Debug, Clone)]
struct Step {
    line: u32,
    text: String,
}

fn word_present(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(found) = haystack[start..].find(needle) {
        let index = start + found;
        let before_ok = index == 0 || !is_ident_byte(bytes[index - 1]);
        let after = index + needle.len();
        let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = index + needle.len().max(1);
        if start >= haystack.len() {
            break;
        }
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// Walks one file top to bottom, propagating taint through assignments.
fn analyse_file(engine: &Engine, file: &SourceFile) -> Vec<Finding> {
    // Languages that keep unit tests in the same file put deliberately vulnerable
    // fixtures beside real code. Flow tracking has to respect that boundary for the
    // same reason the rule engine does.
    let tests_from = crate::scan::test_region_start(file);
    if !engine.is_source(&file.content) {
        return Vec::new();
    }

    let mut tainted: HashMap<String, Vec<Step>> = HashMap::new();
    let mut findings = Vec::new();
    let mut reported: Vec<(&'static str, u32)> = Vec::new();

    for (line_no, raw) in file.lines_iter() {
        if tests_from.is_some_and(|boundary| line_no >= boundary) {
            break;
        }
        let line = raw.trim_end();
        if line.len() > 600 {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace)
            && (trimmed.starts_with("def ")
                || trimmed.starts_with("function ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("func "))
        {
            tainted.clear();
        }

        for (sink, pattern, safe) in &engine.sinks {
            if !pattern.is_match(line) {
                continue;
            }
            if safe
                .as_ref()
                .map(|guard| guard.is_match(line))
                .unwrap_or(false)
            {
                continue;
            }

            let culprit = tainted
                .iter()
                .find(|(variable, _)| word_present(line, variable));

            if let Some((variable, chain)) = culprit {
                if reported.contains(&(sink.id, line_no)) {
                    continue;
                }
                reported.push((sink.id, line_no));

                let mut builder = Finding::builder(sink.id, sink.category, sink.severity)
                    .title(format!("{} (`{variable}`)", sink.title))
                    .description(format!(
                        "Flow: {}",
                        chain
                            .iter()
                            .map(|step| format!("line {}", step.line))
                            .chain(std::iter::once(format!("line {line_no} (sink)")))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    ))
                    .impact(sink.impact)
                    .scenario(format!(
                        "An attacker controls the entry point on line {}; the value reaches line {} \
through `{variable}` and is used there without validation.",
                        chain.first().map(|step| step.line).unwrap_or(line_no),
                        line_no
                    ))
                    .remediation(sink.remediation)
                    .origin(Origin::Static)
                    .confidence(Confidence::Probable)
                    .cwe(sink.cwe)
                    .evidence(Evidence::new(
                        &file.rel_path,
                        Some(line_no),
                        trimmed.chars().take(160).collect::<String>(),
                    ));

                for step in chain.iter().take(3) {
                    builder = builder.evidence(Evidence::new(
                        &file.rel_path,
                        Some(step.line),
                        step.text.clone(),
                    ));
                }
                findings.push(builder.policy("DEV-02, b.2.2").build());
            }
        }

        if let Some(captures) = engine.assignment.captures(line) {
            let variable = captures.get(1).map(|m| m.as_str().to_string());
            let value = captures.get(2).map(|m| m.as_str()).unwrap_or("");
            if let Some(variable) = variable {
                let from_source = engine.is_source(value);
                let from_tainted = tainted
                    .keys()
                    .any(|existing| existing != &variable && word_present(value, existing));

                if from_source || from_tainted {
                    let mut chain: Vec<Step> = if from_source {
                        Vec::new()
                    } else {
                        tainted
                            .iter()
                            .find(|(existing, _)| word_present(value, existing))
                            .map(|(_, steps)| steps.clone())
                            .unwrap_or_default()
                    };
                    chain.push(Step {
                        line: line_no,
                        text: trimmed.chars().take(160).collect(),
                    });
                    if chain.len() <= 3 {
                        tainted.insert(variable, chain);
                    }
                } else {
                    tainted.remove(&variable);
                }
            }
        }
    }

    findings
}

pub fn run(inventory: &Inventory) -> Vec<Finding> {
    let engine = match Engine::new() {
        Some(engine) => engine,
        None => return Vec::new(),
    };

    inventory
        .files
        .iter()
        .filter(|file| !file.is_test() && crate::scan::is_code_language(file.language))
        .flat_map(|file| analyse_file(&engine, file))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file(name: &str, body: &str) -> SourceFile {
        SourceFile {
            rel_path: name.to_string(),
            abs_path: PathBuf::from(name),
            language: if name.ends_with(".py") {
                "Python"
            } else {
                "TypeScript"
            },
            size: body.len() as u64,
            lines: body.lines().count(),
            content: body.to_string(),
            truncated: false,
        }
    }

    fn rules(name: &str, body: &str) -> Vec<String> {
        let engine = Engine::new().unwrap();
        let mut out: Vec<String> = analyse_file(&engine, &file(name, body))
            .into_iter()
            .map(|finding| finding.rule)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn follows_a_source_through_an_assignment_into_a_sink() {
        let body = "\
def handler(request):
    name = request.args.get('name')
    query = f\"SELECT * FROM users WHERE n='{name}'\"
    return db.fetch_one(query)
";
        assert!(rules("app/h.py", body).contains(&"DB-FLOW-001".to_string()));
    }

    #[test]
    fn reports_the_whole_chain() {
        let body = "\
def handler(request):
    raw = request.args.get('p')
    path = raw
    return open(path)
";
        let engine = Engine::new().unwrap();
        let findings = analyse_file(&engine, &file("app/h.py", body));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.len() >= 2);
        assert!(findings[0].description.contains("→"));
    }

    #[test]
    fn a_parameterised_query_is_not_tainted_output() {
        let body = "\
def handler(request):
    name = request.args.get('name')
    return db.execute('SELECT * FROM users WHERE n = %s', (name,))
";
        assert!(!rules("app/h.py", body).contains(&"DB-FLOW-001".to_string()));
    }

    #[test]
    fn a_sanitised_path_is_not_traversal() {
        let body = "\
def handler(request):
    raw = request.args.get('f')
    return open(secure_filename(raw))
";
        assert!(!rules("app/h.py", body).contains(&"DB-FLOW-003".to_string()));
    }

    #[test]
    fn clean_reassignment_clears_taint() {
        let body = "\
def handler(request):
    value = request.args.get('v')
    value = 'constant'
    return db.execute(value)
";
        assert!(rules("app/h.py", body).is_empty());
    }

    #[test]
    fn taint_does_not_leak_across_function_boundaries() {
        let body = "\
def first(request):
    value = request.args.get('v')

def second():
    return db.execute(value)
";
        assert!(rules("app/h.py", body).is_empty());
    }

    #[test]
    fn a_file_with_no_source_is_skipped_cheaply() {
        let body = "def f():\n    return db.execute(query)\n";
        assert!(rules("app/h.py", body).is_empty());
    }

    #[test]
    fn substring_variable_names_do_not_match() {
        let body = "\
def handler(request):
    name = request.args.get('n')
    return db.execute(username)
";
        assert!(rules("app/h.py", body).is_empty());
    }

    #[test]
    fn detects_ssrf_through_a_variable() {
        let body = "\
def handler(req):
    target = req.query['url']
    return requests.get(target)
";
        assert!(rules("app/h.py", body).contains(&"DB-FLOW-004".to_string()));
    }

    #[test]
    fn detects_dom_xss_in_typescript() {
        let body = "\
function render(req: Request) {
  const value = req.query.q;
  element.innerHTML = value;
}
";
        assert!(rules("app/x.ts", body).contains(&"DB-FLOW-006".to_string()));
    }
}
