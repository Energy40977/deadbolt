use super::markers;
use crate::model::StackProfile;

pub const FINDING_CONTRACT: &str = r#"
RESPONSE FORMAT — follow it exactly:
Return a JSON array only. No explanation, no preamble, no markdown fence.
If you find nothing, return exactly this: []

Each element:
{
  "severity":    "critical" | "high" | "medium" | "low",
  "confidence":  "confirmed" | "probable" | "possible",
  "title":       "one-sentence name of the problem",
  "file":        "file path relative to the repository root",
  "line":        <integer, 0 if unknown>,
  "description": "what is wrong — one or two sentences",
  "impact":      "what an attacker or a failure achieves",
  "scenario":    "concrete input or state -> concrete wrong outcome",
  "remediation": "concrete fix",
  "cwe":         <CWE number, null if unknown>
}

RULES:
1. VERIFY the claim with Read/Grep/Glob. An unverified claim is not reported.
2. If you cannot fill in `scenario` — if you cannot name a concrete input and a
   concrete wrong outcome — DO NOT report that finding.
3. Use Grep to check whether the defence exists elsewhere (middleware, a
   decorator, database configuration). If you are still unsure after checking,
   set `confidence` to "possible".
4. Style, naming, formatting and comment remarks are NOT reported.
5. Report the same problem once.
6. At most 10 findings — pick the most severe.
7. Reading budget: at most eight files. The excerpts above exist so you do not have
   to go looking; spend a Read on confirming a specific line, not on browsing.
8. Make sure the file really exists; never invent a path.
"#;

/// Rules of engagement, prepended to every lens prompt.
pub const ENGAGEMENT: &str = include_str!("../../skills/_ENGAGEMENT.md");

pub struct Lens {
    pub name: &'static str,
    /// Attacker methodology for this lens, loaded from `skills/<name>.md`.
    pub skill: &'static str,
    /// Path fragments that make this lens relevant. Empty = always relevant.
    pub hints: &'static [&'static str],
    /// Substrings that indicate this lens has something to look at in a file.
    ///
    /// Two uses, both about not spending money. A slice containing none of them is
    /// skipped entirely rather than handed to a subagent that will read its way to
    /// the same conclusion. And the lines that do match are extracted and put in the
    /// prompt, so the agent starts from evidence instead of paying to rediscover it —
    /// the reading loop, not the prompt, is where the cost lives.
    pub markers: &'static [&'static str],
}

/// Each lens is backed by a skill file: an authorized white-box pentest
/// methodology (recon → attack surface → attack tree → verification → reporting
/// bar). Keeping them as Markdown means they are reviewable, versionable and
/// contributable without touching Rust — and a project can override any of them
/// by dropping its own `.deadbolt/skills/<lens>.md`.
pub const LENSES: &[Lens] = &[
    Lens {
        name: "authz",
        skill: include_str!("../../skills/authz.md"),
        hints: &[],
        markers: markers::AUTHZ,
    },
    Lens {
        name: "data",
        skill: include_str!("../../skills/data.md"),
        hints: &[],
        markers: markers::DATA,
    },
    Lens {
        name: "failure",
        skill: include_str!("../../skills/failure.md"),
        hints: &[],
        markers: markers::FAILURE,
    },
    Lens {
        name: "crypto",
        skill: include_str!("../../skills/crypto.md"),
        hints: &[],
        markers: markers::CRYPTO,
    },
    Lens {
        name: "migration",
        skill: include_str!("../../skills/migration.md"),
        hints: &["migration", "alembic", "migrate", "schema", ".sql"],
        markers: markers::MIGRATION,
    },
    Lens {
        name: "api",
        skill: include_str!("../../skills/api.md"),
        hints: &[
            "api",
            "router",
            "route",
            "controller",
            "schema",
            "serializer",
            "handler",
        ],
        markers: markers::API,
    },
    Lens {
        name: "frontend",
        skill: include_str!("../../skills/frontend.md"),
        hints: &[
            ".tsx",
            ".jsx",
            ".vue",
            ".svelte",
            "components",
            "pages",
            "app/",
        ],
        markers: markers::FRONTEND,
    },
    Lens {
        name: "infra",
        skill: include_str!("../../skills/infra.md"),
        hints: &[
            "dockerfile",
            "docker-compose",
            "k8s",
            "kubernetes",
            ".tf",
            "helm",
            "nginx",
            "caddy",
            ".github/workflows",
            ".gitlab-ci",
        ],
        markers: markers::INFRA,
    },
];

pub fn stack_summary(stack: &StackProfile) -> String {
    let languages: Vec<String> = stack
        .languages
        .iter()
        .take(6)
        .map(|language| format!("{} ({} files)", language.name, language.files))
        .collect();

    let optional = |label: &str, items: &[String]| -> String {
        if items.is_empty() {
            String::new()
        } else {
            format!("{label}: {}\n", items.join(", "))
        }
    };

    format!(
        "Languages: {}\n{}{}{}{}Size: {} files, {} lines\nMobile client: {}\nMigrations: {}\n",
        languages.join(", "),
        optional("Framework", &stack.frameworks),
        optional("Databases", &stack.databases),
        optional("Infrastructure", &stack.infrastructure),
        optional("CI", &stack.ci_systems),
        stack.total_files,
        stack.total_lines,
        if stack.has_mobile { "yes" } else { "no" },
        if stack.has_migrations { "yes" } else { "no" },
    )
}

/// Asks one agent to map the system once, so the lenses do not each spend their
/// turn allowance rediscovering the same routes, models and sinks.
pub fn build_recon_prompt(stack: &StackProfile, files: &[String]) -> String {
    format!(
        r#"You are mapping a codebase for a security assessment. You do NOT report
vulnerabilities in this pass — you produce the map that other reviewers will use.

Read-only tools: Read, Grep, Glob.

================ TARGET ================
{summary}
================ FILES ================
{listing}

Produce these five sections, and nothing else. Be dense; no prose, no advice.

## ROUTES
One line per HTTP route or public entry point, in this exact shape:
`METHOD /path — file:line — auth: <decorator/middleware/none/unknown>`
Include background jobs, webhooks, GraphQL resolvers and CLI entry points.

## DEFENCES
How this project expresses each control, with the exact symbol name and the file
that defines it: authentication, authorisation, rate limiting, input validation,
output serialisation, secret loading, logging/masking. Write `absent` when you
cannot find one.

## MODELS
Data models holding personal, financial or authentication data:
`Model — file:line — sensitive fields: a, b, c — encrypted: yes/no/unknown`

## SINKS
Dangerous operations, grouped: raw SQL, shell/exec, filesystem paths, outbound
HTTP, deserialisation, HTML rendering, template rendering. One line each:
`kind — file:line — input source: <parameter/body/env/constant/unknown>`

## LAYOUT
Which top-level directory holds what (service, app, worker, shared library), and
which are dead or example code.

Rules:
1. Every line carries `file:line`. No line without a location.
2. Never invent a path — verify it exists.
3. If a section is genuinely empty, write `none found`.
4. Keep the whole answer under 400 lines."#,
        summary = stack_summary(stack),
        listing = files.join("\n"),
    )
}

pub fn build_lens_prompt(
    lens: &Lens,
    skill: &str,
    stack: &StackProfile,
    files: &[String],
    recon: Option<&str>,
    excerpts: &str,
) -> String {
    let listing = files.join("\n");
    let recon_block = match recon {
        Some(map) if !map.trim().is_empty() => format!(
            "\n================ RECON MAP ================\n\
Produced by an earlier pass over this repository. It saves you the discovery\n\
work, but it is not evidence: verify any line you rely on with Read or Grep\n\
before reporting a finding built on it.\n\n{map}\n"
        ),
        _ => String::new(),
    };
    format!(
        r#"{engagement}

================ METHODOLOGY: {name} ================
{skill}

================ TARGET ================
{summary}{recon_block}
================ STARTING POINTS ================
{listing}
{excerpt_block}
Work through the phases of the methodology in order: first learn the defensive
standard of the project, then look for what departs from it. Read a file only when
the excerpts above are not enough to decide — every file you read stays in context
for the rest of this session, so reading widely is the expensive way to be wrong.

{contract}

Return a JSON array only."#,
        engagement = ENGAGEMENT,
        name = lens.name,
        skill = skill,
        summary = stack_summary(stack),
        recon_block = recon_block,
        listing = listing,
        excerpt_block = if excerpts.trim().is_empty() {
            String::new()
        } else {
            format!(
                "\n================ LINES THAT MATCH THIS LENS ================\n\
Extracted mechanically, with three lines of context. They are a starting point, not\n\
a verdict: confirm the surrounding code before reporting anything built on them.\n{excerpts}"
            )
        },
        contract = FINDING_CONTRACT,
    )
}

pub const RESEARCH_CONTRACT: &str = r#"
RESPONSE FORMAT — a single JSON object, no markdown fence:
{
  "collects_personal_data": "yes" | "optional" | "no" | "unknown",
  "data_collected":   "which fields are collected — empty string if unknown",
  "endpoints":        "where the data is sent — empty string if unknown",
  "opt_out":          "how to turn it off (environment variable, configuration) — empty if none",
  "maintenance_status": "active | weak | abandoned | unknown, plus a short reason",
  "incidents":        "known security incident, ownership change, malicious release — EMPTY STRING if none",
  "verdict":          "one-sentence conclusion",
  "recommendation":   "keep | update | replace | remove — and why",
  "sources":          ["reference URLs"]
}

RULES:
1. Do not guess. If you find no source, write `"unknown"` and empty strings.
2. Fill in `incidents` only for a confirmed incident. Suspicion is not enough —
   an unfounded accusation destroys the value of this tool.
3. Give a reference in the `sources` array for every claim.
4. Separate "telemetry" from "error reporting": both send data, but the volume
   and the contents differ — state precisely which one it is.
"#;

pub fn build_research_prompt(
    name: &str,
    version: &str,
    ecosystem: &str,
    signals: &[String],
) -> String {
    let signal_line = if signals.is_empty() {
        "none detected".to_string()
    } else {
        signals.join(", ")
    };

    format!(
        r#"You are a supply-chain researcher. Research one package.

PACKAGE: {name}
VERSION: {version}
ECOSYSTEM: {ecosystem}
DETERMINISTIC SIGNALS: {signal_line}

Questions you have to answer:
1. Does this package collect PERSONAL DATA or TELEMETRY? What does it collect,
   where does it send it, and can it be turned off?
2. Maintenance state: last release, number of maintainers, is it archived?
3. Has there been a known security incident, account takeover, ownership change
   or malicious release?
4. Is this package recommended for use?

Method: use WebSearch and WebFetch to check the official repository, the registry
page, the privacy policy and vulnerability databases. Where possible, also check
the network calls in the package source.

{RESEARCH_CONTRACT}

Return a JSON object only."#
    )
}

/// Asks an agent to REFUTE a finding rather than confirm it.
///
/// A reviewer asked to confirm confirms; the prompt has to make refutation the
/// cheap answer, or verification degrades into agreement.
pub fn build_refute_prompt(
    title: &str,
    file: &str,
    line: Option<u32>,
    description: &str,
    scenario: &str,
    lens: &str,
) -> String {
    format!(
        r#"You are a skeptical reviewer. Another reviewer reported the finding below.
Your job is to REFUTE it. Assume it is wrong until the code proves otherwise.

Read-only tools: Read, Grep, Glob. Never modify anything.

CLAIM
  lens:        {lens}
  title:       {title}
  location:    {file}{line}
  description: {description}
  scenario:    {scenario}

Refute it if ANY of these hold:
1. The location does not exist, or the code there does not do what the claim says
2. A control the claim missed protects this path — a decorator, middleware, a
   gateway rule, a database constraint, framework default behaviour
3. The input is not attacker-controlled (it is internal, a constant, or already validated)
4. The code is unreachable: dead code, a disabled feature, an example, a test fixture
5. The scenario cannot happen as written

Verify with Grep and Read. Do not reason from habit — read the code.
Default to refuted when the evidence is not clearly there.

RESPONSE FORMAT — a single JSON object, no markdown fence:
{{
  "refuted": true | false,
  "reason":  "one sentence naming the file:line that settles it",
  "severity_should_be": "critical" | "high" | "medium" | "low" | "info" | ""
}}

Return the JSON object only."#,
        lens = lens,
        title = title,
        file = file,
        line = line.map(|n| format!(":{n}")).unwrap_or_default(),
        description = description,
        scenario = if scenario.trim().is_empty() {
            "(none given)"
        } else {
            scenario
        },
    )
}
