# deadbolt

<img src="assets/deadbolt-logo.svg" alt="deadbolt" width="360">

> Deep security and compliance audit for **any** codebase — whatever language, whatever framework.

`deadbolt` inventories a repository, fingerprints its stack, runs a language-agnostic
rule engine, researches every dependency against live vulnerability data, optionally
sends the code through eight adversarial AI review lenses, and produces a prioritised
report with concrete remediation for every finding.

Single static binary. No runtime, no agent, no account, no telemetry.

```bash
deadbolt audit .
```

```
  deadbolt — example-shop
  ──────────────────────────────────────────────────────────────────
  Stack       Python (420), TypeScript (280), SQL (30), YAML (12)
  Frameworks  FastAPI, Next.js, React
  Databases   PostgreSQL, Redis
  Size        700 Files, 90000 Lines
  Score       58.0/100  (D)
  ──────────────────────────────────────────────────────────────────
  ■ CRITICAL: 1   ▲ HIGH: 40   ● MEDIUM: 55   · LOW: 2

   CRITICAL  services/orders/routes.py:88  attack chain
      Unauthenticated State Change — Open Endpoint Reaching A Write Path
      What Can Happen: An endpoint with no authentication requirement sits in
                       front of an operation that changes state.
      How To Fix It: Apply deny-by-default at the router, then make the write
                     path itself require an authenticated principal.
```

---

## Contents

- [Why another scanner](#why-another-scanner)
- [Install](#install) — [macOS](#macos) · [Linux](#linux) · [Windows](#windows)
- [First run](#first-run)
- [How a run works](#how-a-run-works)
- [The AI layer](#the-ai-layer) — how headless Claude is used, and why
- [The HTML report](#the-html-report)
- [What it checks](#what-it-checks)
- [Dependency research](#dependency-research)
- [Compliance packs](#compliance-packs)
- [Gates](#gates)
- [CI integration](#ci-integration)
- [Configuration](#configuration)
- [Your own rules](#your-own-rules)
- [Portfolio](#portfolio)
- [Privacy and what leaves your machine](#privacy-and-what-leaves-your-machine)
- [Status](#status)

## Why another scanner

Most tools answer *"does this line look wrong?"*. `deadbolt` answers four questions a linter cannot:

| Question | How |
|---|---|
| **What is missing?** | Repo-level checks for defects of *absence*: no rate limiting, no security headers, no memory-hard password hashing, no lockfile, no rollback switch for a mobile app, personal data stored without field-level encryption, backups nobody can restore. |
| **What did we import?** | Every dependency is checked against OSV.dev, then registry metadata: known CVEs, abandonment, single-maintainer risk, install scripts, typosquat distance, licence exposure — and for the riskiest, whether the package collects personal data and where it sends it. |
| **Can an attacker actually reach it?** | Findings that individually survive review are joined into **attack chains**, and severity is re-weighted by whether the file declares an external entry point or sits in dead code. |
| **Does it meet our rules?** | Findings carry CWE, OWASP ASVS and policy-clause references, so one report maps onto the standard *and* onto your own internal protocol. |

Language-agnostic by construction: rules describe defect *classes* with patterns
covering many ecosystems, so Python, TypeScript, Go, Kotlin, Swift, Dart, PHP,
Ruby, Java, Rust and SQL are covered by the same engine.

## Install

### Prerequisites

| | Required for | Notes |
|---|---|---|
| **Rust 1.75+** | building from source | [rustup.rs](https://rustup.rs) — the only build dependency |
| **git** | `diff` mode, history scan | optional otherwise |
| **`claude` CLI** | the AI layer | optional; without it every other phase still runs |
| network | dependency research | `--offline` disables all of it |

`deadbolt` has no runtime dependency. The compiled binary is one file; copy it to
another machine of the same architecture and it works.

### macOS

```bash
# Apple silicon and Intel both build from source
xcode-select --install                     # if you have never built anything here
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/Energy40977/deadbolt
cd deadbolt
cargo build --release

# put it on PATH — ~/.local/bin is already on PATH in most shells
mkdir -p ~/.local/bin
cp target/release/deadbolt ~/.local/bin/
deadbolt doctor .
```

Gatekeeper does not block a binary you compiled yourself. The HTML report opens
with `open`, which respects your default browser.

### Linux

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential pkg-config git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/Energy40977/deadbolt
cd deadbolt
cargo build --release
sudo install -m 0755 target/release/deadbolt /usr/local/bin/
deadbolt doctor .
```

Fedora and RHEL need `gcc` and `openssl-devel` in place of `build-essential`;
Alpine needs `build-base` and `musl-dev`.

**Minimal containers:** TLS uses the operating system trust store rather than
bundled roots. A `scratch` or `distroless` image has no store, so set
`SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` or run `--offline`.

The report opens with `xdg-open`. Headless boxes have none — the run prints the
path and skips the browser instead of failing.

### Windows

```powershell
# 1. Install the toolchain (needs the MSVC build tools once)
winget install Rustlang.Rustup
winget install Git.Git

# 2. Build
git clone https://github.com/Energy40977/deadbolt
cd deadbolt
cargo build --release

# 3. Put it somewhere on PATH
New-Item -ItemType Directory -Force "$env:USERPROFILE\bin"
Copy-Item .\target\release\deadbolt.exe "$env:USERPROFILE\bin\"
[Environment]::SetEnvironmentVariable(
  "Path", "$env:Path;$env:USERPROFILE\bin", "User")

deadbolt doctor .
```

Windows-specific behaviour worth knowing:

- **Use PowerShell or Windows Terminal, not `cmd.exe`.** The banner, the box
  drawing and the progress bars are Unicode; `cmd.exe` with a legacy code page
  renders them as garbage. In PowerShell run `[Console]::OutputEncoding =
  [Text.Encoding]::UTF8` once if you see question marks.
- **Quoting differs.** PowerShell splits on commas, so quote multi-value flags:
  `deadbolt audit . --format "terminal,html"`.
- Paths in the report always use forward slashes, so a report generated on
  Windows and read on Linux points at the same file.
- The report opens with `explorer`, which hands the file to the default browser.
- Colour is on when the terminal supports it. `$env:NO_COLOR=1` turns everything
  monochrome, including the gradient banner.

### Verify the install

```bash
deadbolt doctor .
```

```
deadbolt doctor
────────────────────────────────────────────────────────────
  version            0.1.0
  Target             /path/to/project
  Files / Lines      700 / 90000
  Languages          Python, TypeScript, SQL, YAML
  Frameworks         FastAPI, Next.js, React
  Manifests          4
  static rules       82 loaded
  claude CLI         /Users/you/.local/bin/claude
────────────────────────────────────────────────────────────
```

`doctor` never touches the network and never writes a file. If `claude CLI` shows
`Not Found`, the AI layer is skipped and everything else still runs.

## First run

Run it with no arguments. It reads the project, shows what it found, and asks one
question:

```bash
deadbolt
```

```
   ▄▄████▄▄   ██████╗ ███████╗ █████╗ ██████╗ ██████╗  ██████╗ ██╗  ████████╗
  ▄████████▄  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║  ╚══██╔══╝
  ██  ██  ██  ██║  ██║█████╗  ███████║██║  ██║██████╔╝██║   ██║██║     ██║
  ██  ██  ██  ██║  ██║██╔══╝  ██╔══██║██║  ██║██╔══██╗██║   ██║██║     ██║
  ▀██▄▟▙▄██▀  ██████╔╝███████╗██║  ██║██████╔╝██████╔╝╚██████╔╝███████╗██║
   ██║║║║██   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝

  v0.1.0  ·  Security And Compliance Audit For Any Codebase
  ────────────────────────────────────────────────────────────────────
  ▸ Target            .
  ▸ Size              700 Files · 90000 Lines
  ▸ Languages         Python (420), TypeScript (280), SQL (30)
  ▸ Frameworks        FastAPI, Next.js, React
  ▸ Manifests         package.json, requirements.txt
  ▸ AI Review         Available
  ────────────────────────────────────────────────────────────────────

  :: Select Mode (↑↓ Move · Enter Run · Esc Quit)
      Quick Scan            Rules Only · No Network · ~10s
    ▶ Scan + Dependencies   Adds CVE Lookup · ~2min
      Full Audit            Adds AI Review · ~10min · Costs Money
      Changed Lines Only    Git Diff · Pre-Commit · ~5s
```

Arrow keys, Enter to run, Esc to quit. The colour of each line is the cost tier:
green is free, cyan reaches the network, amber spends money. Before starting it
prints the equivalent command line, so the second run needs no questions.

Everything the wizard can do is a flag:

```bash
deadbolt init .                        # write a commented .deadbolt.toml
deadbolt scan .                        # rules only, fastest, no network
deadbolt baseline --write              # accept what already exists
deadbolt audit .                       # static + deps + AI + compliance
deadbolt diff --base main              # only what this change introduced
deadbolt deps . --privacy              # dependencies, incl. data-collection research
deadbolt portfolio a b c               # rank several repositories in one report
deadbolt explain DB-INJ-001            # what a rule finds, why, how to fix
deadbolt fix .                         # safe additive repairs (preview by default)
deadbolt watch .                       # re-scan on save
deadbolt pack list                     # compliance packs
deadbolt doctor .                      # environment + stack detection check
```

**Exit codes** — a degraded run is not a clean run:

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | blocking findings, or a score regression when the ratchet is on |
| `2` | tool error (arguments, git, configuration) |
| `3` | **degraded** — some phases did not run (AI unreachable, no network, cost limit hit). Not "no problems found"; handle it separately in CI. |

### Adoption path

An audit that reports the whole backlog on day one gets switched off by week two.

```bash
deadbolt init .                # 1. configure
deadbolt baseline --write      # 2. accept today's findings, commit the file
deadbolt diff --base main      # 3. gate pull requests on *new* findings only
deadbolt audit .               # 4. run the deep audit on a schedule, not per PR
```

`.deadbolt-baseline.json` is committed and is expected to **shrink** over time.
Fingerprints are built from rule + file + whitespace-normalised code, so
reformatting does not resurrect an accepted finding — while a *second, different*
occurrence of the same rule in the same file is still reported as new.

## How a run works

```
  1  Discover      walk the tree, detect languages, frameworks, databases,
                   package managers, CI, IaC, manifests, lockfiles
       │
  2  Static        82 checks: 50 line-level rules + 32 repo-level checks
                   + intra-file taint tracking + git history secret scan
                   + OpenAPI contract diff + authorisation matrix
       │
  3  Dependencies  OSV.dev batch query → registry metadata → risk ranking
                   → deep AI research on the riskiest shortlist
       │
  4  AI review     recon pass → sharded lenses → adversarial verification
       │
  5  Post          reachability weighting → attack-chain correlation
                   → compliance evaluation → baseline filter → gates
       │
  6  Report        terminal · html · markdown · json · sarif · sbom
                   · github annotations · gitlab code quality
```

Phases 3 and 4 are optional and each announces itself:

```
  ✔ Project Read           700 Files · 90000 Lines · 9 Languages      142ms
  ✔ Static Rules           123 Findings (82 Rules)                     1.6s
  ✔ Dependencies Checked   679 Packages · 34 With Known CVEs           48s
  Recon      412 Lines Mapped  $2.10
  AI Plan    24 Subagents · Rough Estimate $82
  AI Review  [▰▰▰▰▰▰▰▱▱▱▱▱] 14/24  crypto 2/3 Running (180 Files)
  ✔ AI · authz     4 Findings  $3.31
  ⚠ AI · api       Skipped — Cost Limit Reached
  Verify     Held Up   IDOR On /api/orders/{id}  $1.42
  ⚠ Verify   Refuted   SQL Injection In report.py  $0.98
  Reachability   6 Raised · 3 Lowered
  1 Correlated Attack Path
  ✔ Complete In 6m 12s
```

Progress bars are drawn only on a terminal. Piped output and CI logs stay clean.

## The AI layer

The AI layer is optional, off by default in `scan`, on by default in `audit`. It
exists because a pattern cannot answer *"can an attacker reach this?"* — that
question needs reading the surrounding code and reasoning about control flow.

### How headless Claude is used

`deadbolt` does not embed a model or call an API with your key. It shells out to
the **`claude` CLI in headless mode** — one process per unit of work:

```
claude -p "<prompt>" \
       --output-format json \
       --model claude-opus-5 \
       --max-turns 45 \
       --allowedTools "Read,Grep,Glob"
```

Everything about that command matters:

| Part | Why |
|---|---|
| `-p` | one-shot, non-interactive; no session state between calls |
| `--output-format json` | the answer arrives as a JSON envelope with `result`, `is_error`, `subtype` and `total_cost_usd`, so cost is measured rather than estimated |
| `--allowedTools "Read,Grep,Glob"` | **read-only by construction.** The agent cannot write a file, cannot run a command, cannot reach the network. This is not a prompt instruction the model may ignore — the tool is absent |
| `--max-turns` | a hard ceiling on tool calls, so a lens cannot wander indefinitely |
| the working directory | set to the repository root, so the agent sees the project and nothing above it |

For dependency research the tool set is `Read,Grep,Glob,WebSearch,WebFetch` —
that phase has to read registry pages and advisories. Code lenses never get
network tools.

Because it is the CLI, whatever authentication you already use for Claude Code
applies. `deadbolt` never sees a key.

### Four stages, in order

**1. Recon — map once instead of eight times.**

One agent reads the repository and produces a structured map: every route with its
file, line and authentication marker; how the project expresses each control and
where that symbol is defined; models holding personal or financial data; dangerous
sinks with their input source; which top-level directories are live and which are
dead.

Without it, every lens spends most of its turn allowance rediscovering the same
structure — eight lenses over three shards repeat that work twenty-four times. The
map is prepended to every lens prompt with an explicit caveat: *it is not
evidence, verify any line you rely on.*

**2. Lenses — eight methodologies, sharded.**

Each lens is a separate headless call driven by a **skill file**: an authorised
white-box pentest methodology, not a checklist.

```
skills/
├── _ENGAGEMENT.md   rules of engagement + reporting bar (prepended to every lens)
├── authz.md         access-control breaking
├── data.md          tracing data exfiltration paths
├── failure.md       abusing failure behaviour
├── crypto.md        breaking cryptographic controls
├── migration.md     taking the service down via schema change
├── api.md           contract breaking + input boundary
├── frontend.md      client-side exploitation
└── infra.md         infrastructure and pipeline surface
```

| Lens | Hunts for |
|---|---|
| `authz` | **IDOR / object-level authorisation**, unauthenticated endpoints, vertical escalation, mass assignment, tenant leakage |
| `data` | personal data in logs, error leakage, over-broad serialisers, unencrypted PII, unaudited bulk export |
| `failure` | **fail-open controls**, silent swallow, missing timeout or circuit breaker, idempotency, queue loss |
| `crypto` | static key and nonce reuse, oracle-able modes, JWT confusion (`alg:none`, RS256→HS256), timing attacks |
| `migration` | expand-contract violations, blocking DDL, code/migration ordering, breaking older mobile clients |
| `api` | breaking contract changes, unvalidated boundaries, webhook forgery, enumeration, GraphQL depth |
| `frontend` | **secrets in the client bundle** (`NEXT_PUBLIC_*`), tokens in `localStorage`, XSS sinks, open redirect, WebView bridges |
| `infra` | network exposure, container privilege, **`pull_request_target` CI compromise**, mutable refs, deletable backups |

Every skill has the same five-part shape: learn the project's own defence pattern
first, enumerate the attack surface into a table, work an attack tree of ranked
techniques, verify against a checklist, then check the finding against the specific
ways that class of finding is usually wrong.

On a large repository a lens is **split across parallel subagents** — about 180
files each, up to three slices, sorted by path so each slice covers a coherent
subsystem rather than a random sample. Wall-clock time becomes one slice instead of
the whole repository.

The slice size is a measured trade-off. A subagent costs roughly the same whether
it holds 70 files or 240, because the spend is in reasoning rather than in the
listing: 70-file slices turned one audit into 64 subagents and $220 with no
meaningful latency gain. Narrow slices multiply cost; wide slices with a low cap
keep both.

**3. Adversarial verification — the refuters.**

Every severe AI finding is handed to independent agents whose prompt asks them to
**knock it down**, not to confirm it:

> Your job is to REFUTE it. Assume it is wrong until the code proves otherwise.
> Refute it if the location does not exist, if a control the claim missed protects
> this path, if the input is not attacker-controlled, if the code is unreachable,
> or if the scenario cannot happen as written. Default to refuted when the evidence
> is not clearly there.

A finding survives only if none of them can refute it. Survivors are marked
`Verified: N independent reviewers could not refute this` in the report. Refuted
findings never reach the reader, and the count of removals is reported so the
filtering is visible rather than silent.

An asked-to-confirm reviewer confirms. Making refutation the cheap answer is what
turns verification into a filter instead of an echo.

**4. Post-processing — reachability and chains.**

Reachability weighting moves severity by location: a defect in a file that declares
an external entry point rises one step, one in example, script or unreferenced code
drops one step. Framework-loaded files — migrations, settings, routers, workflows —
are never treated as dead, because nothing imports them by name and demoting them
would bury exactly the findings that deploy automatically. Nothing is ever removed:
the analysis is cheap enough to be wrong.

Correlation then joins findings that individually survived review into one path.
Six chains are defined; each is reported only when every link is present, cites
each member with its location, and is excluded from the score because its members
are already counted.

### Cost, caching and control

Cost is measured, not guessed — the JSON envelope carries `total_cost_usd` per
call. Measured on a 700-file polyglot monorepo: **about $3.40 per subagent**, so a full
eight-lens audit with recon and verification lands around **$60–90**. A `scan` or a
`diff` run costs nothing.

```bash
deadbolt audit .                            # default: no cost cap, everything runs
deadbolt audit . --budget 8.00              # hard stop; skipped lenses are named
deadbolt audit . --lens authz,crypto        # only what you need
deadbolt audit . --concurrency 16           # wall clock, not cost
deadbolt audit . --no-ai                    # deterministic phases only
deadbolt audit . --no-verify                # skip refuters: faster, less precise
```

The plan line prints the subagent count and a rough estimate **before** any money
is spent. When a budget is set and reached, the report says which lenses did not
run and what budget would have covered them:

```
The AI Cost Limit ($8.00) Was Reached — 4 Lenses Did Not Run: data, failure,
api, infra. The Lenses That Ran Cost $7.94; Roughly $15.88 Is Needed For All
Of Them (`--budget 16`).
```

Results are cached in `.deadbolt-cache/` keyed on the lens, the model, the prompt
**and a hash of the contents of the files in that slice**. That last part is what
makes a second audit cheap: an unchanged slice is free and instant, a slice with
one edited file re-runs. An edit that keeps the line count the same still
invalidates, because the key is content-addressed rather than metadata-based.

### Model policy

**Opus is the floor, not a nicety.** These lenses reason about reachability, and
smaller models produce plausible findings that fail verification — worse than no
finding at all.

| | |
|---|---|
| Default | `claude-opus-5` |
| Minimum supported | `claude-opus-4-7` |
| Below that | runs, but warns and explains the trade-off |

Measured on a 5-file fixture, `authz` lens only:

| Model | Findings | Quality | Cost |
|---|---|---|---|
| Haiku 4.5 | 2 | correct but shallow | $0.11 |
| **Opus 5** | **6** | attack chains, brute-force space analysis, payloads | **$0.68** |

Opus found an authentication bypass — a `login()` that never compares the password
hash — that the fixture's own author had not noticed, and chained an IDOR into the
refund endpoint through a leaked `payment_id`.

## The HTML report

```bash
deadbolt audit . --format html --out ./audit
```

One file, about 190 KB. It **loads nothing**: no CDN script, no web font, no remote
image, no analytics. The favicon is a `data:` URI and the charts are inline SVG, so
the report opens on an air-gapped machine, survives being emailed, and can be
committed as an artefact. On a terminal it opens in the browser by itself;
`--no-open` suppresses that.

What is in it, top to bottom:

**Fixed navigation rail** — the score, the severity counts as pills, and links to
every section. It stays visible while you read the findings list, which is the part
that gets long.

**Header** — the command that produced the report, the project, the target path,
the timestamp, the duration and the AI cost.

**Overview**

- **Score gauge** — 0–100 with ticks every five points and the two thresholds that
  change the verdict (50 and 75) marked on the dial, so the number has a scale
  rather than floating free. Colour follows the verdict; the ring animates from
  zero on load.
- **Severity donut** — the mix, with the total and the **blocking** count in the
  centre. Each segment carries a hover title (`52 High — 42%`), so the chart is
  readable without the legend.
- **KPI tiles** — blocking count, **findings per 1000 lines**, lines scanned, and
  where applicable packages with CVEs, controls satisfied, lenses run, AI cost and
  duration. Density is given with its denominator on purpose: an absolute count
  invites the wrong comparison between two repositories of different size.
- **Category bars** — where the problems are, with a count, a share and the worst
  severity in each category.

**Where to start** — critical and high findings grouped **by file** and ordered by
severity. Fixing one file usually closes several findings, so the list walks file
by file rather than finding by finding.

**Score over time** — the trend drawn from `.deadbolt-history.jsonl`, if the file
has more than one entry.

**What this project is built from** — languages with their share of the codebase,
frameworks, databases, package managers, CI systems, infrastructure, and the size.

**Standards compliance** — one card per pack with a coverage ring and a three-way
split: satisfied, violated, **could not be checked**. The last one is stated
plainly rather than counted as a pass, and the reason names the missing detector.
Violated controls are listed in a table with what each one requires.

**Findings** — grouped by severity, collapsed by default, with expand-all and
collapse-all. Opening one shows:

- what the finding means, in plain language
- **what can happen** — the impact, not a restatement of the rule
- a concrete scenario, when the producer could give one
- **how to fix it**, split into numbered steps when the remediation has several
- the evidence snippet, or for a multi-step finding the **attack path** drawn as a
  timeline: *starts here → passes through → reaches here*, each step with its
  file and line
- references: CWE with a link, OWASP ASVS clause, your own policy clause
- provenance: which rule, which AI lens, or which standards control produced it
- confidence, when it is not confirmed, and what that means for the pipeline
- `deadbolt explain <RULE>` for the full rule write-up

**Dependencies** — every package carrying a risk signal, sorted by risk score,
with its known vulnerabilities linked to OSV.dev, its risk signals, whether you
added it or another package pulled it in, and for researched packages whether it
collects personal data.

**Glossary** — every term the report uses, explained in one sentence each: secret,
SQL injection, XSS, IDOR, SSRF, JWT, hash, CORS, migration, gate, baseline. A
report that assumes the vocabulary is a report only its author can read.

**Footer** — warnings from the run: phases that degraded, files skipped, packages
that could not be researched, and why.

The whole thing is a dark terminal-console theme — monospace, grid backdrop,
scanlines, bracket labels — and honours `prefers-reduced-motion` by switching every
animation off.

### Other formats

| Format | Use |
|---|---|
| `terminal` | local runs: colour, wrapped remediation, capped list |
| `html` | the full report described above |
| `markdown` | commit it or send it: grouped by category with evidence snippets |
| `json` | machine-readable everything: dashboards, history, custom queries |
| `sarif` | GitHub / GitLab code scanning, findings inline on the pull request |
| `sbom` | CycloneDX 1.5 with purls and vulnerabilities attached to components |
| `github` | GitHub Actions annotations on stdout — the finding lands on the diff line |
| `gitlab` | GitLab Code Quality report, rendered inline on the merge request |

Combine them with commas: `--format terminal,html,sarif`.

## What it checks

### Static rules (50 line rules)

| Area | Examples |
|---|---|
| Secrets | hardcoded credentials, private keys, provider key formats, credentials in connection strings |
| Cryptography | disabled certificate verification, MD5/SHA-1, ECB/unauthenticated modes, fast password hashing, non-CSPRNG tokens, static IV/salt, unverified JWT, non-constant-time comparison |
| Injection | SQL string building, command injection, unsafe deserialization, path traversal, DOM XSS, SSRF |
| Authorization | client-side authorization, sequential public identifiers, auth explicitly disabled |
| Data protection | sensitive fields in logs, internal errors returned to clients, silently swallowed exceptions |
| Privacy | third-party analytics SDKs, secrets in insecure mobile storage |
| Configuration | wildcard CORS, debug mode enabled, unbounded queries, missing timeouts |
| Database | destructive migrations, blocking DDL, `NOT NULL` without default, rename/drop in one step |
| Infrastructure | container running as root, services bound to `0.0.0.0`, secrets in IaC, cleartext HTTP, mutable CI refs |

Every rule reports **impact** (what an attacker or failure achieves) and **remediation**, not just a location.

### Repo-level checks (32)

Defects of *absence* — nothing on any single line is wrong, the mechanism simply
does not exist:

| Area | Checks |
|---|---|
| Secrets | `.env` committed · `.env` missing from `.gitignore` · **`.gitignore` added after the file was already tracked** · secret reachable in git history |
| Supply chain | no lockfile · unpinned dependencies · end-of-life base image · direct dependency with no release for years |
| Pipeline | no CI · CI without security scanning · secrets exposed to fork-triggered workflows |
| Testing | no test files · low test ratio · `.only` left in place · disabled tests |
| Web | missing security headers · wildcard CORS · **no CSRF protection on a cookie session** · no rate limiting |
| Authentication | no memory-hard password hashing · no MFA · **passwords not checked against a breached-password list** |
| Personal data | PII without field-level encryption · **no retention period implemented** · **no access or deletion mechanism** · **real mailboxes in test fixtures** · **bulk export with no audit trail** · **card fields without tokenisation** |
| Operations | no remote kill switch for a mobile app · **backups not encrypted** · **backups deletable by whoever reaches production** · missing `SECURITY.md` |
| Containers | no unprivileged user · service bound to `0.0.0.0` |
| Database | **migrations with no usable rollback step** · model column no migration creates |
| Runtime | Node version not constrained |

Eleven of these exist so that a compliance control has a detector rather than an
`unknown` verdict — a control nobody can check is indistinguishable from a control
nobody checked.

## Dependency research

Tiered so cost stays bounded:

1. **All packages** — OSV.dev batch query (no API key), typosquat distance.
2. **Direct + vulnerable packages** — registry metadata: last release, maintainer count, deprecation, licence, install scripts.
3. **Risk-ranked shortlist** — deep AI + web research answering: does this package collect
   personal data, what exactly, to which endpoint, can it be turned off, is it maintained,
   has it been involved in a security or ownership incident. Every answer carries sources.

Manifests and lockfiles parsed:

| Ecosystem | Manifest | Lockfile |
|---|---|---|
| npm | `package.json` | `package-lock.json`, `yarn.lock` (v1 + Berry), `pnpm-lock.yaml` (v5 + v6) |
| PyPI | `requirements.txt`, `pyproject.toml` | `poetry.lock`, `uv.lock` |
| crates.io | `Cargo.toml` | `Cargo.lock` |
| Go | `go.mod` | `go.sum` |
| Packagist | `composer.json` | `composer.lock` |
| RubyGems | `Gemfile` | `Gemfile.lock` |
| Pub | `pubspec.yaml` | `pubspec.lock` |
| Maven | `pom.xml` | — |

Lockfiles take precedence where present: they carry the resolved transitive graph,
which is where real supply-chain compromise lives. A manifest states a *requirement*
rather than a version — `regex = "1"` against a resolved `1.13.1` — so a manifest
entry is dropped once the lockfile has resolved that package. Querying a requirement
string against an advisory database returns every advisory ever filed against the
line, including ones fixed years earlier, which is a critical finding about a
dependency that does not have it. Directness is the one fact only the manifest knows,
so it carries over to the resolved entry.

A design rule worth stating: **absence of data never becomes a finding.** A package whose metadata was not fetched is not reported as "unknown licence".

## Scoring

Penalty is normalised **per 1000 lines**, then decayed exponentially. A 140k-line project with 50 findings scores far better than a 2k-line project with the same 50 — absolute counts would punish size instead of quality.

## Compliance packs

95 controls across four built-in packs, embedded in the binary:
`owasp-asvs` (32) · `cwe-top` (25) · `privacy` (12) · `ecc` (26, an example of encoding
your own internal protocol). Write your own YAML and pass `--pack ./my-pack.yaml`.

Verdicts are three-valued on purpose — `satisfied` / `violated` / `unknown` — and a
control is only *satisfied* when a rule capable of assessing it actually ran. A
compliance report that claims coverage it does not have is worse than no report.

```bash
deadbolt pack list
deadbolt pack show ecc
deadbolt pack validate ./my-pack.yaml
```

## Network and TLS

Live research uses `api.osv.dev`, `registry.npmjs.org`, `pypi.org`, `crates.io`. `--offline` disables all of it.

The binary uses the **operating system trust store**, not bundled roots. Corporate networks frequently terminate TLS with their own CA; bundled Mozilla roots reject those chains while every other tool on the machine works. In a minimal container without a trust store, set `SSL_CERT_FILE`.

## Gates

One global threshold is either too strict for the whole repository or too loose
for the part that matters, so the threshold is resolved **per finding** — global,
per category and per path, strictest wins.

```toml
[gates]
fail_on = "high"
max_unknown_controls = 20        # compliance coverage regression
block_new_dependencies = true    # a PR touching a manifest needs a human decision
max_dependency_age_days = 900    # a direct dependency nobody releases anymore

[gates.category]
secrets = "any"                  # a secret blocks at any severity
cryptography = "medium"

[[gates.path]]
pattern = "**/auth/**"
fail_on = "medium"

[trend]
ratchet = true                   # the score may hold or improve, never fall
tolerance = 1.0
```

### Expiring exceptions

A permanent suppression is how a security tool dies: the comment outlives the
reason and the rule is effectively deleted. Every exception carries a date, and
**an expired exception becomes a finding** — the gate turns red on the calendar,
without anyone having to remember.

```python
db.execute(query)  # deadbolt-ignore DB-INJ-001 until=2026-09-01 reason="US-142"
```

`until=` and `reason=` are both mandatory; a dateless directive is treated as
already expired.

## Your own rules

Compliance packs were always YAML while detection rules were compiled in — that
asymmetry is gone. Drop a file in `.deadbolt/rules/` and it loads at startup:

```yaml
name: acme-internal
rules:
  - id: ACME-001
    title: "Internal service token hardcoded"
    category: secrets          # any Category slug
    severity: critical
    pattern: 'ACME_TOKEN\s*=\s*["''][^"'']{8,}'
    negate: 'os\.environ|getenv'    # regex crate has no look-around; use this
    remediation: "Move the value into the vault and rotate it."
    cwe: 798
```

A malformed pack is a warning naming the offending rule id, never a failed run.

## Portfolio

```
  deadbolt — Portfolio (5 Projects)
  PROJECT                   SCORE     CRIT  HIGH   MED    BLOCK kLOC
  e2e                       0.0    ○     7     4     2      11   0.1
  apitest                  53.7    ◐     0     1     2       1   0.0

  Defects Repeated Across Projects:
    DB-REPO-030      3 Projects — Security headers are not configured
    DB-REPO-031      3 Projects — No rate limiting detected
```

Ranking is by weighted severity, not by score alone: a small project with two
criticals outranks a large one with a hundred lows. The repeated-defects section
is the actionable part — the same defect in three products is **one decision**
(shared template, shared library, shared config), not three tickets.

## CI integration

```yaml
# .github/workflows/security.yml
name: security
on: [pull_request]

jobs:
  deadbolt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # diff mode needs history

      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/Energy40977/deadbolt

      - run: deadbolt diff --base ${{ github.base_ref }} --fail-on high
```

Inside a CI job the annotation format is added automatically — `GITHUB_ACTIONS`
selects GitHub annotations, `GITLAB_CI` selects a Code Quality report — so findings
land on the diff line instead of in a file nobody opens:

```
::error file=services/orders/routes.py,line=88,title=deadbolt DB-AUZ-002 — Identifiers
Are Sequential::An attacker can enumerate other users' objects. Fix: use a random
external identifier and verify ownership on every request.
```

GitLab equivalent:

```yaml
deadbolt:
  stage: test
  script:
    - deadbolt diff --base "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --fail-on high
  artifacts:
    reports:
      codequality: deadbolt-report/deadbolt-gitlab.json
```

Notes for pipelines:

- **Handle exit code 3.** It means a phase did not run — no network, no `claude`
  CLI, cost limit reached. Treating it as success reports "clean" on an audit that
  never happened.
- Use `diff` on pull requests and `audit` on a schedule. A full audit per PR is
  slow and, with the AI layer on, expensive.
- Commit `.deadbolt-baseline.json` so the gate fires on *new* findings only.
- Cache `.deadbolt-cache/` between runs to keep the AI layer cheap; the key is
  content-addressed, so a stale cache cannot serve a wrong answer.
- `--offline` for an air-gapped runner. Everything except dependency research and
  deep research still works.

## Configuration

`deadbolt init` writes a commented `.deadbolt.toml`. Precedence is
**CLI flag > config file > built-in default**, and every field is optional.

```toml
[gates]
fail_on = "high"                    # critical | high | medium | low | never

[paths]
ignore = ["**/node_modules/**", "generated/**"]
ai_forbidden = ["**/crypto/**", "**/keys/**"]   # never sent to an AI tool

[scan]
disabled_rules = ["DB-CFG-004"]     # with a comment saying why
# max_file_kb = 512   # optional; unset means every file is read

[ai]
model = "claude-opus-5"
budget_usd = 8.0
diff_lenses = ["authz", "crypto", "migration"]   # cheap subset for `diff`

[deps]
allow = ["left-pad"]                # accepted risk, no finding

[report]
formats = ["terminal", "markdown"]
packs = ["owasp-asvs", "cwe-top", "privacy"]
```

Options that cannot yet be honoured are **not** in the schema — a config field
that silently does nothing is worse than no field.

## Roadmap

1. Runtime-configurable sensitive-field list for the log-leak rule (currently
   compiled into the pattern).
2. More rule coverage for Java, C# and Kotlin idioms.
3. GraphQL schema diff alongside the OpenAPI one.
4. Cross-file taint tracking — needs a real per-language IR, so it is a separate
   piece of work rather than an extension of `taint-lite`.

## Privacy and what leaves your machine

| Phase | Leaves the machine | To where |
|---|---|---|
| Discover, static rules, taint, history, gates | **nothing** | — |
| Dependency lookup | package names and versions | `api.osv.dev` |
| Registry metadata | package names | `registry.npmjs.org`, `pypi.org`, `crates.io`, and the registry for the ecosystem |
| AI review | file paths and, at the agent's discretion, file contents | Anthropic, through the `claude` CLI you already authenticated |
| Deep package research | package name, version, ecosystem | Anthropic plus whatever the agent searches |

There is no telemetry. `deadbolt` never phones home, has no account, and writes
nothing outside the target directory and its own cache.

Two configuration keys bound the AI layer:

```toml
[paths]
ai_forbidden = ["**/crypto/**", "**/keys/**"]   # never sent to an AI tool
ignore       = ["**/node_modules/**"]           # never scanned at all
```

`ai_forbidden` paths are excluded from the file listing handed to a lens **and**
stated in the prompt as out of scope. The lens still holds `Read`, so this is a
boundary you assert rather than a sandbox — put genuinely untouchable material
behind `ignore`, which removes it from the inventory entirely.

Secret **values** are masked everywhere: the report gives the location and the rule,
never the credential. History findings say *rotate the value*, never *rewrite
history*, because existing clones cannot be reached.

`--offline` disables every network phase. `--no-ai` disables the AI layer. With both,
`deadbolt` is a pure local static analyser.

## Status

Verified against a real polyglot monorepo of roughly 700 files and 90k lines (Python/FastAPI, Next.js, React Native):

| Component | State |
|---|---|
| Stack discovery | ✅ works — languages, frameworks, databases, package managers, CI, IaC |
| Static rule engine (50 line rules) | ✅ works — `RegexSet` prefilter, parallel, ~1.6 s on 912 files |
| Repo-level checks (32) | ✅ works — including eleven added so compliance controls have detectors |
| False-positive controls | ✅ rollback-block awareness, secret-value plausibility gate, test-file severity reduction, commented-code skip, per-rule caps |
| Dependency research (OSV + registry + risk) | ✅ works — 679 packages, real CVEs found |
| Reports: terminal / markdown / json / sarif | ✅ works |
| Exit codes / `--fail-on` | ✅ works |
| AI review lenses (8, skill-driven, sharded) | ✅ works — verified with Opus 5: auth bypass, IDOR→refund chain, SQLi, predictable-token brute-force space. Measured $3.40 per subagent on a 700-file polyglot monorepo |
| Deep package research | ✅ works — verified: `next` telemetry identified with endpoint `telemetry.nextjs.org` and exact opt-out; `lodash` CVEs + EOL, 6 cited sources |
| Compliance packs (95 controls, 4 packs) | ✅ works — three-valued verdicts, violated controls become findings. On the reference monorepo: 64 satisfied, 30 violated, **1 unknown** (a signed document a scanner cannot see) |
| HTML report | ✅ works — ~190 KB self-contained, zero external requests, gauge with thresholds, KPI tiles, attack-path timeline, glossary, auto-opens on a terminal |
| `diff` mode (PR / pre-commit) | ✅ works — narrows to added lines, drops repo-level findings, 12-line tolerance window for AI findings |
| Gates: path / category / expiring exceptions / ratchet / new-dependency / coverage / freshness | ✅ works |
| Git history secret scan | ✅ works — finds credentials removed from the tree, redacted in the report, "rotate not rewrite" |
| OpenAPI contract diff (9 detectors) | ✅ works — verified against a real 5-breaking-change diff |
| Taint-lite (intra-file source → sink) | ✅ works — 10 tests including false-positive guards |
| Your own YAML rule packs | ✅ works |
| Portfolio mode | ✅ works — 5 repositories ranked, repeated defects surfaced |
| SBOM (CycloneDX 1.5) | ✅ works — purl + linked vulnerabilities |
| Trend history + sparkline | ✅ works |
| `explain` / `fix` / `watch` | ✅ works |
| Parallel scan + incremental cache | ✅ works — 911 files: 10.8 s cold, **0.36 s warm**, output byte-identical |
| Baseline | ✅ works — snippet-based fingerprints, stale-entry detection, `--prune` |
| `.deadbolt.toml` | ✅ works — every documented field is wired; `init` writes a commented template |
| Lockfile parsing (11 formats) | ✅ works — npm/yarn/pnpm, poetry/uv, cargo, go.sum, composer, bundler, pub |
| Recon pass (one shared map for every lens) | ✅ works — content-addressed cache, free on an unchanged tree |
| Adversarial verification (independent refuters) | ✅ works — refuted findings removed, survivors marked, removals reported |
| Reachability weighting | ✅ works — entry points raised, dead and example code lowered, framework-loaded files protected |
| Correlated attack paths (6 chains) | ✅ works — verified on the reference monorepo (unauthenticated state change) |
| CI annotations (GitHub / GitLab) | ✅ works — auto-selected inside a job, 124 entries on the reference repo |
| Interactive wizard | ✅ works — arrow keys, cost-tiered colouring, prints the equivalent command |
| Tests | ✅ **125 unit tests**; `cargo clippy --all-targets` clean; `cargo fmt` enforced |

Known limitations:
- `deps` reports one entry per resolved version, so a monorepo with several lockfiles lists the same package more than once.
- Deep research output occasionally mixes languages; it always cites sources, and **claims should be checked against them** before acting.
- Lenses hunt with an attacker mindset and do not strictly respect their own scope: the `authz` lens will report a SQL injection it finds on the way. Overlapping findings from different lenses at the same location are both kept.

## Support

deadbolt is free and Apache-2.0 licensed. There is no paid tier, no telemetry and
no account.

If it saved you an incident, or if your company runs it in CI, there are three
ways to keep it maintained:

- **Sponsor** — the button at the top of this repository
- **Report what it missed** — a false negative with a reproducer is worth more
  than a donation, because it becomes a rule everyone gets
- **Commercial support** — audits, custom rule packs for an internal protocol, or
  help wiring it into an existing pipeline: open an issue titled `commercial`

## Brand

| File | Use |
|---|---|
| `assets/deadbolt-mark.svg` | Primary mark — skull, circuit cranium, keyhole in the frontal bone. Strokes are `currentColor`, so it inherits the surrounding text colour. |
| `assets/deadbolt-logo.svg` | Horizontal lockup with wordmark and tagline. |
| `assets/deadbolt-favicon.svg` | Simplified mark for 16–32 px. The board traces and target brackets are removed and the stroke is heavier, because at that size the detail turns to mud. |

The HTML report embeds the simplified mark inline and carries the favicon as a
`data:` URI, so a report stays self-contained with no external request.

Colour: acid green `#00ff9c` on near-black `#04070a`. On a light background use
`#0b3b26`.

## Licence

Apache-2.0 — see [LICENSE](LICENSE).
