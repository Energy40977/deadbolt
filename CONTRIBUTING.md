# Contributing

## Before you start

Run the checks the CI runs:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --release
```

All three must pass. There is no separate lint config to learn.

## Adding a rule

A rule is worth adding when it describes a **defect class**, reports what an
attacker or a failure achieves, and can be verified from the code alone.

Line-level rules live in `src/scan/catalog.rs`. Every field is required for a
reason:

| Field | Requirement |
|---|---|
| `title` | plain language, no jargon. `Error Caught But Never Recorded`, not `Silent exception swallow` |
| `description` | what the pattern found, one sentence |
| `impact` | **what an attacker or a failure achieves.** Not a restatement of the title |
| `remediation` | concrete and ordered. If it has three steps, write three steps |
| `pattern` | the Rust `regex` crate has **no look-around**. Express "X is missing" with `negate` |
| `cwe`, `asvs` | wherever one applies |

Two things a new rule must not do:

- **Report the absence of data.** A package whose metadata failed to fetch is not
  a finding about its licence. This is enforced throughout: absence of evidence is
  never evidence of a defect.
- **Fire on a rollback block.** Migration rules stop at `downgrade()` / `down()`,
  where a destructive operation is correct.

Add a test in the same file for both directions: the pattern fires on the defect
and stays quiet on the idiom that looks like it. False-positive guards are the
part that keeps a scanner usable.

Repo-level checks — defects of absence — live in `src/scan/repo.rs` and follow the
same rules.

## Adding a compliance control

Packs are YAML in `packs/`. A control needs a detector:

```yaml
- id: PRIV-13
  title: "Session tokens are stored hashed"
  severity: high
  detected_by:
    rules: [DB-CRY-009, AI-crypto]
```

A control with `detected_by: {}` evaluates to `unknown`, and an unknown control is
indistinguishable from an unchecked one. If a control genuinely cannot be assessed
from code — a signed document, for example — say so in `note` rather than inventing
a detector that guesses.

Verdicts are three-valued on purpose. Never make a control report `satisfied`
because nothing matched; that requires a detector to have actually run.

## Changing a skill

Skill files in `skills/` are pentest methodologies, not checklists. Keep the five
phases: learn the project's own defence pattern, enumerate the surface, work the
attack tree, verify, then check against the known false-positive traps.

The reporting bar in `_ENGAGEMENT.md` is deliberately high — entry point, path,
absence of the control, concrete scenario, impact. Lowering it produces findings
that fail verification, which is worse than no finding.

## Commits

Conventional prefixes: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`,
`perf:`, `ci:`. Explain **why** in the body when the change is not obvious from the
diff.

## What gets rejected

- A rule with no `impact`, or one whose `impact` restates the title
- A pattern with no false-positive test
- A finding that cannot name a concrete wrong outcome
- A compliance control whose detector cannot actually assess it
- Output text in any language other than English
