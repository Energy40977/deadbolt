# CLAUDE.md

Brakes, not a tutorial. `CONTRIBUTING.md` says what to build; this file says what
**not** to do, and in what order to decide. Read it before the first tool call of
every task, not after the first mistake.

Two failure modes this exists to stop:

1. **Invention** — a rule ID, a crate API, a passing test, a line number that was
   never read. Stated confidently, wrong.
2. **Waste** — planning a two-line change, exploring files the task never touches,
   building an abstraction for one caller.

---

## 0. The ladder — run it in this order, every time

Stop at the first step that answers the task. Do not skip forward.

1. **Name "done" in one sentence.** The smallest change that satisfies the actual
   ask. If two readings of the ask produce materially different code, ask once
   (§6). Otherwise state the assumption and continue.
2. **Find ground truth.** Grep/read the exact rule ID, field name, CLI flag,
   config key, function signature. **If it wasn't read, it does not exist.**
3. **Edit at the lowest altitude.** Existing file, existing pattern, existing
   naming. New files are a last resort, not a starting point.
4. **Test with the mechanism already here.** Line rules → a `corpus/` annotation.
   Logic → a `#[cfg(test)]` module at the end of the same file. No new harness.
5. **Verify by running.** `cargo fmt --check`, `cargo clippy --all-targets -- -D
   warnings`, `cargo test --release`. All three. Nothing is "done" before this.
6. **Commit** with a conventional prefix, `why` in the body when the diff does not
   say it. Push to the designated `claude/...` branch. PR only if asked.
7. **Report short.** What changed, what was actually verified, what was left out.

### Effort budget — match the task, do not exceed it

| Task | Touch | Do **not** |
|---|---|---|
| Add / change one line rule | `src/scan/catalog.rs` + one `corpus/` file | plan, explore the tree, read README |
| Fix a bug in a known module | that module + its test module | read sibling modules "for context" |
| Change output wording | the one `report/` or `ui.rs` site | restructure the renderer |
| New subsystem / new phase | design first — this one earns thought | assume the old shape fits |

Anything at or under ~3 files: no plan mode, no workflow, no subagent. Just do it.

---

## 1. Never invent

- **Never name a rule ID, CWE, ASVS ref, policy string, CLI flag, config key, or
  function that has not been grepped in this repo.** `DB-CRY-006` exists;
  `DB-CRY-014` might not. Check.
- **Never report a test, build, lint, or CI result that was not run.** "This should
  pass" is not a result. Run it, or say explicitly that it was not run.
- **Never guess a crate API or version.** `Cargo.toml` is the source of truth
  (`toml 1.1`, `sha2 0.11`, `reqwest 0.12` with `rustls-tls-native-roots`,
  `dialoguer 0.12`). For API shape, fetch the docs — do not reconstruct from
  memory. A wrong version constraint has already broken this repo once.
- **The `regex` crate has no look-around and no backreferences.** Never write
  `(?=`, `(?!`, `(?<=`, `(?<!`, `\1`. "X is missing" is expressed with `negate`.
- **Never paraphrase `README.md` / `CONTRIBUTING.md` from memory.** Open the
  section and quote the line.
- **Never state a number that was not measured** — rule counts, line counts, file
  counts, timings, coverage. Measure it or leave it out.
- **Absence of evidence is never evidence of a defect.** The engine enforces this;
  so must the analysis. A file not read is not a file that is clean.

---

## 2. Never widen the scope

- No new module, file, trait, or enum variant when an existing one takes the
  change.
- No rename, no reflow, no comment cleanup, no drive-by refactor of code the task
  did not require touching.
- **No new dependency without asking.** Supply chain is this tool's own subject.
- No config knob, feature flag, or generic parameter for a single caller.
- No extra `.md`, summary, or report file unless asked. Answer in the reply.
- **Do not touch, unless the task is precisely about them:**
  - `corpus/**` file contents — the defects are the fixtures, not bugs to fix
  - `.deadbolt.toml` `paths.ignore` / `deps.allow` — structural, documented in place
  - `.deadbolt-baseline.json`, `.deadbolt-history.jsonl` — run state, not source
  - `Cargo.lock` — only alongside a real dependency change
  - the commit-pinned action SHAs in `.github/workflows/ci.yml` — Dependabot owns them
  - `LICENSE`, `assets/**`
- `README.md` is ~47k. Jump to the `##` section by grep; never read it whole.

---

## 3. Never over-think

- Do not enumerate options in the reply. Pick one, justify it in one clause.
- Do not read the same file twice, or re-verify a check that already passed.
- Do not write a helper for two call sites.
- Do not `cargo build --release` when `cargo check` answers the question. Run the
  release test suite once, at the end — not per edit.
- Do not read a >1000-line file whole (`repo.rs`, `mod.rs`, `catalog.rs`). Grep to
  a line range and read that.
- **Three strikes.** If the same approach fails three times, stop. Report the
  actual error and what it rules out. Do not keep drilling.
- Do not model hypothetical futures ("if we later support X"). Build today's ask.

---

## 4. Never fake the finish

- No "all tests pass" without having seen the output. If a check was skipped, name
  which one and why.
- If one part is blocked, finish every other part in full, then say plainly what is
  left and why. Silently shrinking the scope is worse than reporting the blocker.
- Exit code `3` means a phase did not run — **degraded, not clean.** Never report it
  as success.
- No self-assessment ("production-ready", "robust", "comprehensive"), no emoji, no
  table restating the diff. The diff is the record.
- If a claim was wrong, correct it in one sentence and move on. No post-mortem.

---

## 5. Repo-specific traps

Each of these has produced a wrong answer before.

- **`corpus/` is deliberately vulnerable.** Findings there are the point. Markers:
  `deadbolt-expect`, `deadbolt-noise`, `deadbolt-gap`, `deadbolt-clean`; an
  annotation applies to the next non-blank, non-annotation line.
- **`catalog.rs`, `ai/markers.rs`, `skills/**`, `packs/**` are ignored on purpose**
  — they *contain* the patterns the engine hunts for. Scanning them reports the
  tool's vocabulary as the tool's defects.
- **Migration rules stop at `downgrade()` / `down()`** — destruction is correct in a
  rollback block.
- **Compliance verdicts are three-valued.** `detected_by: {}` → `unknown`. Never
  make a control `satisfied` because nothing matched.
- **A new rule needs an `impact` that names what an attacker or failure achieves** —
  not a restatement of the title — and a false-positive guard with a test that the
  idiom stays quiet.
- **Every user-visible string is English.** No exceptions, including examples.
- `--no-ai --offline` self-audit must stay deterministic: no network, no model
  dependency in that path.

---

## 6. When to stop and ask

Only three cases:

1. The action is destructive or hard to reverse (history rewrite, force push, mass
   delete, anything outward-facing).
2. The ask collides with `CONTRIBUTING.md`'s rejection list — e.g. a rule with no
   verifiable impact, a detector that guesses.
3. Two readings of the ask lead to materially different work.

One message, all questions batched, with a recommended answer. Everything that does
not depend on the answer gets done first. Anything else: assume, state the
assumption, proceed.

---

## 7. Done means all of these

- [ ] The ask is satisfied — and nothing beyond it was changed
- [ ] `cargo fmt --check` ran and passed
- [ ] `cargo clippy --all-targets -- -D warnings` ran and passed
- [ ] `cargo test --release` ran and passed
- [ ] Corpus annotations updated if a rule's behaviour changed
- [ ] Conventional commit prefix; `why` in the body
- [ ] Pushed to the designated branch; PR only if it was requested
- [ ] Reply states what was verified and what was not done
