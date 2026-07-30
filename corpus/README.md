# corpus — known-bad code the engine must keep finding

Every file here contains a deliberate defect, annotated in place with the rule that
must report it. `tests/corpus.rs` copies the tree into a temporary directory, runs the
real `deadbolt scan` binary over it, and compares the report against the annotations.

The failure this exists to catch is the one a unit test cannot: a rule that still has
a passing regex test but no longer fires end to end, because a false-positive guard
widened, a scope check changed, or a context heuristic softened it. When that happens
the report stays green and reads as "nothing wrong" while it means "nothing looked".

Do not "fix" the code in this directory. The defects are the fixtures.

## Annotations

An annotation applies to the next line that is neither blank nor another annotation.
It always sits in a comment, so the scanner skips the annotation line itself.

| Marker | Meaning |
| --- | --- |
| `deadbolt-expect DB-SEC-001:critical` | the next line must be reported by this rule, at this severity |
| `deadbolt-expect DB-SEC-003:critical DB-SEC-005:high` | several rules on one line |
| `deadbolt-gap DB-SEC-001` | this rule does **not** report the next line today — a known miss |
| `deadbolt-noise DB-AUN-001:high` | this rule **does** report the next line today, and should not — a known over-report |
| `deadbolt-clean` | file level: nothing in this file may be reported |

`gap` and `noise` record today's wrong answer. Both are assertions, so an improved
pattern fails the suite and the annotation gets deleted as part of the fix. A gap that
is merely known stays known; one that is pinned cannot be forgotten.

## Adding a case

1. Write the smallest realistic file that triggers the rule, under a directory named
   for the category. Realistic matters: the rule set is full of false-positive guards,
   and a fixture that dodges them proves nothing about production code.
2. Annotate the defect line.
3. Run `cargo test --test corpus`.
4. If the finding does not appear, check the guards before changing the rule — the
   words `example`, `test`, `mock`, `fake`, `placeholder`, `dummy`, `fixture` and an
   `os.environ`/`process.env` read all suppress secret findings on purpose.

Two constraints come from the engine itself:

- **Paths must not look like tests.** `SourceFile::is_test` matches `test`, `spec`,
  `__tests__` and `fixtures` anywhere in the path; those files skip every
  `skip_tests` rule and have the rest softened by one step. A directory named
  `fixtures/` here would quietly disable half the suite — which is why the staged
  copy lands on neutral paths and why this directory is not called `fixtures`.
- **Three hits per rule per file.** `MAX_PER_RULE_PER_FILE` collapses the rest, so
  split a fourth case of the same rule into another file.

## What the run turns off

Reachability weighting (`[reach]`) and chain correlation (`[chains]`) are disabled for
the staged copy. Both reason across files; each case here is one isolated file that
nothing imports, so with them on the suite would pin "unreferenced module" arithmetic
rather than the severity each rule carries. They are tested separately.

## Scope

The comparison covers the rules the corpus makes a claim about. Findings from any
other rule — repository-level checks, taint, chains — are ignored inside these files,
so those can evolve without editing the corpus.

The self-audit ignores `corpus/**` (see `.deadbolt.toml`), and the directory is
excluded from the published crate (see `Cargo.toml`).
