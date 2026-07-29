use std::collections::HashSet;

use crate::discover::Inventory;
use crate::model::{Finding, Severity};

/// Directory names whose contents are not part of the deployed product.
const SIDELINE: &[&str] = &[
    "/example",
    "/examples/",
    "/sample",
    "/demo",
    "/playground",
    "/sandbox",
    "/scripts/",
    "/tools/",
    "/docs/",
    "/doc/",
    "/benchmark",
    "/bench/",
    "/fixtures/",
    "/mock",
    "/e2e/",
    "/prototype",
    "/legacy/",
    "/deprecated/",
    "/archive/",
    "/.storybook/",
    "/storybook/",
];

/// Paths a framework loads by convention rather than by import.
///
/// Nothing in the repository references a migration or a settings module by name —
/// the framework discovers them. Without this list the "nothing references it"
/// heuristic demotes exactly the files whose defects deploy automatically.
const FRAMEWORK_LOADED: &[&str] = &[
    "/migration",
    "/alembic/",
    "/db/migrate/",
    "/settings",
    "/config",
    "/conftest",
    "/urls.",
    "/routes.",
    "/wsgi.",
    "/asgi.",
    "/main.",
    "/__main__.",
    "/index.",
    "/schema.",
    "/manage.",
    "/app.",
    "dockerfile",
    "docker-compose",
    "/.github/",
    "/terraform",
    "/k8s/",
    "/helm/",
];

/// Markers that mean the file itself takes external input.
const ENTRY_MARKERS: &[&str] = &[
    "@app.",
    "@router.",
    "@blueprint.",
    "app.get(",
    "app.post(",
    "router.get(",
    "router.post(",
    "@GetMapping",
    "@PostMapping",
    "@RestController",
    "urlpatterns",
    "path(",
    "@api_view",
    "APIRouter",
    "http.HandleFunc",
    "@Controller",
    "createServer",
    "handler(",
    "exports.handler",
    "@RequestMapping",
    "Route::",
    "resources :",
    "@Get(",
    "@Post(",
];

#[derive(Debug, Default, PartialEq)]
pub struct Adjustment {
    pub raised: usize,
    pub lowered: usize,
}

fn severity_up(severity: Severity) -> Severity {
    match severity {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        other => other,
    }
}

fn severity_down(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        other => other,
    }
}

fn module_stem(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let stem = name.split('.').next()?;
    if stem.is_empty() || stem == "index" || stem == "mod" || stem == "__init__" {
        return None;
    }
    Some(stem)
}

/// Files that no other file mentions by name.
///
/// This is deliberately a name search rather than a real import graph: an import
/// graph per language is a project of its own, and the question here only needs to
/// separate "something references this" from "nothing does".
fn unreferenced(inventory: &Inventory) -> HashSet<String> {
    inventory
        .files
        .iter()
        .filter(|file| {
            let Some(stem) = module_stem(&file.rel_path) else {
                return false;
            };
            if stem.len() < 4 {
                // Short stems collide with ordinary words; assume referenced.
                return false;
            }
            !inventory
                .files
                .iter()
                .any(|other| other.rel_path != file.rel_path && other.content.contains(stem))
        })
        .map(|file| file.rel_path.clone())
        .collect()
}

/// Re-weights findings by how reachable their location is.
///
/// A defect on a route an anonymous caller can hit is not the same defect as one
/// in a script nobody deploys, and reporting them at the same severity means the
/// reader has to re-triage the whole list by hand. Only the severity moves — no
/// finding is removed, because reachability analysis this cheap can be wrong.
///
/// Entry points are checked first: a route file is reachable from outside the
/// repository, so the "nothing references it" heuristic must never demote it.
pub fn calibrate(inventory: &Inventory, findings: &mut [Finding]) -> Adjustment {
    let dead = unreferenced(inventory);

    let entry_files: HashSet<&str> = inventory
        .files
        .iter()
        .filter(|file| {
            ENTRY_MARKERS
                .iter()
                .any(|marker| file.content.contains(marker))
        })
        .map(|file| file.rel_path.as_str())
        .collect();

    let mut adjustment = Adjustment::default();

    for finding in findings.iter_mut() {
        let Some(location) = finding.evidence.first().map(|e| e.file.clone()) else {
            continue;
        };
        if location.starts_with('<') {
            // Project-level findings have no location to reason about.
            continue;
        }
        let lowered = format!("/{}", location.to_lowercase());

        let sidelined = SIDELINE.iter().any(|part| lowered.contains(part));
        let framework_loaded = FRAMEWORK_LOADED.iter().any(|part| lowered.contains(part));
        let is_dead = dead.contains(&location) && !framework_loaded;
        let is_entry = entry_files.contains(location.as_str());

        // Test code is never raised. A fixture that the scanner already softened is
        // not made reachable by living in a file that happens to contain an entry
        // marker — raising it would undo the softening and put a deliberately
        // vulnerable fixture back into the blocking set.
        let in_test_code = inventory
            .files
            .iter()
            .find(|file| file.rel_path == location)
            .is_some_and(|file| {
                file.is_test()
                    || crate::scan::test_region_start(file)
                        .zip(finding.evidence.first().and_then(|e| e.line))
                        .is_some_and(|(boundary, line)| line >= boundary)
            });

        // An entry point is reachable by definition: nothing in the repository has
        // to reference it, because the caller is outside the repository. Letting
        // the name-search heuristic demote it would bury exactly the findings that
        // matter most.
        if is_entry && !in_test_code {
            if finding.severity >= Severity::Medium {
                let next = severity_up(finding.severity);
                if next != finding.severity {
                    finding.severity = next;
                    finding.description = format!(
                        "{} [Severity raised: this file declares an external entry point, so the \
defect is directly reachable.]",
                        finding.description
                    );
                    adjustment.raised += 1;
                }
            }
            continue;
        }

        if sidelined || is_dead {
            let next = severity_down(finding.severity);
            if next != finding.severity {
                finding.severity = next;
                finding.description = format!(
                    "{} [Severity lowered: {}.]",
                    finding.description,
                    if sidelined {
                        "this path is not part of the deployed product"
                    } else {
                        "no other file references this module, so it looks unreachable"
                    }
                );
                adjustment.lowered += 1;
            }
            continue;
        }
    }

    adjustment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{Inventory, SourceFile};
    use crate::model::{Category, Evidence, StackProfile};
    use std::path::PathBuf;

    fn file(path: &str, content: &str) -> SourceFile {
        // Language follows the extension: test-region detection is language-gated,
        // so a hardcoded language would make a .rs fixture behave like Python.
        let language = match path.rsplit('.').next() {
            Some("rs") => "Rust",
            Some("go") => "Go",
            Some("ts") | Some("tsx") => "TypeScript",
            _ => "Python",
        };
        SourceFile {
            rel_path: path.to_string(),
            abs_path: PathBuf::from(path),
            language,
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

    fn finding(path: &str, severity: Severity) -> Finding {
        Finding::builder("DB-X", Category::Injection, severity)
            .title("t")
            .evidence(Evidence::new(path, Some(3), ""))
            .build()
    }

    #[test]
    fn a_finding_on_a_route_file_is_raised() {
        let store = inventory(vec![
            file("app/routes.py", "@app.get('/x')\ndef handler(): pass"),
            file("app/main.py", "import routes"),
        ]);
        let mut findings = vec![finding("app/routes.py", Severity::Medium)];
        let adjustment = calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(adjustment.raised, 1);
    }

    #[test]
    fn a_finding_in_an_example_directory_is_lowered() {
        let store = inventory(vec![file("examples/demo.py", "print(1)")]);
        let mut findings = vec![finding("examples/demo.py", Severity::High)];
        let adjustment = calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(adjustment.lowered, 1);
    }

    #[test]
    fn an_unreferenced_module_is_lowered() {
        let store = inventory(vec![
            file("app/orphaned_helper.py", "def helper(): pass"),
            file("app/main.py", "print(1)"),
        ]);
        let mut findings = vec![finding("app/orphaned_helper.py", Severity::High)];
        calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn a_migration_is_never_treated_as_dead_code() {
        // Nothing imports a migration by name, but the framework runs every one.
        let store = inventory(vec![
            file(
                "backend/migrations/0007_add_column.py",
                "def upgrade(): pass",
            ),
            file("app/main.py", "print(1)"),
        ]);
        let mut findings = vec![finding(
            "backend/migrations/0007_add_column.py",
            Severity::High,
        )];
        let adjustment = calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(adjustment, Adjustment::default());
    }

    #[test]
    fn a_softened_test_fixture_is_never_raised_again() {
        // The file declares an entry marker and also holds an in-file test module.
        // A finding inside that module must not be promoted back.
        let store = inventory(vec![
            file(
                "src/scan/rules.rs",
                "fn route() { app.get(\"/x\"); }\n#[cfg(test)]\nmod tests { const K: &str = \"x\"; }",
            ),
            // Referenced elsewhere, so the dead-code path is not what is under test.
            file("src/main.rs", "mod rules;"),
        ]);
        let mut findings =
            vec![
                Finding::builder("DB-SEC-003", Category::Secrets, Severity::Medium)
                    .title("t")
                    .evidence(Evidence::new("src/scan/rules.rs", Some(3), ""))
                    .build(),
            ];
        let adjustment = calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(adjustment, Adjustment::default());
    }

    #[test]
    fn a_referenced_module_keeps_its_severity() {
        let store = inventory(vec![
            file("app/payments.py", "def charge(): pass"),
            file("app/main.py", "from app.payments import charge"),
        ]);
        let mut findings = vec![finding("app/payments.py", Severity::High)];
        let adjustment = calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(adjustment, Adjustment::default());
    }

    #[test]
    fn critical_is_never_raised_further_and_project_findings_are_untouched() {
        let store = inventory(vec![file("app/routes.py", "@app.get('/x')")]);
        let mut findings = vec![
            finding("app/routes.py", Severity::Critical),
            finding("<project>", Severity::High),
        ];
        calibrate(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::High);
    }
}
