use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ignore::WalkBuilder;

use crate::model::{LanguageStat, StackProfile};

/// Files larger than this are inventoried but not read (kept out of memory).
const MAX_READ_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub rel_path: String,
    /// Absolute path — used by size checks and reserved for future phases that
    /// need to re-read a file outside the inventory.
    #[allow(dead_code)]
    pub abs_path: PathBuf,
    pub language: &'static str,
    #[allow(dead_code)]
    pub size: u64,
    pub lines: usize,
    pub content: String,
    /// True when the file exceeded the read limit, so `content` is empty.
    #[allow(dead_code)]
    pub truncated: bool,
}

impl SourceFile {
    pub fn is_test(&self) -> bool {
        let lowered = self.rel_path.to_lowercase();
        lowered.contains("/test")
            || lowered.starts_with("test")
            || lowered.contains("_test.")
            || lowered.contains(".test.")
            || lowered.contains(".spec.")
            || lowered.contains("/spec/")
            || lowered.contains("__tests__")
            || lowered.contains("/fixtures/")
    }

    pub fn is_migration(&self) -> bool {
        let lowered = self.rel_path.to_lowercase();
        lowered.contains("migration")
            || lowered.contains("/alembic/")
            || lowered.contains("/migrate/")
            || lowered.contains("/db/changelog")
    }

    pub fn is_frontend(&self) -> bool {
        matches!(
            self.language,
            "TypeScript" | "JavaScript" | "Vue" | "Svelte" | "HTML" | "CSS"
        )
    }

    pub fn is_infra(&self) -> bool {
        let lowered = self.rel_path.to_lowercase();
        lowered.ends_with(".tf")
            || lowered.ends_with(".tfvars")
            || lowered.contains("dockerfile")
            || lowered.contains("docker-compose")
            || lowered.contains("/k8s/")
            || lowered.contains("/kubernetes/")
            || lowered.ends_with(".nomad")
            || lowered.contains("/helm/")
            || lowered.contains("nginx")
            || lowered.contains("caddyfile")
    }

    /// Iterate `(line_number, line)` pairs, 1-indexed.
    pub fn lines_iter(&self) -> impl Iterator<Item = (u32, &str)> {
        self.content
            .lines()
            .enumerate()
            .map(|(index, line)| (index as u32 + 1, line))
    }
}

#[derive(Debug, Clone)]
pub struct Inventory {
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
    pub stack: StackProfile,
    pub manifests: Vec<String>,
    pub skipped_large: usize,
    /// First few skipped paths, so the warning can name them.
    pub skipped_large_names: Vec<String>,
}

impl Inventory {
    pub fn has_path_containing(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        self.files
            .iter()
            .any(|f| f.rel_path.to_lowercase().contains(&needle))
    }

    pub fn read_root_file(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(name)).ok()
    }
}

fn language_for(path: &Path) -> Option<&'static str> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let by_name = match name.as_str() {
        "yarn.lock" | "poetry.lock" | "uv.lock" | "composer.lock" | "gemfile.lock"
        | "pubspec.lock" | "cargo.lock" | "pnpm-lock.yaml" | "package-lock.json" | "go.sum"
        | "flake.lock" => Some("Lockfile"),
        "dockerfile" => Some("Docker"),
        "caddyfile" => Some("Config"),
        "makefile" => Some("Make"),
        "gemfile" | "rakefile" => Some("Ruby"),
        "procfile" => Some("Config"),
        _ if name.starts_with("dockerfile.") => Some("Docker"),
        _ => None,
    };
    if by_name.is_some() {
        return by_name;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    Some(match ext.as_str() {
        "py" | "pyi" => "Python",
        "js" | "mjs" | "cjs" => "JavaScript",
        "jsx" => "JavaScript",
        "ts" | "mts" | "cts" => "TypeScript",
        "tsx" => "TypeScript",
        "vue" => "Vue",
        "svelte" => "Svelte",
        "go" => "Go",
        "rs" => "Rust",
        "java" => "Java",
        "kt" | "kts" => "Kotlin",
        "swift" => "Swift",
        "dart" => "Dart",
        "rb" => "Ruby",
        "php" => "PHP",
        "cs" => "C#",
        "c" | "h" => "C",
        "cpp" | "cc" | "cxx" | "hpp" => "C++",
        "scala" => "Scala",
        "ex" | "exs" => "Elixir",
        "sql" => "SQL",
        "sh" | "bash" | "zsh" => "Shell",
        "tf" | "tfvars" => "Terraform",
        "html" | "htm" => "HTML",
        "css" | "scss" | "sass" | "less" => "CSS",
        "yaml" | "yml" => "YAML",
        "json" => "JSON",
        "toml" => "TOML",
        "xml" => "XML",
        "gradle" => "Gradle",
        "env" => "Env",
        "ini" | "cfg" | "conf" | "properties" => "Config",
        _ => return None,
    })
}

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".svn",
    "vendor",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".next",
    ".nuxt",
    ".output",
    "coverage",
    ".gradle",
    "Pods",
    "DerivedData",
    ".dart_tool",
    ".terraform",
    "deadbolt-report",
    ".deadbolt-cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
];

/// Reports this tool writes. Scanning them makes the previous run's findings into
/// this run's findings: a report quotes the evidence it found, so the fixture keys
/// and SQL strings inside it match the rules that produced them. Anyone who writes
/// a report into the repository tree hits this on the next run.
const OWN_ARTEFACTS: &[&str] = &[
    "deadbolt-report.html",
    "deadbolt-report.md",
    "deadbolt-report.json",
    "deadbolt.sarif",
    "deadbolt-sbom.cdx.json",
    "deadbolt-gitlab.json",
    "deadbolt-portfolio.md",
    "deadbolt-portfolio.json",
    ".deadbolt-baseline.json",
    ".deadbolt-history.jsonl",
];

fn should_skip(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    let base = parts.last().copied().unwrap_or("");
    parts.iter().any(|part| SKIP_DIRS.contains(part))
        || OWN_ARTEFACTS.contains(&base)
        || rel.ends_with(".min.js")
        || rel.ends_with(".min.css")
        || rel.ends_with(".map")
}

fn looks_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(4096)];
    sample.contains(&0)
}

pub fn discover(root: &Path) -> Result<Inventory> {
    discover_with(root, MAX_READ_BYTES)
}

/// `max_read_bytes` bounds how large a file may be before it is inventoried
/// but not read into memory (configurable via `scan.max_file_kb`).
pub fn discover_with(root: &Path, max_read_bytes: u64) -> Result<Inventory> {
    let root = root
        .canonicalize()
        .with_context(|| format!("Could Not Open Target: {}", root.display()))?;

    let mut files: Vec<SourceFile> = Vec::new();
    let mut skipped_large = 0usize;
    let mut skipped_large_names: Vec<String> = Vec::new();

    let walker = WalkBuilder::new(&root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .follow_links(false)
        .max_depth(Some(24))
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }

        let abs_path = entry.path().to_path_buf();
        let rel_path = abs_path
            .strip_prefix(&root)
            .unwrap_or(&abs_path)
            .to_string_lossy()
            .replace('\\', "/");

        if should_skip(&rel_path) {
            continue;
        }

        let language = match language_for(&abs_path) {
            Some(language) => language,
            None => continue,
        };

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let (content, truncated) = if size > max_read_bytes {
            skipped_large += 1;
            if skipped_large_names.len() < 5 {
                skipped_large_names.push(rel_path.clone());
            }
            (String::new(), true)
        } else {
            match std::fs::read(&abs_path) {
                Ok(bytes) if !looks_binary(&bytes) => {
                    (String::from_utf8_lossy(&bytes).into_owned(), false)
                }
                _ => continue,
            }
        };

        let lines = if truncated {
            0
        } else {
            content.lines().count()
        };

        files.push(SourceFile {
            rel_path,
            abs_path,
            language,
            size,
            lines,
            content,
            truncated,
        });
    }

    let stack = fingerprint(&root, &files);
    let manifests = collect_manifests(&files);

    Ok(Inventory {
        root,
        files,
        stack,
        manifests,
        skipped_large,
        skipped_large_names,
    })
}

const MANIFEST_NAMES: &[&str] = &[
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "pubspec.yaml",
    "Package.swift",
    "mix.exs",
    "*.csproj",
];

fn collect_manifests(files: &[SourceFile]) -> Vec<String> {
    let mut found = BTreeSet::new();
    for file in files {
        let base = file.rel_path.rsplit('/').next().unwrap_or("");
        for manifest in MANIFEST_NAMES {
            if *manifest == base || (manifest.starts_with('*') && base.ends_with(&manifest[1..])) {
                found.insert(file.rel_path.clone());
            }
        }
    }
    found.into_iter().collect()
}

struct Marker {
    label: &'static str,
    files: &'static [&'static str],
    contents: &'static [&'static str],
}

const FRAMEWORKS: &[Marker] = &[
    Marker {
        label: "FastAPI",
        files: &[],
        contents: &["from fastapi", "FastAPI("],
    },
    Marker {
        label: "Django",
        files: &["manage.py"],
        contents: &["django.db", "DJANGO_SETTINGS_MODULE"],
    },
    Marker {
        label: "Flask",
        files: &[],
        contents: &["from flask", "Flask(__name__)"],
    },
    Marker {
        label: "Express",
        files: &[],
        contents: &["require('express')", "from 'express'"],
    },
    Marker {
        label: "NestJS",
        files: &[],
        contents: &["@nestjs/common"],
    },
    Marker {
        label: "Next.js",
        files: &["next.config.js", "next.config.mjs", "next.config.ts"],
        contents: &["from 'next'"],
    },
    Marker {
        label: "Nuxt",
        files: &["nuxt.config.ts", "nuxt.config.js"],
        contents: &[],
    },
    Marker {
        label: "React",
        files: &[],
        contents: &["from 'react'", "from \"react\""],
    },
    Marker {
        label: "Vue",
        files: &[],
        contents: &["from 'vue'"],
    },
    Marker {
        label: "Angular",
        files: &["angular.json"],
        contents: &["@angular/core"],
    },
    Marker {
        label: "Svelte",
        files: &["svelte.config.js"],
        contents: &[],
    },
    Marker {
        label: "Spring Boot",
        files: &[],
        contents: &["org.springframework.boot"],
    },
    Marker {
        label: "Quarkus",
        files: &[],
        contents: &["io.quarkus"],
    },
    Marker {
        label: "Laravel",
        files: &["artisan"],
        contents: &["Illuminate\\"],
    },
    Marker {
        label: "Rails",
        files: &["config/routes.rb"],
        contents: &["Rails.application"],
    },
    Marker {
        label: "Gin",
        files: &[],
        contents: &["github.com/gin-gonic/gin"],
    },
    Marker {
        label: "Axum",
        files: &[],
        contents: &["axum::"],
    },
    Marker {
        label: "Flutter",
        files: &["pubspec.yaml"],
        contents: &["package:flutter/"],
    },
    Marker {
        label: "React Native",
        files: &[],
        contents: &["react-native"],
    },
    Marker {
        label: "SwiftUI",
        files: &[],
        contents: &["import SwiftUI"],
    },
    Marker {
        label: "Jetpack Compose",
        files: &[],
        contents: &["androidx.compose"],
    },
];

const DATABASES: &[Marker] = &[
    Marker {
        label: "PostgreSQL",
        files: &[],
        contents: &["postgresql://", "postgres://", "psycopg", "pg_", "asyncpg"],
    },
    Marker {
        label: "MySQL",
        files: &[],
        contents: &["mysql://", "mysqlclient", "pymysql"],
    },
    Marker {
        label: "SQLite",
        files: &[],
        contents: &["sqlite://", "sqlite3"],
    },
    Marker {
        label: "MongoDB",
        files: &[],
        contents: &["mongodb://", "mongoose", "pymongo"],
    },
    Marker {
        label: "Redis",
        files: &[],
        contents: &["redis://", "createClient(", "aioredis"],
    },
    Marker {
        label: "SQL Server",
        files: &[],
        contents: &["mssql", "pyodbc"],
    },
    Marker {
        label: "Elasticsearch",
        files: &[],
        contents: &["elasticsearch"],
    },
];

const CI_SYSTEMS: &[Marker] = &[
    Marker {
        label: "GitHub Actions",
        files: &[],
        contents: &[],
    },
    Marker {
        label: "GitLab CI",
        files: &[".gitlab-ci.yml"],
        contents: &[],
    },
    Marker {
        label: "CircleCI",
        files: &[".circleci/config.yml"],
        contents: &[],
    },
    Marker {
        label: "Jenkins",
        files: &["Jenkinsfile"],
        contents: &[],
    },
    Marker {
        label: "Azure Pipelines",
        files: &["azure-pipelines.yml"],
        contents: &[],
    },
];

const INFRA: &[Marker] = &[
    Marker {
        label: "Docker",
        files: &["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
        contents: &[],
    },
    Marker {
        label: "Kubernetes",
        files: &[],
        contents: &["apiVersion: apps/v1", "kind: Deployment"],
    },
    Marker {
        label: "Terraform",
        files: &[],
        contents: &["resource \"", "provider \""],
    },
    Marker {
        label: "Helm",
        files: &["Chart.yaml"],
        contents: &[],
    },
    Marker {
        label: "Nginx",
        files: &[],
        contents: &["server_name", "proxy_pass"],
    },
    Marker {
        label: "Caddy",
        files: &["Caddyfile"],
        contents: &[],
    },
];

fn matches_marker(marker: &Marker, files: &[SourceFile]) -> bool {
    for file in files {
        let base = file.rel_path.rsplit('/').next().unwrap_or("");
        if marker
            .files
            .iter()
            .any(|name| *name == base || *name == file.rel_path)
        {
            return true;
        }
        if !marker.contents.is_empty()
            && !file.content.is_empty()
            && marker
                .contents
                .iter()
                .any(|needle| file.content.contains(needle))
        {
            return true;
        }
    }
    false
}

fn detect(markers: &[Marker], files: &[SourceFile]) -> Vec<String> {
    markers
        .iter()
        .filter(|marker| matches_marker(marker, files))
        .map(|marker| marker.label.to_string())
        .collect()
}

fn package_managers(files: &[SourceFile]) -> Vec<String> {
    let mut found = BTreeSet::new();
    for file in files {
        let base = file.rel_path.rsplit('/').next().unwrap_or("");
        let manager = match base {
            "package.json" | "package-lock.json" => "npm",
            "yarn.lock" => "yarn",
            "pnpm-lock.yaml" => "pnpm",
            "bun.lockb" => "bun",
            "requirements.txt" => "pip",
            "pyproject.toml" | "poetry.lock" => "poetry/uv",
            "Pipfile" => "pipenv",
            "Cargo.toml" => "cargo",
            "go.mod" => "go modules",
            "pom.xml" => "maven",
            "build.gradle" | "build.gradle.kts" => "gradle",
            "composer.json" => "composer",
            "Gemfile" => "bundler",
            "pubspec.yaml" => "pub",
            "Package.swift" => "swiftpm",
            "mix.exs" => "hex",
            _ => continue,
        };
        found.insert(manager.to_string());
    }
    found.into_iter().collect()
}

fn fingerprint(root: &Path, files: &[SourceFile]) -> StackProfile {
    let mut per_language: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    for file in files {
        let entry = per_language.entry(file.language).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += file.lines;
    }

    let mut languages: Vec<LanguageStat> = per_language
        .into_iter()
        .map(|(name, (count, lines))| LanguageStat {
            name: name.to_string(),
            files: count,
            lines,
        })
        .collect();
    languages.sort_by(|a, b| b.lines.cmp(&a.lines).then(b.files.cmp(&a.files)));

    let mut ci_systems = detect(CI_SYSTEMS, files);
    if root.join(".github/workflows").is_dir() {
        ci_systems.push("GitHub Actions".to_string());
        ci_systems.sort();
        ci_systems.dedup();
    }

    let frameworks = detect(FRAMEWORKS, files);
    let infrastructure = detect(INFRA, files);

    let has_mobile = frameworks.iter().any(|f| {
        matches!(
            f.as_str(),
            "Flutter" | "React Native" | "SwiftUI" | "Jetpack Compose"
        )
    }) || languages
        .iter()
        .any(|l| matches!(l.name.as_str(), "Swift" | "Dart" | "Kotlin"));

    let has_frontend = files.iter().any(SourceFile::is_frontend);
    let has_migrations = files.iter().any(SourceFile::is_migration);
    let has_iac = files.iter().any(SourceFile::is_infra);

    let has_backend = languages.iter().any(|l| {
        matches!(
            l.name.as_str(),
            "Python" | "Go" | "Java" | "Rust" | "PHP" | "Ruby" | "C#" | "Elixir" | "Scala"
        )
    }) || frameworks.iter().any(|f| {
        matches!(
            f.as_str(),
            "Express" | "NestJS" | "Next.js" | "Nuxt" | "FastAPI" | "Django" | "Flask"
        )
    });

    StackProfile {
        total_files: files.len(),
        total_lines: languages.iter().map(|l| l.lines).sum(),
        languages,
        frameworks,
        databases: detect(DATABASES, files),
        package_managers: package_managers(files),
        ci_systems,
        infrastructure,
        has_frontend,
        has_backend,
        has_mobile,
        has_migrations,
        has_iac,
    }
}

#[cfg(test)]
mod artefact_tests {
    use super::should_skip;

    #[test]
    fn the_tools_own_reports_are_never_scanned() {
        assert!(should_skip("audit/deadbolt-report.html"));
        assert!(should_skip("deadbolt-report.json"));
        assert!(should_skip("nested/dir/deadbolt.sarif"));
        assert!(should_skip(".deadbolt-baseline.json"));
        // A file that merely mentions the name is still source code.
        assert!(!should_skip("src/deadbolt_report_builder.rs"));
        assert!(!should_skip("docs/deadbolt-report.md.tmpl"));
    }
}
