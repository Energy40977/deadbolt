use std::collections::BTreeMap;

use crate::discover::{Inventory, SourceFile};
use crate::model::Package;

pub fn collect(inventory: &Inventory) -> Vec<Package> {
    let mut packages: BTreeMap<(String, String, String), Package> = BTreeMap::new();

    for file in &inventory.files {
        if file.content.is_empty() {
            continue;
        }
        let base = file.rel_path.rsplit('/').next().unwrap_or("");
        let parsed = match base {
            "package.json" => parse_package_json(file),
            "requirements.txt" => parse_requirements(file),
            "pyproject.toml" => parse_pyproject(file),
            "Cargo.toml" => parse_cargo_toml(file),
            "go.mod" => parse_go_mod(file),
            "composer.json" => parse_composer(file),
            "pubspec.yaml" => parse_pubspec(file),
            "Gemfile" => parse_gemfile(file),
            "pom.xml" => parse_pom(file),
            "package-lock.json" => parse_package_lock(file),
            "yarn.lock" => parse_yarn_lock(file),
            "pnpm-lock.yaml" => parse_pnpm_lock(file),
            "Cargo.lock" => parse_cargo_lock(file),
            "poetry.lock" => parse_poetry_lock(file),
            "uv.lock" => parse_poetry_lock(file),
            "go.sum" => parse_go_sum(file),
            "composer.lock" => parse_composer_lock(file),
            "Gemfile.lock" => parse_gemfile_lock(file),
            "pubspec.lock" => parse_pubspec_lock(file),
            _ => Vec::new(),
        };
        for package in parsed {
            let key = (
                package.ecosystem.clone(),
                package.name.clone(),
                package.version.clone(),
            );
            packages
                .entry(key)
                .and_modify(|existing| existing.direct |= package.direct)
                .or_insert(package);
        }
    }

    packages.into_values().collect()
}

fn clean_version(raw: &str) -> String {
    raw.trim()
        .trim_start_matches(['^', '~', '>', '<', '=', 'v', ' '])
        .split(&[' ', ',', '|'][..])
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn make(
    name: &str,
    version: &str,
    ecosystem: &str,
    direct: bool,
    manifest: &str,
) -> Option<Package> {
    let name = name.trim();
    let version = clean_version(version);
    if name.is_empty() || name.starts_with('#') || version.is_empty() || version.contains('*') {
        return None;
    }
    Some(Package {
        name: name.to_string(),
        version,
        ecosystem: ecosystem.to_string(),
        direct,
        manifest: manifest.to_string(),
    })
}

fn parse_package_json(file: &SourceFile) -> Vec<Package> {
    let value: serde_json::Value = match serde_json::from_str(&file.content) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(map) = value.get(section).and_then(|v| v.as_object()) {
            for (name, version) in map {
                if let Some(package) = make(
                    name,
                    version.as_str().unwrap_or(""),
                    "npm",
                    section == "dependencies",
                    &file.rel_path,
                ) {
                    out.push(package);
                }
            }
        }
    }
    out
}

fn parse_package_lock(file: &SourceFile) -> Vec<Package> {
    let value: serde_json::Value = match serde_json::from_str(&file.content) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();

    if let Some(map) = value.get("packages").and_then(|v| v.as_object()) {
        for (path, meta) in map {
            if path.is_empty() {
                continue;
            }
            let name = path.rsplit("node_modules/").next().unwrap_or(path);
            let version = meta.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(package) = make(name, version, "npm", false, &file.rel_path) {
                out.push(package);
            }
        }
    }
    if out.is_empty() {
        if let Some(map) = value.get("dependencies").and_then(|v| v.as_object()) {
            for (name, meta) in map {
                let version = meta.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(package) = make(name, version, "npm", false, &file.rel_path) {
                    out.push(package);
                }
            }
        }
    }
    out
}

fn parse_requirements(file: &SourceFile) -> Vec<Package> {
    file.content
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('-') {
                return None;
            }
            let (name, version) = line.split_once("==")?;
            let name = name.split('[').next().unwrap_or(name);
            make(name, version, "PyPI", true, &file.rel_path)
        })
        .collect()
}

fn parse_pyproject(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed.contains("dependencies") || trimmed.contains("[tool.poetry.dev");
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, version)) = trimmed.split_once('=') {
            let name = name.trim().trim_matches(['"', '\'', ',']);
            let version = version.trim().trim_matches(['"', '\'', ',', '=']);
            if let Some(package) = make(name, version, "PyPI", true, &file.rel_path) {
                out.push(package);
            }
        } else if let Some(caps) = trimmed.trim_matches(['"', '\'', ',']).split_once("==") {
            if let Some(package) = make(caps.0, caps.1, "PyPI", true, &file.rel_path) {
                out.push(package);
            }
        }
    }
    out
}

fn parse_cargo_toml(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed.starts_with("[dependencies")
                || trimmed.starts_with("[dev-dependencies")
                || trimmed.starts_with("[build-dependencies");
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name, rest) = match trimmed.split_once('=') {
            Some(parts) => parts,
            None => continue,
        };
        let version = if rest.contains("version") {
            rest.split("version")
                .nth(1)
                .and_then(|s| s.split('"').nth(1))
                .unwrap_or("")
        } else {
            rest.trim().trim_matches('"')
        };
        if let Some(package) = make(name.trim(), version, "crates.io", true, &file.rel_path) {
            out.push(package);
        }
    }
    out
}

fn parse_cargo_lock(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            name = None;
        } else if let Some(value) = trimmed.strip_prefix("name = ") {
            name = Some(value.trim_matches('"').to_string());
        } else if let Some(value) = trimmed.strip_prefix("version = ") {
            if let Some(package_name) = name.take() {
                if let Some(package) = make(
                    &package_name,
                    value.trim_matches('"'),
                    "crates.io",
                    false,
                    &file.rel_path,
                ) {
                    out.push(package);
                }
            }
        }
    }
    out
}

fn parse_go_mod(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_require = false;
    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && trimmed == ")" {
            in_require = false;
            continue;
        }
        let candidate = trimmed.strip_prefix("require ").unwrap_or(trimmed);
        if !in_require && candidate == trimmed && !trimmed.starts_with("require ") {
            continue;
        }
        let mut parts = candidate.split_whitespace();
        if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
            if let Some(package) = make(name, version, "Go", true, &file.rel_path) {
                out.push(package);
            }
        }
    }
    out
}

fn parse_composer(file: &SourceFile) -> Vec<Package> {
    let value: serde_json::Value = match serde_json::from_str(&file.content) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for section in ["require", "require-dev"] {
        if let Some(map) = value.get(section).and_then(|v| v.as_object()) {
            for (name, version) in map {
                if name == "php" || name.starts_with("ext-") {
                    continue;
                }
                if let Some(package) = make(
                    name,
                    version.as_str().unwrap_or(""),
                    "Packagist",
                    section == "require",
                    &file.rel_path,
                ) {
                    out.push(package);
                }
            }
        }
    }
    out
}

fn parse_pubspec(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in file.content.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_deps = line.starts_with("dependencies:") || line.starts_with("dev_dependencies:");
            continue;
        }
        if !in_deps {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, version)) = trimmed.split_once(':') {
            let version = version.trim().trim_matches(['"', '\'']);
            if version.is_empty() || version.starts_with('{') {
                continue;
            }
            if let Some(package) = make(name.trim(), version, "Pub", true, &file.rel_path) {
                out.push(package);
            }
        }
    }
    out
}

fn parse_gemfile(file: &SourceFile) -> Vec<Package> {
    file.content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix("gem ")?;
            let mut parts = rest.split(',');
            let name = parts.next()?.trim().trim_matches(['"', '\'']);
            let version = parts
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['"', '\'', ' ']);
            make(name, version, "RubyGems", true, &file.rel_path)
        })
        .collect()
}

fn parse_pom(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut group: Option<String> = None;
    let mut artifact: Option<String> = None;
    for line in file.content.lines() {
        let trimmed = line.trim();
        if let Some(value) = extract_tag(trimmed, "groupId") {
            group = Some(value);
        } else if let Some(value) = extract_tag(trimmed, "artifactId") {
            artifact = Some(value);
        } else if let Some(version) = extract_tag(trimmed, "version") {
            if let (Some(g), Some(a)) = (group.clone(), artifact.take()) {
                if !version.starts_with("${") {
                    if let Some(package) =
                        make(&format!("{g}:{a}"), &version, "Maven", true, &file.rel_path)
                    {
                        out.push(package);
                    }
                }
            }
        }
    }
    out
}

fn extract_tag(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)? + open.len();
    let end = line.find(&close)?;
    if end <= start {
        return None;
    }
    Some(line[start..end].trim().to_string())
}

/// yarn.lock — both the v1 text format and Berry's YAML-ish variant.
///
/// v1:     "pkg@^1.0.0", "pkg@~1.1.0":
///           version "1.2.3"
/// Berry:  "pkg@npm:^1.0.0":
///           version: 1.2.3
fn parse_yarn_lock(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;

    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            let header = trimmed.trim_end_matches(':');
            let first = header
                .split(',')
                .next()
                .unwrap_or(header)
                .trim()
                .trim_matches('"');
            pending = extract_scoped_name(first);
            continue;
        }

        if let Some(name) = pending.clone() {
            let value = trimmed
                .strip_prefix("version ")
                .or_else(|| trimmed.strip_prefix("version: "))
                .or_else(|| trimmed.strip_prefix("version:"));
            if let Some(value) = value {
                let version = value.trim().trim_matches('"');
                if let Some(package) = make(&name, version, "npm", false, &file.rel_path) {
                    out.push(package);
                }
                pending = None;
            }
        }
    }
    out
}

/// Splits `@scope/name@spec` or `name@spec` into the package name.
fn extract_scoped_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (scope_prefix, rest) = if let Some(rest) = raw.strip_prefix('@') {
        ("@", rest)
    } else {
        ("", raw)
    };
    let name = rest.split('@').next()?;
    if name.is_empty() {
        return None;
    }
    Some(format!("{scope_prefix}{name}"))
}

/// pnpm-lock.yaml — keys look like `/pkg@1.2.3:` (v6+) or `/pkg/1.2.3:` (v5).
fn parse_pnpm_lock(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    for line in file.content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('/') || !trimmed.ends_with(':') {
            continue;
        }
        let entry = trimmed.trim_end_matches(':').trim_start_matches('/');
        let entry = entry.split('(').next().unwrap_or(entry);

        let (name, version) = match entry.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() => (name.to_string(), version.to_string()),
            _ => match entry.rsplit_once('/') {
                Some((name, version)) => (name.to_string(), version.to_string()),
                None => continue,
            },
        };
        if let Some(package) = make(&name, &version, "npm", false, &file.rel_path) {
            out.push(package);
        }
    }
    out
}

/// poetry.lock and uv.lock share the `[[package]]` TOML shape.
fn parse_poetry_lock(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut in_package = false;

    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            in_package = true;
            name = None;
            continue;
        }
        if trimmed.starts_with('[') && trimmed != "[[package]]" {
            if !trimmed.starts_with("[package.") && !trimmed.starts_with("[[package.") {
                in_package = false;
            }
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("name = ") {
            name = Some(value.trim().trim_matches('"').to_string());
        } else if let Some(value) = trimmed.strip_prefix("version = ") {
            if let Some(package_name) = name.take() {
                if let Some(package) = make(
                    &package_name,
                    value.trim().trim_matches('"'),
                    "PyPI",
                    false,
                    &file.rel_path,
                ) {
                    out.push(package);
                }
            }
        }
    }
    out
}

/// go.sum — `module version hash`; `/go.mod` lines duplicate the module.
fn parse_go_sum(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    for line in file.content.lines() {
        let mut parts = line.split_whitespace();
        let (name, version) = match (parts.next(), parts.next()) {
            (Some(name), Some(version)) => (name, version),
            _ => continue,
        };
        if version.ends_with("/go.mod") {
            continue;
        }
        if version.matches('-').count() >= 2 {
            continue;
        }
        if let Some(package) = make(name, version, "Go", false, &file.rel_path) {
            out.push(package);
        }
    }
    out
}

fn parse_composer_lock(file: &SourceFile) -> Vec<Package> {
    let value: serde_json::Value = match serde_json::from_str(&file.content) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        if let Some(list) = value.get(section).and_then(|v| v.as_array()) {
            for entry in list {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let version = entry.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(package) = make(name, version, "Packagist", false, &file.rel_path) {
                    out.push(package);
                }
            }
        }
    }
    out
}

/// Gemfile.lock — `    name (1.2.3)` under GEM/specs.
fn parse_gemfile_lock(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    for line in file.content.lines() {
        let trimmed = line.trim();
        if !line.starts_with("    ") || !trimmed.ends_with(')') {
            continue;
        }
        let (name, rest) = match trimmed.split_once(" (") {
            Some(parts) => parts,
            None => continue,
        };
        let version = rest.trim_end_matches(')');
        if version.starts_with(['>', '<', '~', '=']) {
            continue;
        }
        if let Some(package) = make(name, version, "RubyGems", false, &file.rel_path) {
            out.push(package);
        }
    }
    out
}

/// pubspec.lock — `  name:` then `    version: "1.2.3"`.
fn parse_pubspec_lock(file: &SourceFile) -> Vec<Package> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;

    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 2 && trimmed.ends_with(':') {
            name = Some(trimmed.trim_end_matches(':').trim_matches('"').to_string());
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("version:") {
            if let Some(package_name) = name.take() {
                if let Some(package) = make(
                    &package_name,
                    value.trim().trim_matches('"'),
                    "Pub",
                    false,
                    &file.rel_path,
                ) {
                    out.push(package);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file(name: &str, content: &str) -> SourceFile {
        SourceFile {
            rel_path: name.to_string(),
            abs_path: PathBuf::from(name),
            language: "Lockfile",
            size: content.len() as u64,
            lines: content.lines().count(),
            content: content.to_string(),
            truncated: false,
        }
    }

    fn names(packages: &[Package]) -> Vec<String> {
        let mut out: Vec<String> = packages
            .iter()
            .map(|package| format!("{}@{}", package.name, package.version))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn yarn_lock_handles_v1_berry_and_multiple_specifiers() {
        let parsed = parse_yarn_lock(&file(
            "yarn.lock",
            r#"# autogenerated
"@babel/core@^7.20.0":
  version "7.23.9"

"lodash@^4.17.20", "lodash@^4.17.21":
  version "4.17.21"

"@scope/pkg@npm:^2.1.0":
  version: 2.1.4
"#,
        ));
        assert_eq!(
            names(&parsed),
            vec!["@babel/core@7.23.9", "@scope/pkg@2.1.4", "lodash@4.17.21"]
        );
    }

    #[test]
    fn pnpm_lock_handles_both_key_styles_and_strips_peer_suffix() {
        let parsed = parse_pnpm_lock(&file(
            "pnpm-lock.yaml",
            r#"packages:
  /axios@1.6.7:
    resolution: {integrity: sha512-x}
  /@types/node@20.11.5:
    resolution: {integrity: sha512-x}
  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-x}
  /old-style/1.0.3:
    resolution: {integrity: sha512-x}
"#,
        ));
        assert_eq!(
            names(&parsed),
            vec![
                "@types/node@20.11.5",
                "axios@1.6.7",
                "old-style@1.0.3",
                "react-dom@18.2.0",
            ]
        );
    }

    #[test]
    fn poetry_lock_survives_sub_tables() {
        let parsed = parse_poetry_lock(&file(
            "poetry.lock",
            r#"[[package]]
name = "requests"
version = "2.31.0"

[package.dependencies]
urllib3 = ">=1.21.1"

[[package]]
name = "django"
version = "4.2.11"
"#,
        ));
        assert_eq!(names(&parsed), vec!["django@4.2.11", "requests@2.31.0"]);
    }

    #[test]
    fn go_sum_skips_go_mod_lines_and_pseudo_versions() {
        let parsed = parse_go_sum(&file(
            "go.sum",
            "github.com/gin-gonic/gin v1.9.1 h1:abc=\n\
             github.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n\
             golang.org/x/crypto v0.17.0 h1:ghi=\n\
             github.com/x/y v0.0.0-20260101120000-abcdef123456 h1:jkl=\n",
        ));
        assert_eq!(
            names(&parsed),
            vec![
                "github.com/gin-gonic/gin@1.9.1",
                "golang.org/x/crypto@0.17.0"
            ]
        );
    }

    #[test]
    fn gemfile_lock_skips_constraint_lines() {
        let parsed = parse_gemfile_lock(&file(
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.3)\n      actionpack (= 7.1.3)\n    nokogiri (1.16.2)\n    puma (>= 5.0)\n",
        ));
        assert_eq!(names(&parsed), vec!["nokogiri@1.16.2", "rails@7.1.3"]);
    }

    #[test]
    fn pubspec_lock_reads_nested_versions() {
        let parsed = parse_pubspec_lock(&file(
            "pubspec.lock",
            "packages:\n  http:\n    dependency: \"direct main\"\n    version: \"1.2.0\"\n  provider:\n    version: \"6.1.2\"\nsdks:\n  dart: \">=3.0.0\"\n",
        ));
        assert_eq!(names(&parsed), vec!["http@1.2.0", "provider@6.1.2"]);
    }

    #[test]
    fn composer_lock_covers_dev_packages() {
        let parsed = parse_composer_lock(&file(
            "composer.lock",
            r#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}],
                "packages-dev":[{"name":"phpunit/phpunit","version":"10.5.10"}]}"#,
        ));
        assert_eq!(
            names(&parsed),
            vec!["monolog/monolog@3.5.0", "phpunit/phpunit@10.5.10"]
        );
    }

    #[test]
    fn placeholder_and_wildcard_versions_are_rejected() {
        assert!(make("pkg", "*", "npm", true, "package.json").is_none());
        assert!(make("", "1.0.0", "npm", true, "package.json").is_none());
        assert!(make("pkg", "", "npm", true, "package.json").is_none());
        assert!(make("pkg", "^1.2.3", "npm", true, "package.json").is_some());
    }
}
