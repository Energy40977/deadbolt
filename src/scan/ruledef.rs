use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::catalog::{Rule, Scope};
use crate::model::{Category, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// Compiled into the binary.
    BuiltIn,
    /// Loaded from a YAML pack; the string is the pack name.
    User(String),
}

#[derive(Debug, Clone)]
pub struct RuleDef {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub pattern: String,
    pub negate: Option<String>,
    pub languages: Vec<String>,
    pub scope: Scope,
    pub skip_tests: bool,
    pub cwe: Option<u32>,
    pub asvs: Vec<String>,
    pub policy: Vec<String>,
    pub source: RuleSource,
}

impl From<&'static Rule> for RuleDef {
    fn from(rule: &'static Rule) -> Self {
        Self {
            id: rule.id.to_string(),
            category: rule.category,
            severity: rule.severity,
            title: rule.title.to_string(),
            description: rule.description.to_string(),
            impact: rule.impact.to_string(),
            remediation: rule.remediation.to_string(),
            pattern: rule.pattern.to_string(),
            negate: rule.negate.map(str::to_string),
            languages: rule.languages.iter().map(|s| s.to_string()).collect(),
            scope: rule.scope,
            skip_tests: rule.skip_tests,
            cwe: rule.cwe,
            asvs: rule.asvs.iter().map(|s| s.to_string()).collect(),
            policy: rule.policy.iter().map(|s| s.to_string()).collect(),
            source: RuleSource::BuiltIn,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    pub name: String,
    /// Shown by `deadbolt pack`-style listings of user rule packs.
    #[allow(dead_code)]
    #[serde(default)]
    pub description: String,
    pub rules: Vec<YamlRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlRule {
    pub id: String,
    pub title: String,
    /// One of the `Category` slugs, e.g. `secrets`, `authorization`.
    pub category: String,
    /// `critical` | `high` | `medium` | `low` | `info`
    pub severity: String,
    /// Regex applied to each added line. The `regex` crate has no look-around;
    /// express "X is missing" with `negate` instead.
    pub pattern: String,
    #[serde(default)]
    pub negate: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub remediation: String,
    /// Empty = every language.
    #[serde(default)]
    pub languages: Vec<String>,
    /// `any` | `code` | `migration` | `frontend` | `infra` | `config`
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default = "default_true")]
    pub skip_tests: bool,
    #[serde(default)]
    pub cwe: Option<u32>,
    #[serde(default)]
    pub asvs: Vec<String>,
    #[serde(default)]
    pub policy: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn parse_category(raw: &str) -> Result<Category> {
    let category = match raw.trim().to_ascii_lowercase().as_str() {
        "secrets" => Category::Secrets,
        "cryptography" | "crypto" => Category::Cryptography,
        "authentication" | "authn" => Category::Authentication,
        "authorization" | "authz" => Category::Authorization,
        "injection" => Category::Injection,
        "data-protection" | "data" => Category::DataProtection,
        "privacy" => Category::Privacy,
        "error-handling" | "errors" => Category::ErrorHandling,
        "supply-chain" | "supply" => Category::SupplyChain,
        "infrastructure" | "infra" => Category::Infrastructure,
        "frontend" => Category::Frontend,
        "mobile" => Category::Mobile,
        "database" | "db" => Category::Database,
        "api-contract" | "api" => Category::ApiContract,
        "configuration" | "config" => Category::Configuration,
        "compliance" => Category::Compliance,
        other => anyhow::bail!(
            "Unknown category '{other}'. Allowed: secrets, cryptography, \
authentication, authorization, injection, data-protection, privacy, \
error-handling, supply-chain, infrastructure, frontend, mobile, database, \
api-contract, configuration, compliance"
        ),
    };
    Ok(category)
}

fn parse_scope(raw: Option<&str>) -> Result<Scope> {
    let scope = match raw.unwrap_or("any").trim().to_ascii_lowercase().as_str() {
        "any" => Scope::Any,
        "code" => Scope::Code,
        "migration" => Scope::Migration,
        "frontend" => Scope::Frontend,
        "infra" | "infrastructure" => Scope::Infra,
        "config" | "configuration" => Scope::Config,
        other => anyhow::bail!(
            "Unknown scope '{other}'. Allowed: any, code, migration, frontend, infra, config"
        ),
    };
    Ok(scope)
}

impl RulePack {
    pub fn parse(body: &str) -> Result<Self> {
        let pack: RulePack = serde_yaml::from_str(body).context("Invalid YAML Structure")?;
        if pack.rules.is_empty() {
            anyhow::bail!("The pack contains no rules");
        }
        Ok(pack)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("Could Not Read Rule Pack: {}", path.display()))?;
        Self::parse(&body).with_context(|| format!("Invalid Rule Pack: {}", path.display()))
    }

    /// Converts to engine rules, validating each pattern so a broken user rule
    /// reports its own id instead of failing the whole run anonymously.
    pub fn into_defs(self) -> Result<Vec<RuleDef>> {
        let pack_name = self.name.clone();
        self.rules
            .into_iter()
            .map(|rule| {
                let id = rule.id.clone();
                convert(rule, &pack_name)
                    .with_context(|| format!("Rule '{id}' ({pack_name}) Is Invalid"))
            })
            .collect()
    }
}

fn convert(rule: YamlRule, pack: &str) -> Result<RuleDef> {
    regex::Regex::new(&rule.pattern).context("pattern Is Not A Valid Regex")?;
    if let Some(negate) = &rule.negate {
        regex::Regex::new(negate).context("negate Is Not A Valid Regex")?;
    }
    if rule.id.trim().is_empty() {
        anyhow::bail!("id must not be empty");
    }

    Ok(RuleDef {
        category: parse_category(&rule.category)?,
        scope: parse_scope(rule.scope.as_deref())?,
        severity: Severity::parse(&rule.severity),
        id: rule.id,
        title: rule.title,
        description: rule.description,
        impact: rule.impact,
        remediation: rule.remediation,
        pattern: rule.pattern,
        negate: rule.negate,
        languages: rule.languages,
        skip_tests: rule.skip_tests,
        cwe: rule.cwe,
        asvs: rule.asvs,
        policy: rule.policy,
        source: RuleSource::User(pack.to_string()),
    })
}

/// Default discovery location for project rule packs.
pub const USER_RULES_DIR: &str = ".deadbolt/rules";

/// Collects `<root>/.deadbolt/rules/*.yaml` plus any explicit paths.
pub fn discover_packs(root: &Path, explicit: &[String]) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();

    let directory = root.join(USER_RULES_DIR);
    if let Ok(entries) = std::fs::read_dir(&directory) {
        let mut found: Vec<std::path::PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        found.sort();
        paths.extend(found);
    }

    for candidate in explicit {
        let path = std::path::PathBuf::from(candidate);
        let path = if path.is_absolute() {
            path
        } else {
            root.join(path)
        };
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
name: internal
description: "Company-specific rules"
rules:
  - id: ACME-001
    title: "Internal service token in code"
    category: secrets
    severity: critical
    pattern: 'ACME_TOKEN\s*=\s*["''][^"'']{8,}'
    negate: 'os\.environ'
    cwe: 798
    policy: ["SEC-03, b.3.1/1"]
  - id: ACME-002
    title: "Legacy internal API call"
    category: api-contract
    severity: medium
    pattern: 'legacy_api\.'
    scope: code
    skip_tests: false
"#;

    #[test]
    fn parses_and_converts_a_pack() {
        let pack = RulePack::parse(SAMPLE).expect("the pack must be valid");
        assert_eq!(pack.name, "internal");
        let defs = pack.into_defs().expect("conversion must succeed");
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].id, "ACME-001");
        assert_eq!(defs[0].category, Category::Secrets);
        assert_eq!(defs[0].severity, Severity::Critical);
        assert_eq!(defs[0].source, RuleSource::User("internal".to_string()));
        assert!(
            defs[0].skip_tests,
            "test files are skipped unless told otherwise"
        );
        assert!(!defs[1].skip_tests);
        assert_eq!(defs[1].scope, Scope::Code);
    }

    #[test]
    fn rejects_an_invalid_regex_naming_the_rule() {
        let body = r#"
name: broken
rules:
  - id: BAD-001
    title: "x"
    category: secrets
    severity: high
    pattern: '([unclosed'
"#;
        let error = RulePack::parse(body)
            .unwrap()
            .into_defs()
            .expect_err("an invalid regex must be rejected");
        let message = format!("{error:#}");
        assert!(
            message.contains("BAD-001"),
            "the error must name the rule id: {message}"
        );
    }

    #[test]
    fn rejects_unknown_category_with_a_helpful_list() {
        let body = r#"
name: broken
rules:
  - id: BAD-002
    title: "x"
    category: nonsense
    severity: high
    pattern: 'x'
"#;
        let error = RulePack::parse(body)
            .unwrap()
            .into_defs()
            .expect_err("must be rejected");
        assert!(format!("{error:#}").contains("Unknown category"));
    }

    #[test]
    fn built_in_rules_convert_cleanly() {
        let defs: Vec<RuleDef> = super::super::catalog::RULES
            .iter()
            .map(RuleDef::from)
            .collect();
        assert!(defs.len() >= 40);
        assert!(defs.iter().all(|def| def.source == RuleSource::BuiltIn));
    }
}
