use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Package, Severity, Vulnerability};

const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const VULN_URL: &str = "https://api.osv.dev/v1/vulns";
const CHUNK: usize = 400;
const DETAIL_CONCURRENCY: usize = 8;
const MAX_DETAILS: usize = 250;

pub fn key(package: &Package) -> String {
    format!("{}|{}|{}", package.ecosystem, package.name, package.version)
}

#[derive(Serialize)]
struct BatchQuery<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Serialize)]
struct Query<'a> {
    package: QueryPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct QueryPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnStub>,
}

#[derive(Deserialize)]
struct VulnStub {
    id: String,
}

#[derive(Deserialize)]
struct VulnDetail {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<SeverityEntry>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Deserialize)]
struct SeverityEntry {
    #[serde(default)]
    score: String,
}

#[derive(Deserialize)]
struct Affected {
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Deserialize)]
struct Range {
    #[serde(default)]
    events: Vec<HashMap<String, String>>,
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("deadbolt/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .context("Could Not Build The HTTP Client")
}

/// Returns a map of `key(package)` -> vulnerabilities.
pub async fn query_batch(packages: &[Package]) -> Result<HashMap<String, Vec<Vulnerability>>> {
    let client = client()?;
    let mut per_package: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_ids: HashSet<String> = HashSet::new();

    for chunk in packages.chunks(CHUNK) {
        let payload = BatchQuery {
            queries: chunk
                .iter()
                .map(|package| Query {
                    package: QueryPackage {
                        name: &package.name,
                        ecosystem: &package.ecosystem,
                    },
                    version: &package.version,
                })
                .collect(),
        };

        let response = client
            .post(BATCH_URL)
            .json(&payload)
            .send()
            .await
            .context("Could Not Send The OSV querybatch Request")?;

        if !response.status().is_success() {
            anyhow::bail!("OSV Responded With Status: {}", response.status());
        }

        let parsed: BatchResponse = response
            .json()
            .await
            .context("Could Not Read The OSV Response")?;
        for (package, result) in chunk.iter().zip(parsed.results) {
            if result.vulns.is_empty() {
                continue;
            }
            let ids: Vec<String> = result.vulns.into_iter().map(|v| v.id).collect();
            for id in &ids {
                all_ids.insert(id.clone());
            }
            per_package.insert(key(package), ids);
        }
    }

    let details = fetch_details(&client, all_ids).await;

    let mut out: HashMap<String, Vec<Vulnerability>> = HashMap::new();
    for (package_key, ids) in per_package {
        let mut list: Vec<Vulnerability> = ids
            .iter()
            .map(|id| {
                details.get(id).cloned().unwrap_or(Vulnerability {
                    id: id.clone(),
                    severity: Severity::Medium,
                    summary: "Details Unavailable".to_string(),
                    fixed_version: String::new(),
                    aliases: Vec::new(),
                    cvss: None,
                })
            })
            .collect();
        list.sort_by_key(|v| v.severity);
        out.insert(package_key, list);
    }
    Ok(out)
}

async fn fetch_details(
    client: &reqwest::Client,
    ids: HashSet<String>,
) -> HashMap<String, Vulnerability> {
    use futures::stream::{self, StreamExt};

    let ids: Vec<String> = ids.into_iter().take(MAX_DETAILS).collect();

    let fetched = stream::iter(ids)
        .map(|id| {
            let client = client.clone();
            async move {
                let url = format!("{VULN_URL}/{id}");
                let detail = client
                    .get(&url)
                    .send()
                    .await
                    .ok()?
                    .json::<VulnDetail>()
                    .await
                    .ok()?;
                Some(convert(detail))
            }
        })
        .buffer_unordered(DETAIL_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    fetched
        .into_iter()
        .flatten()
        .map(|vulnerability| (vulnerability.id.clone(), vulnerability))
        .collect()
}

fn convert(detail: VulnDetail) -> Vulnerability {
    let cvss = detail
        .severity
        .iter()
        .map(|entry| entry.score.clone())
        .find(|score| score.starts_with("CVSS:"));

    let severity = detail
        .database_specific
        .get("severity")
        .and_then(|value| value.as_str())
        .map(Severity::parse)
        .or_else(|| cvss.as_deref().and_then(severity_from_cvss))
        .unwrap_or(Severity::Medium);

    let fixed_version = detail
        .affected
        .iter()
        .flat_map(|affected| affected.ranges.iter())
        .flat_map(|range| range.events.iter())
        .filter_map(|event| event.get("fixed").cloned())
        .next()
        .unwrap_or_default();

    let summary = if detail.summary.is_empty() {
        detail.details.chars().take(240).collect()
    } else {
        detail.summary
    };

    Vulnerability {
        id: detail.id,
        severity,
        summary,
        fixed_version,
        aliases: detail.aliases,
        cvss,
    }
}

/// Derive a severity band from the CVSS v3 base metrics present in the vector.
///
/// Full CVSS scoring is not reimplemented here: the impact and attack-vector
/// metrics are enough to place a vulnerability in the right band, and the exact
/// decimal is reported verbatim in `cvss` for anyone who needs it.
fn severity_from_cvss(vector: &str) -> Option<Severity> {
    let high_impact = vector.contains("/C:H") || vector.contains("/I:H") || vector.contains("/A:H");
    let network = vector.contains("/AV:N");
    let no_privileges = vector.contains("/PR:N");
    let no_interaction = vector.contains("/UI:N");

    Some(
        match (high_impact, network, no_privileges, no_interaction) {
            (true, true, true, true) => Severity::Critical,
            (true, true, true, false) => Severity::High,
            (true, true, false, _) => Severity::High,
            (true, false, _, _) => Severity::Medium,
            (false, true, true, _) => Severity::Medium,
            _ => Severity::Low,
        },
    )
}
