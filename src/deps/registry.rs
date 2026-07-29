use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};

use crate::model::PackageAudit;

const CONCURRENCY: usize = 8;
const MAX_LOOKUPS: usize = 160;

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("deadbolt/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .build()
        .context("Could Not Build The HTTP Client")
}

#[derive(Debug, Default, Clone)]
pub struct Metadata {
    pub last_release: Option<String>,
    pub maintainers: usize,
    pub deprecated: bool,
    pub license: String,
    pub install_scripts: bool,
}

/// Fills registry metadata in place; returns how many packages were enriched.
pub async fn enrich(audits: &mut [PackageAudit]) -> Result<usize> {
    let client = client()?;

    let targets: Vec<(usize, String, String)> = audits
        .iter()
        .enumerate()
        .filter(|(_, audit)| {
            audit
                .package
                .as_ref()
                .map(|p| p.direct || !audit.vulnerabilities.is_empty())
                .unwrap_or(false)
        })
        .take(MAX_LOOKUPS)
        .filter_map(|(index, audit)| {
            let package = audit.package.as_ref()?;
            Some((index, package.ecosystem.clone(), package.name.clone()))
        })
        .collect();

    if targets.is_empty() {
        return Ok(0);
    }

    let results = stream::iter(targets)
        .map(|(index, ecosystem, name)| {
            let client = client.clone();
            async move {
                let metadata = match ecosystem.as_str() {
                    "npm" => fetch_npm(&client, &name).await,
                    "PyPI" => fetch_pypi(&client, &name).await,
                    "crates.io" => fetch_crates(&client, &name).await,
                    _ => None,
                };
                (index, metadata)
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    let mut enriched = 0usize;
    for (index, metadata) in results {
        if let Some(metadata) = metadata {
            let audit = &mut audits[index];
            audit.last_release = metadata.last_release;
            audit.maintainers = metadata.maintainers;
            audit.deprecated = metadata.deprecated;
            audit.license = metadata.license;
            audit.install_scripts = metadata.install_scripts;
            audit.enriched = true;
            enriched += 1;
        }
    }
    Ok(enriched)
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Option<serde_json::Value> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<serde_json::Value>().await.ok()
}

async fn fetch_npm(client: &reqwest::Client, name: &str) -> Option<Metadata> {
    let url = format!("https://registry.npmjs.org/{}", encode(name));
    let value = fetch_json(client, &url).await?;

    let latest = value
        .get("dist-tags")
        .and_then(|tags| tags.get("latest"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let last_release = value
        .get("time")
        .and_then(|time| time.get(latest).or_else(|| time.get("modified")))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let maintainers = value
        .get("maintainers")
        .and_then(|v| v.as_array())
        .map(Vec::len)
        .unwrap_or(0);

    let latest_meta = value
        .get("versions")
        .and_then(|versions| versions.get(latest));

    let deprecated = latest_meta
        .and_then(|meta| meta.get("deprecated"))
        .is_some()
        || value.get("deprecated").is_some();

    let install_scripts = latest_meta
        .and_then(|meta| meta.get("scripts"))
        .and_then(|scripts| scripts.as_object())
        .map(|scripts| {
            ["preinstall", "install", "postinstall", "prepare"]
                .iter()
                .any(|hook| scripts.contains_key(*hook))
        })
        .unwrap_or(false);

    let license = value
        .get("license")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(Metadata {
        last_release,
        maintainers,
        deprecated,
        license,
        install_scripts,
    })
}

async fn fetch_pypi(client: &reqwest::Client, name: &str) -> Option<Metadata> {
    let url = format!("https://pypi.org/pypi/{}/json", encode(name));
    let value = fetch_json(client, &url).await?;
    let info = value.get("info")?;

    let license = info
        .get("license")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            info.get("classifiers")
                .and_then(|v| v.as_array())
                .and_then(|list| {
                    list.iter()
                        .filter_map(|c| c.as_str())
                        .find(|c| c.starts_with("License ::"))
                        .map(|c| c.rsplit(" :: ").next().unwrap_or(c).to_string())
                })
        })
        .unwrap_or_default();

    let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
    let last_release = value
        .get("releases")
        .and_then(|releases| releases.get(version))
        .and_then(|files| files.as_array())
        .and_then(|files| files.first())
        .and_then(|file| file.get("upload_time_iso_8601"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let deprecated = info
        .get("classifiers")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|c| c.as_str())
                .any(|c| c.contains("Inactive"))
        })
        .unwrap_or(false);

    Some(Metadata {
        last_release,
        maintainers: 0, // PyPI does not expose a maintainer list publicly
        deprecated,
        license,
        install_scripts: false,
    })
}

async fn fetch_crates(client: &reqwest::Client, name: &str) -> Option<Metadata> {
    let url = format!("https://crates.io/api/v1/crates/{}", encode(name));
    let value = fetch_json(client, &url).await?;
    let crate_info = value.get("crate")?;

    Some(Metadata {
        last_release: crate_info
            .get("updated_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        maintainers: 0,
        deprecated: false,
        license: value
            .get("versions")
            .and_then(|v| v.as_array())
            .and_then(|list| list.first())
            .and_then(|version| version.get("license"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        install_scripts: false,
    })
}

fn encode(name: &str) -> String {
    name.replace('/', "%2F")
}
