use std::collections::BTreeMap;

use regex::Regex;

use crate::discover::Inventory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub method: String,
    pub route: String,
    pub file: String,
    pub line: u32,
    /// Authorization markers found on or just after the route declaration.
    pub requires: Vec<String>,
    /// True when the handler takes an id-shaped parameter, which is where
    /// object-level authorization matters most.
    pub takes_identifier: bool,
}

impl Endpoint {
    pub fn unprotected(&self) -> bool {
        self.requires.is_empty()
    }

    /// The combination that produces IDOR: an object id and no ownership check.
    pub fn idor_candidate(&self) -> bool {
        self.takes_identifier && self.unprotected()
    }
}

struct Patterns {
    route: Vec<Regex>,
    auth: Vec<(&'static str, Regex)>,
    identifier: Regex,
}

fn patterns() -> Option<Patterns> {
    Some(Patterns {
        route: vec![
            Regex::new(r#"(?i)@\w+\.(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']"#).ok()?,
            Regex::new(r#"(?i)\b(?:app|router|server)\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]"#).ok()?,
            Regex::new(r#"(?i)@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']"#).ok()?,
            Regex::new(r#"(?i)\b\w+\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*["`]([^"`]+)["`]"#).ok()?,
        ],
        auth: vec![
            ("Depends", Regex::new(r"Depends\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)").ok()?),
            ("decorator", Regex::new(r"@(login_required|permission_required|requires_auth|authenticated|admin_required|jwt_required)").ok()?),
            ("permission_classes", Regex::new(r"permission_classes\s*=\s*\[([^\]]+)\]").ok()?),
            ("guard", Regex::new(r"(?i)@(UseGuards|PreAuthorize|Secured|RolesAllowed)\s*\(([^)]*)").ok()?),
            ("middleware", Regex::new(r"(?i)\b(authMiddleware|requireAuth|ensureAuth|verifyToken|isAuthenticated)\b").ok()?),
        ],
        identifier: Regex::new(r"(?i)[<{:]\s*(?:int\s*:\s*)?\w*(?:id|pk|uuid|slug)\w*\s*[>}]|:\w*(?:id|pk)\w*\b").ok()?,
    })
}

fn is_route_line(patterns: &Patterns, line: &str) -> bool {
    patterns.route.iter().any(|pattern| pattern.is_match(line))
}

/// Authorization markers belonging to *this* route.
///
/// The window stops at the neighbouring route declaration: without that bound a
/// `Depends(...)` on the route above silently marks the route below as
/// protected, which is precisely the mistake this matrix exists to reveal.
fn markers(patterns: &Patterns, lines: &[&str], index: usize) -> Vec<String> {
    let mut window: Vec<&str> = vec![lines[index]];

    for offset in 1..=4 {
        let Some(position) = index.checked_sub(offset) else {
            break;
        };
        let line = lines[position];
        if is_route_line(patterns, line) || line.trim().is_empty() {
            break;
        }
        window.push(line);
    }

    for line in lines
        .iter()
        .take((index + 7).min(lines.len()))
        .skip(index + 1)
        .copied()
    {
        if is_route_line(patterns, line) || line.trim().is_empty() {
            break;
        }
        window.push(line);
    }

    let mut found: Vec<String> = Vec::new();
    for line in window {
        for (label, pattern) in &patterns.auth {
            if let Some(captures) = pattern.captures(line) {
                let detail = captures
                    .get(2)
                    .or_else(|| captures.get(1))
                    .map(|m| m.as_str().trim().to_string())
                    .filter(|value| !value.is_empty());
                let entry = match detail {
                    Some(detail) => {
                        format!("{label}({})", detail.chars().take(40).collect::<String>())
                    }
                    None => label.to_string(),
                };
                if !found.contains(&entry) {
                    found.push(entry);
                }
            }
        }
    }
    found
}

pub fn extract(inventory: &Inventory) -> Vec<Endpoint> {
    let patterns = match patterns() {
        Some(patterns) => patterns,
        None => return Vec::new(),
    };

    let mut endpoints = Vec::new();
    for file in &inventory.files {
        if file.is_test() || !crate::scan::is_code_language(file.language) {
            continue;
        }
        let lines: Vec<&str> = file.content.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            for pattern in &patterns.route {
                if let Some(captures) = pattern.captures(line) {
                    let method = captures
                        .get(1)
                        .map(|m| m.as_str().to_uppercase())
                        .unwrap_or_default();
                    let route = captures
                        .get(2)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                    if route.is_empty() {
                        continue;
                    }
                    endpoints.push(Endpoint {
                        method,
                        takes_identifier: patterns.identifier.is_match(&route),
                        route,
                        file: file.rel_path.clone(),
                        line: index as u32 + 1,
                        requires: markers(&patterns, &lines, index),
                    });
                    break;
                }
            }
        }
    }

    endpoints.sort_by(|a, b| {
        a.route
            .cmp(&b.route)
            .then(a.method.cmp(&b.method))
            .then(a.file.cmp(&b.file))
    });
    endpoints.dedup_by(|a, b| a.method == b.method && a.route == b.route && a.file == b.file);
    endpoints
}

pub struct Summary {
    pub total: usize,
    pub unprotected: usize,
    pub idor_candidates: usize,
}

pub fn summarize(endpoints: &[Endpoint]) -> Summary {
    Summary {
        total: endpoints.len(),
        unprotected: endpoints.iter().filter(|e| e.unprotected()).count(),
        idor_candidates: endpoints.iter().filter(|e| e.idor_candidate()).count(),
    }
}

pub fn render_markdown(endpoints: &[Endpoint]) -> String {
    if endpoints.is_empty() {
        return String::new();
    }
    let summary = summarize(endpoints);

    let mut out = String::from("## Authorisation Matrix\n\n");
    out.push_str(&format!(
        "{} endpoints detected · **{} with no stated requirement** · **{} accept an object \
identifier and state no requirement** (IDOR suspects).\n\n",
        summary.total, summary.unprotected, summary.idor_candidates
    ));
    out.push_str(
        "This table is a review aid, not a complete inventory: routes registered dynamically do \
not appear in pattern-based extraction.\n\n",
    );
    out.push_str("| | Method | Route | Requirement | Location |\n|---|---|---|---|---|\n");

    for endpoint in endpoints {
        let flag = if endpoint.idor_candidate() {
            "⚠️"
        } else if endpoint.unprotected() {
            "❗"
        } else {
            "✓"
        };
        out.push_str(&format!(
            "| {flag} | `{}` | `{}` | {} | `{}:{}` |\n",
            endpoint.method,
            endpoint.route,
            if endpoint.requires.is_empty() {
                "**—**".to_string()
            } else {
                endpoint.requires.join(", ")
            },
            endpoint.file,
            endpoint.line
        ));
    }

    out.push_str(
        "\n:warning: Accepts An Identifier And States No Requirement · :exclamation: No Requirement · :white_check_mark: Requirement Present\n\n",
    );
    out
}

/// Groups endpoints by the requirement set, which makes an outlier obvious.
#[allow(dead_code)] // used by report consumers of the JSON artifact
pub fn by_requirement(endpoints: &[Endpoint]) -> BTreeMap<String, Vec<&Endpoint>> {
    let mut grouped: BTreeMap<String, Vec<&Endpoint>> = BTreeMap::new();
    for endpoint in endpoints {
        let key = if endpoint.requires.is_empty() {
            "—".to_string()
        } else {
            endpoint.requires.join(", ")
        };
        grouped.entry(key).or_default().push(endpoint);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::SourceFile;
    use std::path::PathBuf;

    fn inventory(name: &str, body: &str) -> Inventory {
        Inventory {
            root: PathBuf::from("/tmp"),
            files: vec![SourceFile {
                rel_path: name.to_string(),
                abs_path: PathBuf::from(name),
                language: if name.ends_with(".py") {
                    "Python"
                } else {
                    "TypeScript"
                },
                size: body.len() as u64,
                lines: body.lines().count(),
                content: body.to_string(),
                truncated: false,
            }],
            stack: Default::default(),
            manifests: Vec::new(),
            skipped_large: 0,
            skipped_large_names: Vec::new(),
        }
    }

    #[test]
    fn extracts_fastapi_routes_with_and_without_dependencies() {
        let body = "\
@router.get(\"/orders/{order_id}\")
async def get_order(order_id: int, user=Depends(current_user)):
    pass

@router.post(\"/orders/{order_id}/refund\")
async def refund(order_id: int):
    pass
";
        let endpoints = extract(&inventory("app/api.py", body));
        assert_eq!(endpoints.len(), 2);

        let refund = endpoints
            .iter()
            .find(|endpoint| endpoint.route.ends_with("refund"))
            .unwrap();
        assert!(refund.unprotected());
        assert!(refund.idor_candidate());

        let get = endpoints
            .iter()
            .find(|endpoint| endpoint.method == "GET")
            .unwrap();
        assert!(!get.unprotected());
        assert!(get
            .requires
            .iter()
            .any(|value| value.contains("current_user")));
    }

    #[test]
    fn recognises_express_routes_and_middleware() {
        let body =
            "router.get('/users/:id', requireAuth, handler);\nrouter.get('/health', handler);\n";
        let endpoints = extract(&inventory("app/routes.ts", body));
        assert_eq!(endpoints.len(), 2);

        let user = endpoints.iter().find(|e| e.route.contains(":id")).unwrap();
        assert!(!user.unprotected());
        assert!(user.takes_identifier);

        let health = endpoints.iter().find(|e| e.route == "/health").unwrap();
        assert!(health.unprotected());
        assert!(!health.idor_candidate());
    }

    #[test]
    fn summary_counts_the_two_risk_classes_separately() {
        let body = "\
@app.get(\"/a/{id}\")
def a(id: int):
    pass

@app.get(\"/b\")
def b():
    pass

@app.get(\"/c/{id}\")
def c(id: int, user=Depends(auth)):
    pass
";
        let endpoints = extract(&inventory("app/api.py", body));
        let summary = summarize(&endpoints);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.unprotected, 2);
        assert_eq!(summary.idor_candidates, 1);
    }

    #[test]
    fn markdown_marks_idor_candidates() {
        let body = "@app.get(\"/x/{id}\")\ndef x(id: int):\n    pass\n";
        let markdown = render_markdown(&extract(&inventory("app/api.py", body)));
        assert!(markdown.contains("⚠️"));
        assert!(markdown.contains("Authorisation Matrix"));
    }

    #[test]
    fn an_empty_project_produces_no_section() {
        assert!(render_markdown(&[]).is_empty());
    }

    #[test]
    fn test_files_are_excluded() {
        let body = "@app.get(\"/x\")\ndef x():\n    pass\n";
        assert!(extract(&inventory("tests/test_api.py", body)).is_empty());
    }
}
