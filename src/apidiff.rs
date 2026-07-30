use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::model::{Category, Confidence, Evidence, Finding, Origin, Severity};

/// Filenames searched when no explicit path is configured.
const CANDIDATES: &[&str] = &[
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "docs/openapi.json",
    "api/openapi.json",
    "backend/openapi.json",
];

const METHODS: &[&str] = &["get", "put", "post", "delete", "patch", "head", "options"];
/// Guards against a `$ref` cycle in a hand-written document.
const MAX_REF_DEPTH: usize = 8;

pub struct SpecPair {
    pub path: String,
    pub base: Value,
    pub head: Value,
}

/// Locates candidate specs inside the inventory root.
pub fn discover(root: &Path, explicit: &[String]) -> Vec<String> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    CANDIDATES
        .iter()
        .filter(|candidate| root.join(candidate).is_file())
        .map(|candidate| candidate.to_string())
        .collect()
}

fn parse(body: &str) -> Result<Value> {
    serde_yaml::from_str(body).context("Could Not Read The OpenAPI Document (Not JSON Or YAML)")
}

/// Reads the spec as it exists at `base_ref`.
fn spec_at_ref(root: &Path, base_ref: &str, spec_path: &str) -> Result<Value> {
    let output = Command::new("git")
        .args(["show", &format!("{base_ref}:{spec_path}")])
        .current_dir(root)
        .output()
        .context("Could Not Run git show")?;

    if !output.status.success() {
        anyhow::bail!("{spec_path} does not exist in {base_ref} (it may be a new file)");
    }
    parse(&String::from_utf8_lossy(&output.stdout))
}

pub fn load_pair(root: &Path, base_ref: &str, spec_path: &str) -> Result<SpecPair> {
    let head_body = std::fs::read_to_string(root.join(spec_path))
        .with_context(|| format!("Could Not Read {spec_path}"))?;
    Ok(SpecPair {
        path: spec_path.to_string(),
        base: spec_at_ref(root, base_ref, spec_path)?,
        head: parse(&head_body)?,
    })
}

/// Resolves `$ref` pointers that live in the same document.
fn resolve<'a>(document: &'a Value, node: &'a Value, depth: usize) -> &'a Value {
    if depth >= MAX_REF_DEPTH {
        return node;
    }
    let reference = match node.get("$ref").and_then(Value::as_str) {
        Some(reference) => reference,
        None => return node,
    };
    let pointer = match reference.strip_prefix("#/") {
        Some(pointer) => pointer,
        None => return node, // external refs are out of scope
    };
    let mut current = document;
    for segment in pointer.split('/') {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        match current.get(&segment) {
            Some(next) => current = next,
            None => return node,
        }
    }
    resolve(document, current, depth + 1)
}

/// Flattens a schema into `field path -> type`, following `$ref` and `allOf`.
fn flatten(
    document: &Value,
    schema: &Value,
    prefix: &str,
    out: &mut BTreeMap<String, String>,
    depth: usize,
) {
    if depth >= MAX_REF_DEPTH {
        return;
    }
    let schema = resolve(document, schema, 0);

    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for part in all_of {
            flatten(document, part, prefix, out, depth + 1);
        }
    }

    if let Some(items) = schema.get("items") {
        flatten(document, items, &format!("{prefix}[]"), out, depth + 1);
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            let field = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            let resolved = resolve(document, property, 0);
            let kind = resolved
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("object")
                .to_string();
            let kind = match resolved.get("format").and_then(Value::as_str) {
                Some(format) => format!("{kind}/{format}"),
                None => kind,
            };
            out.insert(field.clone(), kind);
            flatten(document, property, &field, out, depth + 1);
        }
    }
}

fn required_fields(document: &Value, schema: &Value) -> BTreeSet<String> {
    let schema = resolve(document, schema, 0);
    let mut out: BTreeSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for part in all_of {
            out.extend(required_fields(document, part));
        }
    }
    out
}

fn enum_values(document: &Value, schema: &Value) -> BTreeSet<String> {
    resolve(document, schema, 0)
        .get("enum")
        .and_then(Value::as_array)
        .map(|list| list.iter().map(|value| value.to_string()).collect())
        .unwrap_or_default()
}

fn request_schema<'a>(document: &'a Value, operation: &'a Value) -> Option<&'a Value> {
    operation
        .get("requestBody")
        .map(|body| resolve(document, body, 0))?
        .get("content")?
        .as_object()?
        .values()
        .next()?
        .get("schema")
}

fn response_schema<'a>(
    document: &'a Value,
    operation: &'a Value,
    status: &str,
) -> Option<&'a Value> {
    operation
        .get("responses")?
        .get(status)
        .map(|response| resolve(document, response, 0))?
        .get("content")?
        .as_object()?
        .values()
        .next()?
        .get("schema")
}

fn success_statuses(operation: &Value) -> Vec<String> {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .map(|map| {
            map.keys()
                .filter(|status| status.starts_with('2'))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn operations(document: &Value) -> BTreeMap<String, &Value> {
    let mut out = BTreeMap::new();
    if let Some(paths) = document.get("paths").and_then(Value::as_object) {
        for (route, item) in paths {
            for method in METHODS {
                if let Some(operation) = item.get(method) {
                    out.insert(format!("{} {route}", method.to_uppercase()), operation);
                }
            }
        }
    }
    out
}

fn breaking(rule: &str, title: String, spec: &str, detail: String, remediation: String) -> Finding {
    Finding::builder(rule, Category::ApiContract, Severity::High)
        .title(title)
        .description(detail)
        .impact(
            "Older client versions on user devices send requests that match this contract. A mobile \
release that reached the store cannot be rolled back, so the breakage continues until users \
update.",
        )
        .remediation(remediation)
        .origin(Origin::Static)
        .confidence(Confidence::Confirmed)
        .evidence(Evidence::new(spec, None, String::new()))
        .cwe(1059)
        .policy("DEV-04, b.5")
        .build()
}

pub fn compare(pair: &SpecPair) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base_ops = operations(&pair.base);
    let head_ops = operations(&pair.head);
    let spec = pair.path.as_str();

    for name in base_ops.keys() {
        if !head_ops.contains_key(name) {
            findings.push(breaking(
                "DB-API-001",
                format!("Endpoint Removed Or Its Path Changed: {name}"),
                spec,
                format!("`{name}` exists in the base version but not in the new one."),
                "Keep the endpoint and mark it deprecated, or version the new path (`/v2/...`) \
and manage the transition with `min_supported_version`."
                    .to_string(),
            ));
        }
    }

    for (name, head_op) in &head_ops {
        let base_op = match base_ops.get(name) {
            Some(base_op) => *base_op,
            None => continue, // brand-new operation cannot break an old client
        };

        let base_params = parameters(&pair.base, base_op);
        let head_params = parameters(&pair.head, head_op);
        for (key, required) in &head_params {
            match base_params.get(key) {
                Some(false) if *required => findings.push(breaking(
                    "DB-API-002",
                    format!("Parameter Became Required: {name} — {key}"),
                    spec,
                    format!("`{key}` used to be optional and is now required."),
                    "Keep the parameter optional and give it a default; make it required only in \
a new version."
                        .to_string(),
                )),
                None if *required => findings.push(breaking(
                    "DB-API-002",
                    format!("New Required Parameter Added: {name} — {key}"),
                    spec,
                    format!("`{key}` is absent in the base version and is required; older clients do not send it."),
                    "Add the new parameter as optional with a default value.".to_string(),
                )),
                _ => {}
            }
        }
        for key in base_params.keys() {
            if !head_params.contains_key(key) {
                findings.push(
                    Finding::builder(
                        "DB-API-003",
                        Category::ApiContract,
                        Severity::Medium,
                    )
                    .title(format!("Parametr silinib: {name} — {key}"))
                    .description(format!("`{key}` is no longer accepted."))
                    .impact("Older clients keep sending this parameter and the server ignores it — a silent behaviour change.")
                    .remediation("Keep accepting the parameter, even if it is ignored, or version the endpoint.".to_string())
                    .origin(Origin::Static)
                    .confidence(Confidence::Confirmed)
                    .evidence(Evidence::new(spec, None, String::new()))
                    .policy("DEV-04, b.5")
                    .build(),
                );
            }
        }

        if let (Some(base_schema), Some(head_schema)) = (
            request_schema(&pair.base, base_op),
            request_schema(&pair.head, head_op),
        ) {
            let base_required = required_fields(&pair.base, base_schema);
            let head_required = required_fields(&pair.head, head_schema);
            for field in head_required.difference(&base_required) {
                findings.push(breaking(
                    "DB-API-004",
                    format!("New Required Field In The Request Body: {name} — {field}"),
                    spec,
                    format!("`{field}` became required; older clients do not send it."),
                    "Keep the field optional and apply a server-side default.".to_string(),
                ));
            }

            compare_fields(
                &pair.base,
                &pair.head,
                base_schema,
                head_schema,
                name,
                spec,
                "request",
                &mut findings,
            );
        }

        let base_statuses: BTreeSet<String> = success_statuses(base_op).into_iter().collect();
        let head_statuses: BTreeSet<String> = success_statuses(head_op).into_iter().collect();
        for status in base_statuses.difference(&head_statuses) {
            findings.push(breaking(
                "DB-API-005",
                format!("Response Code Removed: {name} — {status}"),
                spec,
                format!("The `{status}` response is no longer returned."),
                "Keep the old status code; client error handling depends on it.".to_string(),
            ));
        }

        for status in base_statuses.intersection(&head_statuses) {
            if let (Some(base_schema), Some(head_schema)) = (
                response_schema(&pair.base, base_op, status),
                response_schema(&pair.head, head_op, status),
            ) {
                compare_response_fields(
                    &pair.base,
                    &pair.head,
                    base_schema,
                    head_schema,
                    name,
                    spec,
                    &mut findings,
                );
            }
        }

        let base_security = base_op.get("security").and_then(Value::as_array);
        let head_security = head_op.get("security").and_then(Value::as_array);
        if base_security.map(Vec::is_empty).unwrap_or(true)
            && head_security.map(|list| !list.is_empty()).unwrap_or(false)
        {
            findings.push(breaking(
                "DB-API-006",
                format!("Authentication Requirement Added To An Endpoint: {name}"),
                spec,
                "This endpoint required no authentication in the base version.".to_string(),
                "The change is correct from a security standpoint but breaks older clients: \
coordinate it with `min_supported_version` and plan a transition period."
                    .to_string(),
            ));
        }
    }

    findings
}

/// `name -> required` for path/query/header parameters.
fn parameters(document: &Value, operation: &Value) -> BTreeMap<String, bool> {
    operation
        .get("parameters")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|parameter| resolve(document, parameter, 0))
                .filter_map(|parameter| {
                    let name = parameter.get("name")?.as_str()?;
                    let location = parameter
                        .get("in")
                        .and_then(Value::as_str)
                        .unwrap_or("query");
                    let required = parameter
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(location == "path");
                    Some((format!("{location}:{name}"), required))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Type changes and removed enum values in a request schema.
#[allow(clippy::too_many_arguments)]
fn compare_fields(
    base_doc: &Value,
    head_doc: &Value,
    base_schema: &Value,
    head_schema: &Value,
    operation: &str,
    spec: &str,
    label: &str,
    findings: &mut Vec<Finding>,
) {
    let mut base_fields = BTreeMap::new();
    let mut head_fields = BTreeMap::new();
    flatten(base_doc, base_schema, "", &mut base_fields, 0);
    flatten(head_doc, head_schema, "", &mut head_fields, 0);

    for (field, base_type) in &base_fields {
        if let Some(head_type) = head_fields.get(field) {
            if base_type != head_type {
                findings.push(breaking(
                    "DB-API-007",
                    format!("{label} Field Type Changed: {operation} — {field}"),
                    spec,
                    format!("`{field}`: `{base_type}` → `{head_type}`."),
                    "Keep the type; if a new type is needed, add a new field and deprecate the \
old one."
                        .to_string(),
                ));
            }
        }
    }

    let base_enums = enum_values(base_doc, base_schema);
    let head_enums = enum_values(head_doc, head_schema);
    for value in base_enums.difference(&head_enums) {
        findings.push(breaking(
            "DB-API-008",
            format!("Enum Value Removed: {operation} — {value}"),
            spec,
            format!("`{value}` is no longer accepted."),
            "Keep accepting the old value, or wait until clients have migrated.".to_string(),
        ));
    }
}

/// A field disappearing from a response is the most common silent breakage.
fn compare_response_fields(
    base_doc: &Value,
    head_doc: &Value,
    base_schema: &Value,
    head_schema: &Value,
    operation: &str,
    spec: &str,
    findings: &mut Vec<Finding>,
) {
    let mut base_fields = BTreeMap::new();
    let mut head_fields = BTreeMap::new();
    flatten(base_doc, base_schema, "", &mut base_fields, 0);
    flatten(head_doc, head_schema, "", &mut head_fields, 0);

    for (field, base_type) in &base_fields {
        match head_fields.get(field) {
            None => findings.push(breaking(
                "DB-API-009",
                format!("Field Removed From The Response: {operation} — {field}"),
                spec,
                format!("`{field}` is no longer returned."),
                "Keep the field, even with an empty value; the client expects it.".to_string(),
            )),
            Some(head_type) if head_type != base_type => findings.push(breaking(
                "DB-API-007",
                format!("Response Field Type Changed: {operation} — {field}"),
                spec,
                format!("`{field}`: `{base_type}` → `{head_type}`."),
                "Keep the type; add a new field if the shape has to change.".to_string(),
            )),
            _ => {}
        }
    }
}

/// Full check: locate specs, diff each against `base_ref`.
pub fn run(root: &Path, base_ref: &str, explicit: &[String]) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut warnings = Vec::new();

    let specs = discover(root, explicit);
    if specs.is_empty() {
        return (findings, warnings);
    }

    for spec in specs {
        match load_pair(root, base_ref, &spec) {
            Ok(pair) => findings.extend(compare(&pair)),
            Err(error) => warnings.push(format!("API Diff Skipped ({spec}): {error:#}")),
        }
    }
    (findings, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(base: &str, head: &str) -> SpecPair {
        SpecPair {
            path: "openapi.json".to_string(),
            base: parse(base).unwrap(),
            head: parse(head).unwrap(),
        }
    }

    fn rules(findings: &[Finding]) -> Vec<String> {
        let mut out: Vec<String> = findings.iter().map(|f| f.rule.clone()).collect();
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn detects_removed_endpoint() {
        let findings = compare(&pair(
            r#"{"paths":{"/a":{"get":{"responses":{"200":{}}}},"/b":{"get":{"responses":{"200":{}}}}}}"#,
            r#"{"paths":{"/a":{"get":{"responses":{"200":{}}}}}}"#,
        ));
        assert!(rules(&findings).contains(&"DB-API-001".to_string()));
    }

    #[test]
    fn detects_parameter_becoming_required() {
        let findings = compare(&pair(
            r#"{"paths":{"/a":{"get":{"parameters":[{"name":"q","in":"query","required":false}],"responses":{"200":{}}}}}}"#,
            r#"{"paths":{"/a":{"get":{"parameters":[{"name":"q","in":"query","required":true}],"responses":{"200":{}}}}}}"#,
        ));
        assert!(rules(&findings).contains(&"DB-API-002".to_string()));
    }

    #[test]
    fn detects_removed_response_field_through_a_ref() {
        let base = r##"{
          "paths":{"/u":{"get":{"responses":{"200":{"content":{"application/json":
            {"schema":{"$ref":"#/components/schemas/User"}}}}}}}},
          "components":{"schemas":{"User":{"type":"object","properties":
            {"id":{"type":"integer"},"email":{"type":"string"}}}}}}"##;
        let head = r##"{
          "paths":{"/u":{"get":{"responses":{"200":{"content":{"application/json":
            {"schema":{"$ref":"#/components/schemas/User"}}}}}}}},
          "components":{"schemas":{"User":{"type":"object","properties":
            {"id":{"type":"integer"}}}}}}"##;
        let findings = compare(&pair(base, head));
        assert!(rules(&findings).contains(&"DB-API-009".to_string()));
    }

    #[test]
    fn detects_type_change() {
        let base = r#"{"paths":{"/u":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"integer"}}}}}}}}}}}"#;
        let head = r#"{"paths":{"/u":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"string"}}}}}}}}}}}"#;
        assert!(rules(&compare(&pair(base, head))).contains(&"DB-API-007".to_string()));
    }

    #[test]
    fn detects_new_required_body_field() {
        let base = r#"{"paths":{"/u":{"post":{"requestBody":{"content":{"application/json":
          {"schema":{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}}}},
          "responses":{"200":{}}}}}}"#;
        let head = r#"{"paths":{"/u":{"post":{"requestBody":{"content":{"application/json":
          {"schema":{"type":"object","required":["a","b"],"properties":{"a":{"type":"string"},"b":{"type":"string"}}}}}},
          "responses":{"200":{}}}}}}"#;
        assert!(rules(&compare(&pair(base, head))).contains(&"DB-API-004".to_string()));
    }

    #[test]
    fn detects_added_security_requirement() {
        let findings = compare(&pair(
            r#"{"paths":{"/a":{"get":{"responses":{"200":{}}}}}}"#,
            r#"{"paths":{"/a":{"get":{"security":[{"bearer":[]}],"responses":{"200":{}}}}}}"#,
        ));
        assert!(rules(&findings).contains(&"DB-API-006".to_string()));
    }

    #[test]
    fn a_new_endpoint_and_a_new_optional_field_are_not_breaking() {
        let base = r#"{"paths":{"/u":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"integer"}}}}}}}}}}}"#;
        let head = r#"{"paths":{"/u":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"integer"},"extra":{"type":"string"}}}}}}}}},"/b":{"post":{"responses":{"201":{}}}}}}"#;
        let findings = compare(&pair(base, head));
        assert!(
            findings.is_empty(),
            "a backward-compatible change must not produce a finding: {:?}",
            rules(&findings)
        );
    }

    #[test]
    fn survives_a_ref_cycle() {
        let cyclic = r##"{"paths":{"/a":{"get":{"responses":{"200":{"content":{"application/json":
          {"schema":{"$ref":"#/components/schemas/Node"}}}}}}}},
          "components":{"schemas":{"Node":{"type":"object","properties":
            {"child":{"$ref":"#/components/schemas/Node"}}}}}}"##;
        let _ = compare(&pair(cyclic, cyclic));
    }
}
