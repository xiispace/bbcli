//! Offline API catalog over the embedded OpenAPI spec.
//!
//! Embeds the same spec the MCP `search_api` tool serves (vendored from
//! `backend/api/mcp/gen/openapi.yaml`, generated from proto by buf — see
//! `vendor/bytebase/SOURCE.md`), so agents can discover services, methods,
//! and request schemas without any server round trip. Field names here are
//! protojson (camelCase) — exactly what `bbcli api` expects in `--args`.
//!
//! Field descriptions are printed in full, not truncated: proto3 has no
//! `required`, so the resource-name formats an agent must not guess
//! ("Format: instances/{instance}/databases/{database}") live in the second
//! and later lines of a field's description.

use anyhow::{anyhow, bail, Result};
use serde_yaml::Value as Yaml;

const OPENAPI_YAML: &str = include_str!("../vendor/bytebase/openapi.yaml");

/// Bytebase commit the vendored catalog was generated from; printed so an
/// agent can tell which API surface these fields describe.
pub const CATALOG_COMMIT: &str = include_str!("../vendor/bytebase/COMMIT");

/// Runs one of the four search modes (priority: operation > schema > service
/// > list-all) and prints the result.
pub fn run(
    operation_id: Option<String>,
    schema: Option<String>,
    service: Option<String>,
) -> Result<()> {
    let doc: Yaml = serde_yaml::from_str(OPENAPI_YAML)?;
    let paths = doc
        .get("paths")
        .and_then(Yaml::as_mapping)
        .ok_or_else(|| anyhow!("embedded OpenAPI spec has no paths"))?;

    if let Some(op) = operation_id {
        print_operation(&doc, paths, &op)?;
    } else if let Some(schema) = schema {
        print_schema(&doc, &schema)?;
    } else if let Some(service) = service {
        print_service(paths, &service)?;
    } else {
        print_services(paths);
    }
    Ok(())
}

/// Lists every service with its method count.
fn print_services(paths: &serde_yaml::Mapping) {
    let mut services: Vec<(String, usize)> = Vec::new();
    for (k, _) in paths {
        let Some(path) = k.as_str() else { continue };
        let Some(name) = service_of(path) else {
            continue;
        };
        match services.last_mut() {
            Some((last, n)) if *last == name => *n += 1,
            _ => services.push((name, 1)),
        }
    }
    println!(
        "Services ({} total). Browse one with: bbcli search --service <name>",
        services.len()
    );
    println!("Catalog: bytebase {CATALOG_COMMIT}\n");
    for (name, n) in services {
        println!("  {name} ({n} methods)");
    }
}

/// Lists the methods of one service.
fn print_service(paths: &serde_yaml::Mapping, service: &str) -> Result<()> {
    let prefix = format!("/bytebase.v1.{service}/");
    let mut rows = Vec::new();
    for (k, v) in paths {
        let Some(path) = k.as_str() else { continue };
        let Some(method) = path.strip_prefix(&prefix) else {
            continue;
        };
        let Some(post) = v.get("post") else { continue };
        let summary = post.get("summary").and_then(Yaml::as_str).unwrap_or("");
        let desc = first_line(desc_of(post));
        rows.push((method.to_string(), summary.to_string(), desc));
    }
    if rows.is_empty() {
        bail!("no service {service:?}; list all with: bbcli search");
    }
    println!(
        "{service} ({} methods). Call with: bbcli api {service}/<Method>",
        rows.len()
    );
    for (method, summary, desc) in rows {
        if desc.is_empty() {
            println!("  {method} — {summary}");
        } else {
            println!("  {method} — {summary}: {desc}");
        }
    }
    Ok(())
}

/// Prints one operation: description plus request/response field tables.
/// Accepts `SQLService/Query`, `SQLService.Query`, or the fully qualified
/// `bytebase.v1.SQLService/Query` form.
fn print_operation(doc: &Yaml, paths: &serde_yaml::Mapping, operation: &str) -> Result<()> {
    let (service, method) = crate::client::parse_method(operation)?;
    let path_name = format!("/bytebase.v1.{service}/{method}");
    let post = paths
        .get(path_name.as_str())
        .and_then(|v| v.get("post"))
        .ok_or_else(|| {
            anyhow!(
                "no operation {operation:?}; browse services with: bbcli search --service <name>"
            )
        })?;

    println!("POST {path_name}\n");
    if let Some(desc) = desc_of(post) {
        println!("{desc}\n");
    }

    let request_ref = post.get("requestBody").and_then(json_ref);
    let response_ref = post
        .get("responses")
        .and_then(|v| v.get("200"))
        .and_then(json_ref);

    if let Some(schema) = request_ref.and_then(|r| resolve_schema(doc, r)) {
        println!("Request fields (pass as --args, camelCase):");
        print_fields(schema);
        println!();
    }
    if let Some(r) = response_ref {
        let name = r.rsplit('/').next().unwrap_or(r);
        println!("Response: {name} (fields: bbcli search --schema {name})");
    }
    Ok(())
}

/// Prints the definition of one message type (short or fully qualified name).
fn print_schema(doc: &Yaml, name: &str) -> Result<()> {
    let schemas = doc
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(Yaml::as_mapping)
        .ok_or_else(|| anyhow!("spec has no components.schemas"))?;
    let full = format!("bytebase.v1.{name}");
    let entry = schemas
        .get(name)
        .or_else(|| schemas.get(full.as_str()))
        .ok_or_else(|| anyhow!("no schema named {name:?}"))?;

    println!("{name}\n");
    print_fields(entry);
    Ok(())
}

/// Prints one line per field, followed by the rest of a multi-line
/// description indented underneath. Continuation lines are where proto puts
/// resource-name formats and constraints ("Format: instances/{instance}/..."),
/// so they are never dropped — an agent told not to guess field values needs
/// them to build a valid request.
fn print_fields(schema: &Yaml) {
    let Some(props) = schema.get("properties").and_then(Yaml::as_mapping) else {
        println!("  (no fields)");
        return;
    };
    // proto3 has no `required`; a schema-level list only appears on the few
    // messages where it is set, so print it when present rather than implying
    // everything is optional.
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Yaml::as_sequence)
        .map(|s| s.iter().filter_map(Yaml::as_str).collect())
        .unwrap_or_default();
    for (k, v) in props {
        let field = k.as_str().unwrap_or("?");
        let ty = field_type(v);
        let req = if required.contains(&field) {
            " (required)"
        } else {
            ""
        };
        let mut lines = desc_lines(desc_of(v));
        let head = if lines.is_empty() {
            String::new()
        } else {
            lines.remove(0)
        };
        if head.is_empty() {
            println!("  {field}: {ty}{req}");
        } else {
            println!("  {field}: {ty}{req} — {head}");
        }
        for line in lines {
            println!("      {line}");
        }
    }
}

/// Human-readable type for a property: $ref tail, array<item>, scalar, enum.
///
/// A proto3 `optional` field is emitted as `type: [string, "null"]`, so the
/// type node is a sequence rather than a scalar. Reading it as a scalar
/// silently reports those fields as `object` — and an agent that believes it
/// then sends `{}` where the API wants a string.
fn field_type(v: &Yaml) -> String {
    if let Some(r) = v.get("$ref").and_then(Yaml::as_str) {
        return r.rsplit('/').next().unwrap_or(r).to_string();
    }
    let node = v.get("type");
    let nullable = node
        .and_then(Yaml::as_sequence)
        .is_some_and(|s| s.iter().any(|t| t.as_str() == Some("null")));
    let ty = node
        .and_then(Yaml::as_str)
        .or_else(|| {
            // Nullable form: take the one non-"null" entry.
            node.and_then(Yaml::as_sequence)?
                .iter()
                .filter_map(Yaml::as_str)
                .find(|t| *t != "null")
        })
        .unwrap_or("object");
    let rendered = render_type(v, ty);
    if nullable {
        format!("{rendered} (optional)")
    } else {
        rendered
    }
}

/// Formats a resolved scalar/array/enum type name.
fn render_type(v: &Yaml, ty: &str) -> String {
    match ty {
        "array" => {
            let item = v
                .get("items")
                .map(field_type)
                .unwrap_or_else(|| "any".into());
            format!("array<{item}>")
        }
        "string" => {
            if let Some(en) = v.get("enum").and_then(Yaml::as_sequence) {
                let vals: Vec<&str> = en.iter().filter_map(Yaml::as_str).take(12).collect();
                let more = if en.len() > 12 { " | ..." } else { "" };
                return format!("enum {}{}", vals.join(" | "), more);
            }
            "string".into()
        }
        other => other.to_string(),
    }
}

fn resolve_schema<'a>(doc: &'a Yaml, reference: &str) -> Option<&'a Yaml> {
    let name = reference.rsplit('/').next()?;
    doc.get("components")?.get("schemas")?.get(name)
}

/// `$ref` of a JSON body schema: content → application/json → schema → $ref.
fn json_ref(v: &Yaml) -> Option<&str> {
    v.get("content")?
        .get("application/json")?
        .get("schema")?
        .get("$ref")?
        .as_str()
}

fn service_of(path: &str) -> Option<String> {
    // "/bytebase.v1.SQLService/Query" -> "SQLService"
    let rest = path.strip_prefix("/bytebase.v1.")?;
    let service = rest.split('/').next()?;
    if service.is_empty() {
        None
    } else {
        Some(service.to_string())
    }
}

fn desc_of(v: &Yaml) -> Option<&str> {
    v.get("description").and_then(Yaml::as_str)
}

/// First non-empty line of a (possibly multi-line) description — for the
/// one-line-per-method listings, where the full text would drown the list.
fn first_line(desc: Option<&str>) -> String {
    desc.and_then(|d| d.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Every non-empty line of a description, trimmed. proto comments arrive as
/// a block scalar whose continuation lines carry a leading space; trimming
/// each line normalizes that without losing any of the text.
fn desc_lines(desc: Option<&str>) -> Vec<String> {
    desc.map(|d| {
        d.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_spec_lists_all_services() {
        let doc: Yaml = serde_yaml::from_str(OPENAPI_YAML).unwrap();
        let paths = doc.get("paths").and_then(Yaml::as_mapping).unwrap();
        let services: Vec<String> = paths
            .keys()
            .filter_map(|k| k.as_str())
            .filter_map(service_of)
            .collect();
        assert!(
            services.len() > 30,
            "expected 30+ services, got {}",
            services.len()
        );
        assert!(services.contains(&"SQLService".to_string()));
    }

    /// Resource-name formats live on the second line of a proto comment; a
    /// first-line-only render drops exactly what an agent must not guess.
    #[test]
    fn field_description_keeps_continuation_lines() {
        let doc: Yaml = serde_yaml::from_str(OPENAPI_YAML).unwrap();
        let name = doc
            .get("components")
            .unwrap()
            .get("schemas")
            .unwrap()
            .get("bytebase.v1.QueryRequest")
            .unwrap()
            .get("properties")
            .unwrap()
            .get("name")
            .unwrap();
        let lines = desc_lines(desc_of(name));
        assert!(
            lines.len() > 1,
            "expected a multi-line description: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("Format: instances/")),
            "resource-name format line missing: {lines:?}"
        );
    }

    /// proto3 `optional` renders as `type: [string, "null"]`; reading that
    /// node as a scalar reports the field as `object`.
    #[test]
    fn nullable_field_reports_its_real_type() {
        let doc: Yaml = serde_yaml::from_str(OPENAPI_YAML).unwrap();
        let schema = doc
            .get("components")
            .unwrap()
            .get("schemas")
            .unwrap()
            .get("bytebase.v1.QueryRequest")
            .unwrap()
            .get("properties")
            .unwrap()
            .get("schema")
            .unwrap();
        assert_eq!(field_type(schema), "string (optional)");
    }

    #[test]
    fn catalog_commit_is_a_bare_sha() {
        assert_eq!(CATALOG_COMMIT.len(), 40, "COMMIT: {CATALOG_COMMIT:?}");
        assert!(CATALOG_COMMIT.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn query_request_schema_resolves() {
        let doc: Yaml = serde_yaml::from_str(OPENAPI_YAML).unwrap();
        let schemas = doc.get("components").unwrap().get("schemas").unwrap();
        let qr = schemas
            .get("bytebase.v1.QueryRequest")
            .expect("QueryRequest schema");
        let props = qr.get("properties").and_then(Yaml::as_mapping).unwrap();
        assert!(props.len() >= 3, "QueryRequest fields: {props:?}");
        assert!(props.keys().any(|k| k.as_str() == Some("name")));
        assert!(props.keys().any(|k| k.as_str() == Some("statement")));
    }
}
