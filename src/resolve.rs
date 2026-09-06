//! Database resolution: a short name an agent can type into the
//! `instances/{i}/databases/{d}` resource name every v1 method wants, plus
//! the data source id to read from.
//!
//! Mirrors upstream's `backend/api/mcp/tool_resolve.go` so the vendored task
//! guides read without translation. The one rule that matters most is what it
//! refuses to do: an input matching more than one database is an error listing
//! every candidate, never a pick. A wrong guess here runs a statement against
//! a database nobody named, and the agent cannot tell from the output that it
//! happened.

use std::fmt::Display;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::client::ApiClient;

/// A database narrowed to exactly one, with everything the callers need to
/// build their own requests.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// `instances/{instance}/databases/{database}`.
    pub name: String,
    /// `projects/{project}` — the parent for sheets, plans and issues.
    pub project: String,
    /// Engine name, e.g. `POSTGRES`. Decides whether `--schema` means anything.
    pub engine: String,
    /// READ_ONLY preferred over ADMIN. Empty when the instance declares
    /// neither, in which case the server resolves the data source itself.
    pub data_source_id: String,
}

/// One database in a `ListDatabases` / `GetDatabase` response. Unknown fields
/// are ignored, so a newer server does not break decoding.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub instance_resource: InstanceResource,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InstanceResource {
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub data_sources: Vec<DataSource>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DataSource {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub r#type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListDatabasesResponse {
    #[serde(default)]
    databases: Vec<DatabaseEntry>,
    #[serde(default)]
    next_page_token: String,
}

/// A refusal bbcli itself raised, as opposed to one the server returned.
///
/// The code is UPPER_SNAKE and named after upstream's; Connect codes from the
/// server stay lowercase. That case difference is how an agent tells who
/// refused — bbcli's own resolution, or Bytebase — without parsing prose.
pub fn tool_error(code: &str, msg: impl Display) -> anyhow::Error {
    anyhow::anyhow!("[{code}] {msg}")
}

/// The workspace parent for a listing. The catalog documents `-` as the
/// current workspace, which is the only one a single credential can see.
const WORKSPACE_PARENT: &str = "workspaces/-";

/// Resolves `database` to exactly one database.
///
/// A full resource name is taken at its word (one `GetDatabase`); anything
/// else is listed and matched in tiers. `instance`/`project` narrow the
/// listing only — they are ignored for a full name, which is already unique.
pub async fn resolve(
    client: &ApiClient,
    database: &str,
    instance: Option<&str>,
    project: Option<&str>,
) -> Result<Resolved> {
    let resolved = if is_full_database_name(database) {
        // The CLI has to accept the names its own `api` output produces;
        // re-listing to rediscover a name the agent already holds would be a
        // wasted round trip and could fail to match its own input.
        let resp = client
            .call_announced("DatabaseService/GetDatabase", &json!({"name": database}))
            .await
            .context("fetching the database by resource name")?;
        let entry: DatabaseEntry =
            serde_json::from_value(resp).context("failed to parse the GetDatabase response")?;
        from_entry(&entry)
    } else {
        let filter = build_database_filter(database, instance, project);
        let entries = list_databases(client, &filter).await?;
        let matches = match_databases(&entries, database);
        match matches.len() {
            0 => return Err(not_found_error(database, instance, project)),
            1 => from_entry(matches[0]),
            _ => return Err(ambiguous_error(database, &matches)),
        }
    };

    eprintln!(
        "resolved {database:?} -> {} ({}, {}; {})",
        resolved.name,
        resolved.engine,
        resolved.project,
        match resolved.data_source_id.as_str() {
            // An empty id is not a failure: `SQLService/Query` resolves the
            // data source itself. Say which happened, so an agent handing the
            // id to `api` knows there is none to hand.
            "" => "data source chosen server-side".to_string(),
            id => format!("data source {id}"),
        }
    );
    Ok(resolved)
}

/// Pages through `ListDatabases` until the server stops handing out tokens.
async fn list_databases(client: &ApiClient, filter: &str) -> Result<Vec<DatabaseEntry>> {
    let mut all = Vec::new();
    let mut page_token = String::new();
    loop {
        let mut args = json!({
            "parent": WORKSPACE_PARENT,
            "pageSize": 1000,
            "filter": filter,
        });
        if !page_token.is_empty() {
            args["pageToken"] = json!(page_token);
        }
        let resp = client
            .call_announced("DatabaseService/ListDatabases", &args)
            .await
            .context("listing databases")?;
        let page: ListDatabasesResponse =
            serde_json::from_value(resp).context("failed to parse the ListDatabases response")?;
        all.extend(page.databases);
        if page.next_page_token.is_empty() {
            return Ok(all);
        }
        page_token = page.next_page_token;
    }
}

fn from_entry(entry: &DatabaseEntry) -> Resolved {
    Resolved {
        name: entry.name.clone(),
        project: entry.project.clone(),
        engine: entry.instance_resource.engine.clone(),
        data_source_id: select_data_source(&entry.instance_resource.data_sources),
    }
}

/// True for exactly `instances/{i}/databases/{d}` with both ids non-empty.
///
/// Anything looser (`instances/a`, `projects/p`, a bare name that happens to
/// contain a slash) has to go through the listing, or the `GetDatabase` call
/// would fail with a `not_found` that says nothing about the real problem.
pub fn is_full_database_name(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    parts.len() == 4
        && parts[0] == "instances"
        && parts[2] == "databases"
        && !parts[1].is_empty()
        && !parts[3].is_empty()
}

/// The database id: the last segment of a full resource name, else the input
/// unchanged (matching upstream's `extractDatabaseName`).
fn short_database_name(name: &str) -> &str {
    if is_full_database_name(name) {
        name.rsplit('/').next().unwrap_or(name)
    } else {
        name
    }
}

/// Escapes a Rust string for use inside a CEL double-quoted literal.
pub fn cel_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `name.contains("db")`, plus the `instance ==` / `project ==` terms the
/// catalog documents for `ListDatabases`.
pub fn build_database_filter(
    database: &str,
    instance: Option<&str>,
    project: Option<&str>,
) -> String {
    let mut filter = format!("name.contains(\"{}\")", cel_escape(database));
    if let Some(instance) = instance.filter(|s| !s.is_empty()) {
        filter.push_str(&format!(
            " && instance == \"{}\"",
            cel_escape(&qualify(instance, "instances"))
        ));
    }
    if let Some(project) = project.filter(|s| !s.is_empty()) {
        filter.push_str(&format!(
            " && project == \"{}\"",
            cel_escape(&qualify(project, "projects"))
        ));
    }
    filter
}

/// Turns a bare id into `{collection}/{id}` and leaves an already-qualified
/// name alone. A name that carries any `/` is assumed canonical, so
/// `projects/hr/instances/prod-pg` (a project-scoped instance) survives.
fn qualify(value: &str, collection: &str) -> String {
    if value.contains('/') {
        value.to_string()
    } else {
        format!("{collection}/{value}")
    }
}

/// Tiered matching on the database id: exact, then case-insensitive, then
/// case-insensitive substring. The first tier with any hit wins, so a database
/// named exactly what was asked for is never ambiguous with one that merely
/// contains it.
fn match_databases<'a>(entries: &'a [DatabaseEntry], input: &str) -> Vec<&'a DatabaseEntry> {
    let lower = input.to_lowercase();
    let tiers: [fn(&str, &str, &str) -> bool; 3] = [
        |short, input, _lower| short == input,
        |short, _input, lower| short.to_lowercase() == lower,
        |short, _input, lower| short.to_lowercase().contains(lower),
    ];
    for matches in tiers {
        let hits: Vec<&DatabaseEntry> = entries
            .iter()
            .filter(|e| matches(short_database_name(&e.name), input, &lower))
            .collect();
        if !hits.is_empty() {
            return hits;
        }
    }
    Vec::new()
}

/// READ_ONLY first, else ADMIN, else nothing. A query should not hit the admin
/// connection when a read replica exists.
fn select_data_source(sources: &[DataSource]) -> String {
    if let Some(ds) = sources.iter().find(|d| d.r#type == "READ_ONLY") {
        return ds.id.clone();
    }
    sources
        .iter()
        .find(|d| d.r#type == "ADMIN")
        .map(|d| d.id.clone())
        .unwrap_or_default()
}

fn not_found_error(database: &str, instance: Option<&str>, project: Option<&str>) -> anyhow::Error {
    let narrowed =
        instance.is_some_and(|s| !s.is_empty()) || project.is_some_and(|s| !s.is_empty());
    let hint = if narrowed {
        "try without --instance/--project"
    } else {
        "list them with `bbcli api DatabaseService/ListDatabases --args '{\"parent\": \"workspaces/-\"}'`"
    };
    tool_error(
        "DATABASE_NOT_FOUND",
        format!("no database matching {database:?}\n  {hint}"),
    )
}

/// Lists every candidate and picks none. Sorted by name so two runs of the
/// same ambiguous input produce the same output.
fn ambiguous_error(database: &str, matches: &[&DatabaseEntry]) -> anyhow::Error {
    let mut lines: Vec<String> = matches
        .iter()
        .map(|e| {
            format!(
                "  {}  ({}, {})",
                e.name, e.instance_resource.engine, e.project
            )
        })
        .collect();
    lines.sort();
    tool_error(
        "AMBIGUOUS_TARGET",
        format!(
            "{} databases match {database:?}; narrow with --instance/--project \
             or pass the full resource name:\n{}",
            matches.len(),
            lines.join("\n")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, engine: &str, sources: &[(&str, &str)]) -> DatabaseEntry {
        DatabaseEntry {
            name: name.to_string(),
            project: "projects/hr".to_string(),
            instance_resource: InstanceResource {
                engine: engine.to_string(),
                data_sources: sources
                    .iter()
                    .map(|(id, t)| DataSource {
                        id: id.to_string(),
                        r#type: t.to_string(),
                    })
                    .collect(),
            },
        }
    }

    fn names(matches: &[&DatabaseEntry]) -> Vec<String> {
        matches.iter().map(|e| e.name.clone()).collect()
    }

    /// A full name skips the listing entirely, so the detector decides whether
    /// a `GetDatabase` is legal. Anything shorter must not take that path — the
    /// call would 404 on a name the user never claimed was canonical.
    #[test]
    fn only_a_four_segment_instances_databases_name_skips_the_listing() {
        assert!(is_full_database_name("instances/a/databases/b"));
        assert!(!is_full_database_name("instances/a"));
        assert!(!is_full_database_name("projects/p"));
        assert!(!is_full_database_name("employee"));
        assert!(!is_full_database_name("instances/a/databases/"));
        assert!(!is_full_database_name("instances//databases/b"));
        assert!(!is_full_database_name("instances/a/databases/b/metadata"));
        assert!(!is_full_database_name("projects/p/instances/a"));
    }

    /// The tiers exist so an exact name wins outright. If they collapsed into
    /// one pass, `employee` would be ambiguous with `employee_archive` and a
    /// correct, unambiguous request would start failing.
    #[test]
    fn an_exact_name_beats_case_insensitive_which_beats_substring() {
        let entries = vec![
            entry("instances/i1/databases/Employee", "POSTGRES", &[]),
            entry("instances/i2/databases/employee", "POSTGRES", &[]),
            entry("instances/i3/databases/employee_archive", "MYSQL", &[]),
        ];
        assert_eq!(
            names(&match_databases(&entries, "employee")),
            ["instances/i2/databases/employee"],
            "the exact tier must not admit the other two"
        );
        // No exact hit, so the case-insensitive tier runs -- and it matches
        // two, which is genuinely ambiguous rather than a reason to fall
        // through to substring.
        assert_eq!(
            names(&match_databases(&entries, "EMPLOYEE")),
            [
                "instances/i1/databases/Employee",
                "instances/i2/databases/employee"
            ]
        );
    }

    #[test]
    fn one_substring_match_resolves_and_two_stay_ambiguous() {
        let entries = vec![
            entry("instances/i1/databases/employee", "POSTGRES", &[]),
            entry("instances/i2/databases/employee_archive", "MYSQL", &[]),
        ];
        assert_eq!(
            names(&match_databases(&entries, "archive")),
            ["instances/i2/databases/employee_archive"]
        );
        assert_eq!(match_databases(&entries, "emp").len(), 2);
        assert!(match_databases(&entries, "nope").is_empty());
    }

    /// A query must land on a replica when one exists; falling back to ADMIN
    /// is only for instances that have nothing else.
    #[test]
    fn read_only_wins_over_admin_and_admin_is_the_fallback() {
        assert_eq!(
            select_data_source(
                &entry("d", "POSTGRES", &[("admin", "ADMIN"), ("ro", "READ_ONLY")])
                    .instance_resource
                    .data_sources
            ),
            "ro"
        );
        assert_eq!(
            select_data_source(
                &entry("d", "POSTGRES", &[("admin", "ADMIN")])
                    .instance_resource
                    .data_sources
            ),
            "admin"
        );
        assert_eq!(
            select_data_source(&entry("d", "POSTGRES", &[]).instance_resource.data_sources),
            "",
            "no data source means the server picks, not that resolution failed"
        );
    }

    /// A bare id is the workspace-instance shorthand; a name with a slash is
    /// already canonical and must survive, or a project-scoped instance filter
    /// would be rewritten into one that matches nothing.
    #[test]
    fn a_bare_narrowing_id_is_qualified_and_a_canonical_one_passes_through() {
        assert_eq!(
            build_database_filter("emp", Some("prod"), None),
            "name.contains(\"emp\") && instance == \"instances/prod\""
        );
        assert_eq!(
            build_database_filter("emp", Some("instances/prod"), None),
            "name.contains(\"emp\") && instance == \"instances/prod\""
        );
        assert_eq!(
            build_database_filter("emp", Some("projects/hr/instances/prod"), None),
            "name.contains(\"emp\") && instance == \"projects/hr/instances/prod\""
        );
        assert_eq!(
            build_database_filter("emp", None, Some("hr")),
            "name.contains(\"emp\") && project == \"projects/hr\""
        );
        assert_eq!(
            build_database_filter("emp", Some("prod"), Some("projects/hr")),
            "name.contains(\"emp\") && instance == \"instances/prod\" && project == \"projects/hr\""
        );
    }

    /// The filter is a CEL string literal on the wire. Unescaped input would
    /// make the server reject the whole expression, which reads to an agent
    /// like the database not existing.
    #[test]
    fn quotes_and_backslashes_are_escaped_in_the_cel_literal() {
        assert_eq!(cel_escape("a\"b"), "a\\\"b");
        assert_eq!(cel_escape("a\\b"), "a\\\\b");
        assert_eq!(
            build_database_filter("we\"ird", None, None),
            "name.contains(\"we\\\"ird\")"
        );
    }

    /// Both refusals must name the way out: the zero case says how to see what
    /// exists, the many case lists what it found instead of choosing.
    #[test]
    fn refusals_name_every_candidate_or_the_way_to_list_them() {
        let err = not_found_error("nope", None, None).to_string();
        assert!(err.starts_with("[DATABASE_NOT_FOUND]"), "{err}");
        assert!(err.contains("ListDatabases"), "{err}");
        let narrowed = not_found_error("nope", Some("prod"), None).to_string();
        assert!(
            narrowed.contains("try without --instance/--project"),
            "{narrowed}"
        );

        let a = entry("instances/i2/databases/employee", "POSTGRES", &[]);
        let b = entry("instances/i1/databases/employee", "MYSQL", &[]);
        let err = ambiguous_error("employee", &[&a, &b]).to_string();
        assert!(
            err.starts_with("[AMBIGUOUS_TARGET] 2 databases match"),
            "{err}"
        );
        assert!(
            err.contains("instances/i1/databases/employee  (MYSQL, projects/hr)"),
            "{err}"
        );
        assert!(
            err.contains("instances/i2/databases/employee  (POSTGRES, projects/hr)"),
            "{err}"
        );
        // Sorted, so the same ambiguity always reads the same way.
        assert!(
            err.find("instances/i1").unwrap() < err.find("instances/i2").unwrap(),
            "{err}"
        );
    }
}
