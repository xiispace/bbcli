//! `bbcli schema` — a database's schema at a detail level a model can afford.
//!
//! Mirrors upstream's `backend/api/mcp/tool_schema.go`. `GetDatabaseMetadata`
//! returns everything about every table; that is unreadable at agent scale, so
//! this summarises (`--include summary`), drills into one table
//! (`--table`), and bounds the bulk modes. Two rules are load-bearing and
//! easy to "simplify" back into a bug: it asks for one table more than it will
//! show (so `truncated` is a fact), and it drops `--schema` on engines with no
//! named schemas (where the server's exact-match filter would return nothing).

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

use crate::client::ApiClient;
use crate::resolve::{self, cel_escape, tool_error};

/// How much per table to return. `summary` is the default because a first
/// call is almost always "what is in here".
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Include {
    /// Name, row count, column count, comment
    Summary,
    /// ...plus columns with type, nullability and primary-key flag
    Columns,
    /// ...plus column defaults and comments, indexes and foreign keys
    Details,
}

/// User-facing cap on tables per schema in the bulk modes. The server is
/// asked for one more, so "exactly 200" and "cut off at 200" are
/// distinguishable rather than both reported as maybe-truncated.
const TABLE_LIMIT: usize = 200;
/// Bound on the second, unfiltered fetch that builds `TABLE_NOT_FOUND`
/// candidates: wide enough to catch a typo, narrow enough to stay cheap.
const CANDIDATE_FETCH_LIMIT: u32 = 500;
/// How many candidate names an error names. More is noise.
const CANDIDATE_CAP: usize = 10;

/// Engines that expose more than one user-visible schema per database.
///
/// Copied verbatim from upstream. On every other engine the schema name is
/// empty, and the server applies `schema == "x"` as an *exact* match
/// (`convertStoreDatabaseMetadata`), so passing a hint like `public` on MySQL
/// filters out every table and the caller sees an empty database. Adding an
/// engine upstream means adding it here.
const MULTI_SCHEMA_ENGINES: &[&str] = &[
    "POSTGRES",
    "COCKROACHDB",
    "MSSQL",
    "ORACLE",
    "SNOWFLAKE",
    "REDSHIFT",
    "DATABRICKS",
    "TRINO",
    "SPANNER",
    "HIVE",
];

/// An empty engine (unknown to this binary) counts as single-schema: dropping
/// the filter with a note beats returning zero tables from an exact-match miss.
fn engine_supports_schemas(engine: &str) -> bool {
    MULTI_SCHEMA_ENGINES.contains(&engine)
}

// --- The parts of DatabaseMetadata this command consumes. Unknown fields are
// --- ignored, so a newer server still decodes.

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DatabaseMetadata {
    #[serde(default)]
    schemas: Vec<SchemaMetadata>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaMetadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    tables: Vec<TableMetadata>,
    #[serde(default)]
    views: Vec<NamedMetadata>,
    #[serde(default)]
    functions: Vec<NamedMetadata>,
    #[serde(default)]
    procedures: Vec<NamedMetadata>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TableMetadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    columns: Vec<ColumnMetadata>,
    #[serde(default)]
    indexes: Vec<IndexMetadata>,
    #[serde(default, deserialize_with = "number_or_string")]
    row_count: i64,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    foreign_keys: Vec<ForeignKeyMetadata>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ColumnMetadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    default: String,
    #[serde(default)]
    comment: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexMetadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    expressions: Vec<String>,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    unique: bool,
    #[serde(default)]
    primary: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForeignKeyMetadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    referenced_table: String,
    #[serde(default)]
    referenced_columns: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NamedMetadata {
    #[serde(default)]
    name: String,
}

/// protojson renders 64-bit fields as either a number or a string depending on
/// the producer, and `rowCount` is one. Accept both and emit a number, so the
/// output type does not depend on which server answered.
fn number_or_string<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(i64),
        Str(String),
    }
    Ok(match NumberOrString::deserialize(d)? {
        NumberOrString::Number(n) => n,
        NumberOrString::Str(s) => s.trim().parse().unwrap_or(0),
    })
}

// --- Output shape. `skip_serializing_if` mirrors upstream's `omitempty`:
// --- absent fields are how a model tells "none" from "not at this level".

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaOutput {
    database: String,
    engine: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    schemas: Vec<SchemaSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    table: Option<TableEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaSection {
    /// `public`, or empty on engines without named schemas.
    name: String,
    tables: Vec<TableEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    views: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    function_count: usize,
    #[serde(skip_serializing_if = "is_zero")]
    procedure_count: usize,
    #[serde(skip_serializing_if = "is_false")]
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tables_shown: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TableEntry {
    name: String,
    row_count: i64,
    /// Summary only: at `columns` and above, `columns.len()` is the count.
    #[serde(skip_serializing_if = "Option::is_none")]
    column_count: Option<usize>,
    #[serde(skip_serializing_if = "str::is_empty")]
    comment: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    columns: Vec<ColumnEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    indexes: Vec<IndexEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    foreign_keys: Vec<FkEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ColumnEntry {
    name: String,
    r#type: String,
    nullable: bool,
    #[serde(skip_serializing_if = "is_false")]
    primary_key: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    default: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    comment: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexEntry {
    name: String,
    r#type: String,
    unique: bool,
    columns: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FkEntry {
    name: String,
    columns: Vec<String>,
    referenced_table: String,
    referenced_columns: Vec<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Fetches and shapes the schema of `database`.
pub async fn run(
    client: &ApiClient,
    database: &str,
    instance: Option<&str>,
    project: Option<&str>,
    schema: Option<&str>,
    table: Option<&str>,
    include: Option<Include>,
) -> Result<Value> {
    let include = resolve_include(include, table);
    let resolved = resolve::resolve(client, database, instance, project).await?;

    let mut schema_hint = schema.filter(|s| !s.is_empty());
    if schema_hint.is_some() && !engine_supports_schemas(&resolved.engine) {
        // A note rather than an error: the tables the caller actually wanted
        // are still returned, and saying why the flag did nothing is what
        // stops them from retrying it.
        eprintln!(
            "note: --schema ignored — {} does not use named schemas",
            if resolved.engine.is_empty() {
                "this engine"
            } else {
                &resolved.engine
            }
        );
        schema_hint = None;
    }

    let metadata = fetch_metadata(
        client,
        &resolved.name,
        &build_metadata_filter(schema_hint, table),
        limit_for_include(include, table),
    )
    .await?;

    let output = match table {
        Some(table) => {
            let matches = find_table_matches(&metadata, table);
            match matches.len() {
                0 => {
                    // Re-fetch unfiltered so the refusal can name what does
                    // exist; a bare "not found" leaves the agent guessing at
                    // spellings, which is how it burns turns.
                    let candidates = lookup_candidates(
                        client,
                        &resolved.name,
                        &build_metadata_filter(schema_hint, None),
                        table,
                    )
                    .await;
                    return Err(table_not_found_error(table, &resolved.name, &candidates));
                }
                1 => SchemaOutput {
                    database: resolved.name.clone(),
                    engine: resolved.engine.clone(),
                    schemas: Vec::new(),
                    // A drill-down is always full detail: --include describes
                    // how much of a whole database to print, and the caller
                    // already narrowed to one table.
                    table: Some(build_table_entry(matches[0].1, Include::Details)),
                },
                _ => {
                    let schemas: Vec<&str> = matches.iter().map(|(s, _)| *s).collect();
                    return Err(ambiguous_table_error(table, &resolved.name, &schemas));
                }
            }
        }
        None => SchemaOutput {
            database: resolved.name.clone(),
            engine: resolved.engine.clone(),
            schemas: transform_schemas(&metadata, include),
            table: None,
        },
    };

    serde_json::to_value(output).context("failed to serialize the schema output")
}

/// `summary` normally, `details` when one table was named — a caller who
/// drilled in wants everything about that table, not a row count.
fn resolve_include(include: Option<Include>, table: Option<&str>) -> Include {
    match (include, table) {
        (Some(include), _) => include,
        (None, Some(_)) => Include::Details,
        (None, None) => Include::Summary,
    }
}

/// `schema == "s" && table == "t"`, or empty when nothing narrows.
fn build_metadata_filter(schema: Option<&str>, table: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(schema) = schema.filter(|s| !s.is_empty()) {
        parts.push(format!("schema == \"{}\"", cel_escape(schema)));
    }
    if let Some(table) = table.filter(|s| !s.is_empty()) {
        parts.push(format!("table == \"{}\"", cel_escape(table)));
    }
    parts.join(" && ")
}

/// The per-schema `limit` to send. Only the bulk modes need one, and they ask
/// for `TABLE_LIMIT + 1` so truncation is exact. Summary is uncapped: its
/// per-table payload is a few fields, and a silent cap would hide tables.
fn limit_for_include(include: Include, table: Option<&str>) -> Option<u32> {
    if table.is_some_and(|t| !t.is_empty()) {
        return None;
    }
    match include {
        Include::Columns | Include::Details => Some(TABLE_LIMIT as u32 + 1),
        Include::Summary => None,
    }
}

async fn fetch_metadata(
    client: &ApiClient,
    database: &str,
    filter: &str,
    limit: Option<u32>,
) -> Result<DatabaseMetadata> {
    let mut args = json!({"name": format!("{database}/metadata")});
    if !filter.is_empty() {
        args["filter"] = json!(filter);
    }
    if let Some(limit) = limit {
        args["limit"] = json!(limit);
    }
    let resp = client
        .call_announced("DatabaseService/GetDatabaseMetadata", &args)
        .await
        .context("fetching database metadata")?;
    serde_json::from_value(resp).context("failed to parse the database metadata")
}

/// Every (schema, table) whose table name equals `table`. The caller decides
/// what 0, 1 or many mean — it must not pick one.
fn find_table_matches<'a>(
    metadata: &'a DatabaseMetadata,
    table: &str,
) -> Vec<(&'a str, &'a TableMetadata)> {
    metadata
        .schemas
        .iter()
        .flat_map(|schema| {
            schema
                .tables
                .iter()
                .filter(|t| t.name == table)
                .map(move |t| (schema.name.as_str(), t))
        })
        .collect()
}

/// Table names worth suggesting after a miss. A failure to fetch yields no
/// candidates rather than replacing the real error.
async fn lookup_candidates(
    client: &ApiClient,
    database: &str,
    filter: &str,
    missing: &str,
) -> Vec<String> {
    match fetch_metadata(client, database, filter, Some(CANDIDATE_FETCH_LIMIT)).await {
        Ok(metadata) => collect_candidates(&metadata, missing),
        Err(_) => Vec::new(),
    }
}

fn collect_candidates(metadata: &DatabaseMetadata, missing: &str) -> Vec<String> {
    metadata
        .schemas
        .iter()
        .flat_map(|s| s.tables.iter())
        .filter(|t| table_name_matches(&t.name, missing))
        .take(CANDIDATE_CAP)
        .map(|t| t.name.clone())
        .collect()
}

/// A plausible spelling of `missing`: it contains the input, or shares its
/// first four characters (`orderz` → `orders`, `order_items`).
fn table_name_matches(name: &str, missing: &str) -> bool {
    if missing.is_empty() {
        return false;
    }
    let name = name.to_lowercase();
    let missing = missing.to_lowercase();
    if name.contains(&missing) {
        return true;
    }
    // Byte-slicing a lowercased name is safe only on ASCII; a multi-byte
    // prefix would panic, so compare character by character instead.
    let prefix_len = missing.chars().count().min(4);
    let n: Vec<char> = name.chars().take(prefix_len).collect();
    let m: Vec<char> = missing.chars().take(prefix_len).collect();
    n.len() == prefix_len && n == m
}

/// Shapes every schema for the requested detail level: sorted, and trimmed in
/// the bulk modes.
fn transform_schemas(metadata: &DatabaseMetadata, include: Include) -> Vec<SchemaSection> {
    // Only the bulk modes asked the server for limit+1, so only they have a
    // sentinel row to drop. Applying the cap to summary would silently hide
    // tables from a mode designed to list all of them.
    let apply_truncation = matches!(include, Include::Columns | Include::Details);

    let mut sections: Vec<SchemaSection> = metadata
        .schemas
        .iter()
        .map(|schema| {
            let mut tables: Vec<&TableMetadata> = schema.tables.iter().collect();
            tables.sort_by(|a, b| a.name.cmp(&b.name));

            let truncated = apply_truncation && tables.len() > TABLE_LIMIT;
            if truncated {
                tables.truncate(TABLE_LIMIT);
            }

            let mut views: Vec<String> = schema.views.iter().map(|v| v.name.clone()).collect();
            views.sort();

            SchemaSection {
                name: schema.name.clone(),
                tables: tables
                    .into_iter()
                    .map(|t| build_table_entry(t, include))
                    .collect(),
                views,
                function_count: schema.functions.len(),
                procedure_count: schema.procedures.len(),
                truncated,
                tables_shown: truncated.then_some(TABLE_LIMIT),
            }
        })
        .collect();

    // Empty sorts first, which puts the single unnamed schema of a
    // MySQL-family database at the top where a reader expects it.
    sections.sort_by(|a, b| a.name.cmp(&b.name));
    sections
}

fn build_table_entry(t: &TableMetadata, include: Include) -> TableEntry {
    let mut entry = TableEntry {
        name: t.name.clone(),
        row_count: t.row_count,
        column_count: None,
        comment: t.comment.clone(),
        columns: Vec::new(),
        indexes: Vec::new(),
        foreign_keys: Vec::new(),
    };
    if include == Include::Summary {
        entry.column_count = Some(t.columns.len());
        return entry;
    }

    let details = include == Include::Details;
    let pk = primary_key_columns(&t.indexes);
    entry.columns = t
        .columns
        .iter()
        .map(|c| ColumnEntry {
            name: c.name.clone(),
            r#type: c.r#type.clone(),
            nullable: c.nullable,
            primary_key: pk.iter().any(|p| *p == c.name),
            default: if details {
                c.default.clone()
            } else {
                String::new()
            },
            comment: if details {
                c.comment.clone()
            } else {
                String::new()
            },
        })
        .collect();

    if details {
        entry.indexes = t
            .indexes
            .iter()
            .map(|i| IndexEntry {
                name: i.name.clone(),
                r#type: i.r#type.clone(),
                unique: i.unique,
                columns: i.expressions.clone(),
            })
            .collect();
        entry.indexes.sort_by(|a, b| a.name.cmp(&b.name));

        entry.foreign_keys = t
            .foreign_keys
            .iter()
            .map(|fk| FkEntry {
                name: fk.name.clone(),
                columns: fk.columns.clone(),
                referenced_table: fk.referenced_table.clone(),
                referenced_columns: fk.referenced_columns.clone(),
            })
            .collect();
        entry.foreign_keys.sort_by(|a, b| a.name.cmp(&b.name));
    }
    entry
}

/// Primary-key columns come from the index flagged `primary`; `ColumnMetadata`
/// carries no such flag. The expressions of a primary index are column names
/// in practice (no engine here allows an expression primary key), and a silent
/// miss beats flagging the wrong column.
fn primary_key_columns(indexes: &[IndexMetadata]) -> Vec<&str> {
    indexes
        .iter()
        .filter(|i| i.primary)
        .flat_map(|i| i.expressions.iter().map(String::as_str))
        .collect()
}

fn table_not_found_error(table: &str, database: &str, candidates: &[String]) -> anyhow::Error {
    let mut msg = format!("no table matching {table:?} in {database}");
    if !candidates.is_empty() {
        msg.push_str(&format!("\n  candidates: {}", candidates.join(", ")));
    }
    msg.push_str("\n  run without --table to see available tables");
    tool_error("TABLE_NOT_FOUND", msg)
}

fn ambiguous_table_error(table: &str, database: &str, schemas: &[&str]) -> anyhow::Error {
    tool_error(
        "AMBIGUOUS_TABLE",
        format!(
            "table {table:?} exists in multiple schemas of {database}; \
             re-run with --schema set to one of: {}",
            schemas.join(", ")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(json: Value) -> DatabaseMetadata {
        serde_json::from_value(json).expect("test metadata decodes")
    }

    fn table(name: &str, columns: usize) -> Value {
        json!({
            "name": name,
            "columns": (0..columns).map(|i| json!({"name": format!("c{i}"), "type": "int"})).collect::<Vec<_>>(),
        })
    }

    /// `--include` describes how much of a whole database to print; naming one
    /// table is already the narrowing, so it implies full detail. Getting this
    /// backwards makes the drill-down useless (a row count) or the overview
    /// unaffordable (every column of every table).
    #[test]
    fn include_defaults_to_summary_and_to_details_for_a_single_table() {
        assert_eq!(resolve_include(None, None), Include::Summary);
        assert_eq!(resolve_include(None, Some("orders")), Include::Details);
        // An explicit flag still wins for the bulk path.
        assert_eq!(
            resolve_include(Some(Include::Columns), None),
            Include::Columns
        );
    }

    /// Only the modes that asked for limit+1 may trim, and they must flag it.
    /// Summary is uncapped on purpose: a silent cap there would hide tables
    /// from the mode whose whole job is listing them.
    #[test]
    fn columns_mode_trims_the_sentinel_table_and_flags_it_while_summary_never_does() {
        assert_eq!(limit_for_include(Include::Columns, None), Some(201));
        assert_eq!(limit_for_include(Include::Details, None), Some(201));
        assert_eq!(limit_for_include(Include::Summary, None), None);
        // A single-table drill-down needs no cap.
        assert_eq!(limit_for_include(Include::Details, Some("orders")), None);

        let tables: Vec<Value> = (0..201).map(|i| table(&format!("t{i:03}"), 1)).collect();
        let md = metadata(json!({"schemas": [{"name": "public", "tables": tables}]}));

        let bulk = &transform_schemas(&md, Include::Columns)[0];
        assert_eq!(bulk.tables.len(), TABLE_LIMIT);
        assert!(bulk.truncated);
        assert_eq!(bulk.tables_shown, Some(TABLE_LIMIT));

        let summary = &transform_schemas(&md, Include::Summary)[0];
        assert_eq!(summary.tables.len(), 201);
        assert!(!summary.truncated);
        assert_eq!(summary.tables_shown, None);
    }

    /// Exactly 200 tables is not truncation. If the client did not ask for one
    /// extra row it could not tell the two apart, and every full page would be
    /// reported as maybe-incomplete.
    #[test]
    fn exactly_the_limit_is_not_reported_as_truncated() {
        let tables: Vec<Value> = (0..200).map(|i| table(&format!("t{i:03}"), 1)).collect();
        let md = metadata(json!({"schemas": [{"name": "public", "tables": tables}]}));
        let section = &transform_schemas(&md, Include::Details)[0];
        assert_eq!(section.tables.len(), 200);
        assert!(!section.truncated);
    }

    /// `ColumnMetadata` has no primary-key flag, so the only source is the
    /// index marked primary. Reading `unique` instead would flag every unique
    /// column as a key.
    #[test]
    fn primary_key_columns_come_from_the_primary_index() {
        let md = metadata(json!({"schemas": [{"name": "public", "tables": [{
            "name": "orders",
            "columns": [{"name": "id", "type": "int"}, {"name": "email", "type": "text", "nullable": true}],
            "indexes": [
                {"name": "orders_email_key", "expressions": ["email"], "unique": true},
                {"name": "orders_pkey", "expressions": ["id"], "unique": true, "primary": true},
            ],
        }]}]}));
        let section = &transform_schemas(&md, Include::Details)[0];
        let cols = &section.tables[0].columns;
        assert!(cols[0].primary_key, "id is the primary key");
        assert!(!cols[1].primary_key, "a unique index is not a primary key");
    }

    /// Alphabetical order is what makes two runs comparable and lets a reader
    /// find a name; server order is an implementation detail of the sync.
    #[test]
    fn tables_views_indexes_and_schemas_come_out_sorted() {
        let md = metadata(json!({"schemas": [
            {"name": "zoo", "tables": [], "views": []},
            {"name": "", "tables": [], "views": []},
            {"name": "public",
             "tables": [table("orders", 1), table("accounts", 1)],
             "views": [{"name": "v_z"}, {"name": "v_a"}]},
        ]}));
        let sections = transform_schemas(&md, Include::Summary);
        assert_eq!(
            sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["", "public", "zoo"],
            "the unnamed schema of a MySQL-family database sorts first"
        );
        let public = &sections[1];
        assert_eq!(
            public
                .tables
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            ["accounts", "orders"]
        );
        assert_eq!(public.views, ["v_a", "v_z"]);

        let md = metadata(json!({"schemas": [{"name": "public", "tables": [{
            "name": "t",
            "indexes": [{"name": "i_b"}, {"name": "i_a"}],
            "foreignKeys": [{"name": "fk_b"}, {"name": "fk_a"}],
        }]}]}));
        let t = &transform_schemas(&md, Include::Details)[0].tables[0];
        assert_eq!(
            t.indexes
                .iter()
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>(),
            ["i_a", "i_b"]
        );
        assert_eq!(
            t.foreign_keys
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["fk_a", "fk_b"]
        );
    }

    /// Picking one of two same-named tables would describe a table the caller
    /// did not ask about, and nothing in the output would say so.
    #[test]
    fn a_table_name_in_two_schemas_is_ambiguous_rather_than_picked() {
        let md = metadata(json!({"schemas": [
            {"name": "public", "tables": [table("orders", 2)]},
            {"name": "archive", "tables": [table("orders", 3)]},
        ]}));
        let matches = find_table_matches(&md, "orders");
        assert_eq!(matches.len(), 2);
        let err = ambiguous_table_error(
            "orders",
            "instances/i/databases/d",
            &matches.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        )
        .to_string();
        assert!(err.starts_with("[AMBIGUOUS_TABLE]"), "{err}");
        assert!(err.contains("--schema"), "{err}");
        assert!(err.contains("public") && err.contains("archive"), "{err}");

        assert!(find_table_matches(&md, "nope").is_empty());
    }

    /// The point of candidates is to end the guessing after a miss, so both a
    /// substring and a typo'd prefix must surface — and the list must stay
    /// short enough to read.
    #[test]
    fn candidates_match_by_substring_or_four_char_prefix_and_cap_at_ten() {
        assert!(table_name_matches("orders", "order"), "substring");
        assert!(table_name_matches("ORDERS", "order"), "case-insensitive");
        assert!(table_name_matches("order_items", "orderz"), "shared prefix");
        assert!(!table_name_matches("users", "orderz"), "unrelated");
        assert!(
            !table_name_matches("ord", "orderz"),
            "prefix shorter than 4"
        );
        assert!(
            table_name_matches("abc_x", "abc"),
            "input shorter than 4 must match whole"
        );
        assert!(!table_name_matches("axc_x", "abc"));
        assert!(
            !table_name_matches("orders", ""),
            "an empty input matches nothing"
        );

        let tables: Vec<Value> = (0..15)
            .map(|i| table(&format!("orders_{i:02}"), 1))
            .collect();
        let md = metadata(json!({"schemas": [{"name": "public", "tables": tables}]}));
        assert_eq!(collect_candidates(&md, "orders").len(), CANDIDATE_CAP);

        let err = table_not_found_error("nope", "instances/i/databases/d", &["orders".to_string()]);
        let err = err.to_string();
        assert!(err.starts_with("[TABLE_NOT_FOUND]"), "{err}");
        assert!(err.contains("candidates: orders"), "{err}");
        assert!(err.contains("run without --table"), "{err}");
        // No candidates: still say how to see what exists.
        let bare = table_not_found_error("nope", "instances/i/databases/d", &[]).to_string();
        assert!(!bare.contains("candidates:"), "{bare}");
        assert!(bare.contains("run without --table"), "{bare}");
    }

    /// The server applies `schema == "x"` as an exact match, and MySQL's
    /// schema name is empty — so keeping the filter there returns zero tables
    /// and reads to an agent like an empty database.
    #[test]
    fn schema_filter_survives_on_postgres_and_is_dropped_on_mysql() {
        assert!(engine_supports_schemas("POSTGRES"));
        assert!(engine_supports_schemas("MSSQL"));
        assert!(!engine_supports_schemas("MYSQL"));
        assert!(!engine_supports_schemas("TIDB"));
        assert!(
            !engine_supports_schemas(""),
            "an unknown engine must be treated as single-schema, not risked"
        );
        assert_eq!(
            build_metadata_filter(Some("public"), Some("orders")),
            "schema == \"public\" && table == \"orders\""
        );
        assert_eq!(
            build_metadata_filter(None, Some("orders")),
            "table == \"orders\""
        );
        assert_eq!(build_metadata_filter(None, None), "");
    }

    /// `rowCount` is an int64: protojson lets it arrive as a string, and the
    /// output must be a number either way or a model has to special-case it.
    #[test]
    fn row_count_decodes_from_a_string_or_a_number() {
        let md = metadata(json!({"schemas": [{"name": "s", "tables": [
            {"name": "a", "rowCount": "1234"},
            {"name": "b", "rowCount": 7},
            {"name": "c"},
        ]}]}));
        let tables = &transform_schemas(&md, Include::Summary)[0].tables;
        assert_eq!(tables[0].row_count, 1234);
        assert_eq!(tables[1].row_count, 7);
        assert_eq!(tables[2].row_count, 0);
    }

    /// The absent fields carry meaning: no `columns` in summary means "not at
    /// this level", and no `columnCount` in columns mode means "count the
    /// columns you were given". Emitting both blurs that.
    #[test]
    fn each_level_omits_the_fields_that_belong_to_another() {
        let md = metadata(json!({"schemas": [{"name": "public", "tables": [{
            "name": "orders",
            "columns": [{"name": "id", "type": "int", "default": "0", "comment": "pk"}],
            "indexes": [{"name": "orders_pkey", "expressions": ["id"], "primary": true}],
            "foreignKeys": [{"name": "fk", "columns": ["id"], "referencedTable": "users"}],
        }]}]}));

        let summary = serde_json::to_value(&transform_schemas(&md, Include::Summary)[0]).unwrap();
        assert_eq!(summary["tables"][0]["columnCount"], json!(1));
        assert!(summary["tables"][0].get("columns").is_none());

        let columns = serde_json::to_value(&transform_schemas(&md, Include::Columns)[0]).unwrap();
        assert!(columns["tables"][0].get("columnCount").is_none());
        assert_eq!(columns["tables"][0]["columns"][0]["name"], json!("id"));
        assert!(columns["tables"][0]["columns"][0].get("default").is_none());
        assert!(columns["tables"][0].get("indexes").is_none());

        let details = serde_json::to_value(&transform_schemas(&md, Include::Details)[0]).unwrap();
        assert_eq!(details["tables"][0]["columns"][0]["default"], json!("0"));
        assert_eq!(
            details["tables"][0]["columns"][0]["primaryKey"],
            json!(true)
        );
        assert_eq!(
            details["tables"][0]["indexes"][0]["name"],
            json!("orders_pkey")
        );
        assert_eq!(
            details["tables"][0]["foreignKeys"][0]["referencedTable"],
            json!("users")
        );
    }
}
