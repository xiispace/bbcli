//! `bbcli query` — resolve a database by name, run one read-only statement,
//! and flatten the result into plain JSON rows.
//!
//! Mirrors upstream's `backend/api/mcp/tool_query.go`. It earns a subcommand
//! over `bbcli api SQLService/Query` on two counts: it resolves the resource
//! name and data source id (see `resolve`), and it flattens the `RowValue`
//! oneof — `[{"int64Value": "1"}, {"stringValue": "a"}]` becomes `[1, "a"]`,
//! which is the difference between a model reading a result set and a model
//! spending its context on protojson wrappers.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::client::ApiClient;
use crate::resolve::{self, tool_error};

/// Runs `statement` against `database` and returns the output document.
///
/// Notes for the operator (extra result sets) go to stderr; the returned
/// value is what stdout gets.
pub async fn run(
    client: &ApiClient,
    database: &str,
    statement: &str,
    instance: Option<&str>,
    project: Option<&str>,
    limit: u32,
) -> Result<Value> {
    let resolved = resolve::resolve(client, database, instance, project).await?;

    let mut args = json!({
        "name": resolved.name,
        "statement": statement,
        // One more row than asked for is what makes `truncated` exact rather
        // than "maybe": if the server hands back limit+1, there was more.
        "limit": limit as u64 + 1,
    });
    if !resolved.data_source_id.is_empty() {
        args["dataSourceId"] = json!(resolved.data_source_id);
    }

    let resp = client
        .call_announced("SQLService/Query", &args)
        .await
        .context("running the query")?;

    let (output, notes) = build_output(
        &resolved.name,
        &resolved.data_source_id,
        &resp,
        limit as usize,
    )?;
    for note in notes {
        eprintln!("note: {note}");
    }
    Ok(output)
}

/// Shapes a `QueryResponse` into the output document, plus any notes for
/// stderr. Pure, so every rule below is testable without a server.
fn build_output(
    database: &str,
    data_source_id: &str,
    resp: &Value,
    limit: usize,
) -> Result<(Value, Vec<String>)> {
    let results = resp
        .get("results")
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    let mut notes = Vec::new();
    // One statement per call is the contract, so a multi-statement response is
    // announced rather than silently trimmed -- and rather than allowed to
    // change the output shape, which every caller would then have to handle.
    if results.len() > 1 {
        notes.push(format!(
            "{} result sets returned; showing the first — send one statement per call",
            results.len()
        ));
    }

    let Some(result) = results.first() else {
        return Ok((
            json!({
                "database": database,
                "dataSourceId": data_source_id,
                "columns": [],
                "columnTypes": [],
                "rows": [],
                "rowCount": 0,
                "truncated": false,
                "latencyMs": 0,
            }),
            notes,
        ));
    };

    // A failed statement can arrive inside a 200: the Connect call succeeded,
    // the SQL did not. Reporting that as a result would have an agent read an
    // empty row set as "no matching rows".
    if let Some(err) = result.get("error").and_then(Value::as_str) {
        if !err.is_empty() {
            return Err(tool_error("QUERY_ERROR", err));
        }
    }

    let mut rows: Vec<Value> = result
        .get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let cells = row.get("values").and_then(Value::as_array);
                    Value::Array(
                        cells
                            .map(|cells| cells.iter().map(flatten_row_value).collect())
                            .unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let truncated = rows.len() > limit;
    rows.truncate(limit);

    Ok((
        json!({
            "database": database,
            "dataSourceId": data_source_id,
            "columns": string_list(result.get("columnNames")),
            "columnTypes": string_list(result.get("columnTypeNames")),
            "rowCount": rows.len(),
            "rows": rows,
            "truncated": truncated,
            "latencyMs": parse_latency_ms(result.get("latency").and_then(Value::as_str)),
        }),
        notes,
    ))
}

fn string_list(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Unwraps one `RowValue` oneof into the plain JSON value a model can read.
///
/// A cell is `{"stringValue": "x"}`: exactly one key naming the variant. An
/// unknown key (a variant added upstream after this binary was built) yields
/// the inner value rather than nothing, so a newer server degrades to raw
/// protojson instead of dropping data.
fn flatten_row_value(cell: &Value) -> Value {
    let Some(obj) = cell.as_object() else {
        return cell.clone();
    };
    if obj.len() != 1 {
        return cell.clone();
    }
    let (key, inner) = obj.iter().next().expect("len checked above");
    match key.as_str() {
        "nullValue" => Value::Null,
        // protojson encodes 64-bit ints as strings, which a model then cannot
        // compare or sum. Widen back to a number when it fits exactly
        // (serde_json holds i64/u64 losslessly); a value that does not fit
        // keeps its string rather than being silently rounded through f64.
        "int64Value" | "uint64Value" => widen_integer(inner),
        // Timestamps collapse to the RFC 3339 UTC instant. Zone, offset and
        // accuracy are dropped on purpose: the instant is the unambiguous
        // value, and the wrapper object costs an agent a lookup per cell.
        "timestampValue" | "timestampTzValue" => match inner.get("googleTimestamp") {
            Some(ts) => ts.clone(),
            // No instant to collapse to — hand back what the server sent
            // rather than inventing one.
            None => inner.clone(),
        },
        // boolValue, stringValue, int32Value, uint32Value, doubleValue,
        // floatValue and bytesValue are already the value ("NaN"/"Infinity"
        // arrive as strings and stay strings); bytesValue is base64 text, and
        // decoding it would produce bytes JSON cannot hold. valueValue is a
        // google.protobuf.Value, i.e. plain JSON already.
        _ => inner.clone(),
    }
}

/// A protojson 64-bit integer string as a JSON number when it fits, else the
/// string unchanged.
fn widen_integer(inner: &Value) -> Value {
    let Some(s) = inner.as_str() else {
        return inner.clone(); // already a number
    };
    if let Ok(n) = s.parse::<i64>() {
        return json!(n);
    }
    if let Ok(n) = s.parse::<u64>() {
        return json!(n);
    }
    inner.clone()
}

/// A `google.protobuf.Duration` (`"0.012s"`) in whole milliseconds.
///
/// Latency is a diagnostic, so an unparsable value is 0 rather than an error:
/// failing a successful query over its own timing would be absurd.
fn parse_latency_ms(latency: Option<&str>) -> u64 {
    let s = latency.unwrap_or("").trim();
    let s = s.strip_suffix('s').unwrap_or(s);
    match s.parse::<f64>() {
        Ok(secs) if secs.is_finite() && secs >= 0.0 => (secs * 1000.0).round() as u64,
        _ => 0,
    }
}

/// Builds a `QueryResponse`-shaped value with `n` identical rows, for the
/// truncation tests.
#[cfg(test)]
fn response_with_rows(n: usize) -> Value {
    let rows: Vec<Value> = (0..n)
        .map(|i| json!({"values": [{"int64Value": i.to_string()}]}))
        .collect();
    json!({"results": [{"columnNames": ["id"], "columnTypeNames": ["INT"], "rows": rows}]})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(cell: Value) -> Value {
        flatten_row_value(&cell)
    }

    /// The wire type for int64 is a string. Leaving it a string means an agent
    /// cannot compare or aggregate the column without re-parsing every cell.
    #[test]
    fn an_int64_string_becomes_a_json_number() {
        assert_eq!(flat(json!({"int64Value": "42"})), json!(42));
        assert_eq!(flat(json!({"int64Value": "-42"})), json!(-42));
        assert_eq!(
            flat(json!({"uint64Value": "18446744073709551615"})),
            json!(18446744073709551615u64)
        );
        // Already a number on the wire (some servers emit it that way).
        assert_eq!(flat(json!({"int64Value": 7})), json!(7));
    }

    /// Widening is only safe when it is exact. A value JSON cannot hold as an
    /// integer keeps its string instead of being rounded through a float.
    #[test]
    fn an_int64_too_large_for_json_keeps_its_string() {
        let huge = "184467440737095516150";
        assert_eq!(flat(json!({"int64Value": huge})), json!(huge));
    }

    /// Non-finite doubles are protojson strings. Turning them into null or 0
    /// would report a different value than the database holds.
    #[test]
    fn non_finite_doubles_stay_strings() {
        assert_eq!(flat(json!({"doubleValue": "NaN"})), json!("NaN"));
        assert_eq!(
            flat(json!({"doubleValue": "-Infinity"})),
            json!("-Infinity")
        );
        assert_eq!(flat(json!({"doubleValue": 1.5})), json!(1.5));
    }

    /// The instant is the unambiguous part; zone and accuracy are not worth a
    /// nested object per cell.
    #[test]
    fn a_timestamp_collapses_to_its_utc_instant() {
        assert_eq!(
            flat(
                json!({"timestampValue": {"googleTimestamp": "2026-01-01T00:00:00Z", "accuracy": 6}})
            ),
            json!("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            flat(
                json!({"timestampTzValue": {"googleTimestamp": "2026-01-01T00:00:00Z", "zone": "PST", "offset": -28800}})
            ),
            json!("2026-01-01T00:00:00Z")
        );
        // Nothing to collapse to: hand back the wrapper rather than a guess.
        assert_eq!(
            flat(json!({"timestampValue": {"accuracy": 6}})),
            json!({"accuracy": 6})
        );
    }

    /// A variant added upstream after this binary was built must still show
    /// its value; dropping the cell would silently lose a column.
    #[test]
    fn an_unknown_variant_passes_its_inner_value_through() {
        assert_eq!(flat(json!({"somethingNewValue": "v"})), json!("v"));
        assert_eq!(flat(json!({"nullValue": "NULL_VALUE"})), Value::Null);
        assert_eq!(flat(json!({"boolValue": true})), json!(true));
        assert_eq!(flat(json!({"bytesValue": "aGk="})), json!("aGk="));
        assert_eq!(flat(json!({"valueValue": {"a": [1]}})), json!({"a": [1]}));
        // Not a single-key object at all: as-is, so nothing is invented.
        assert_eq!(flat(json!("bare")), json!("bare"));
        assert_eq!(flat(json!({"a": 1, "b": 2})), json!({"a": 1, "b": 2}));
    }

    /// Asking for limit+1 is what makes `truncated` a fact instead of a
    /// guess: exactly `limit` rows back means the result set ended there.
    #[test]
    fn one_row_past_the_limit_flags_truncation_and_is_trimmed_off() {
        let (out, _) = build_output("db", "ro", &response_with_rows(3), 2).unwrap();
        assert_eq!(out["truncated"], json!(true));
        assert_eq!(out["rowCount"], json!(2));
        assert_eq!(out["rows"], json!([[0], [1]]));

        let (out, _) = build_output("db", "ro", &response_with_rows(2), 2).unwrap();
        assert_eq!(out["truncated"], json!(false));
        assert_eq!(out["rowCount"], json!(2));
    }

    /// A 200 response carrying `error` is a failed statement. Reported as a
    /// result, an agent reads the empty row set as "no matching rows".
    #[test]
    fn an_error_inside_a_successful_response_is_a_query_error() {
        let resp = json!({"results": [{"error": "syntax error near bad"}]});
        let err = build_output("db", "ro", &resp, 100)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "[QUERY_ERROR] syntax error near bad");
    }

    /// Extra result sets are announced, not dropped and not merged: merging
    /// would change the output shape for every caller.
    #[test]
    fn extra_result_sets_are_announced_and_only_the_first_is_shown() {
        let resp = json!({"results": [
            {"columnNames": ["a"], "rows": [{"values": [{"int64Value": "1"}]}]},
            {"columnNames": ["b"], "rows": [{"values": [{"int64Value": "2"}]}]},
        ]});
        let (out, notes) = build_output("db", "ro", &resp, 100).unwrap();
        assert_eq!(out["columns"], json!(["a"]));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("2 result sets"), "{notes:?}");
        assert!(notes[0].contains("one statement per call"), "{notes:?}");
    }

    /// A statement with no result set (DDL through the query path, say) still
    /// has to produce the documented shape, or a caller reading `rows` breaks.
    #[test]
    fn no_result_set_still_yields_the_full_output_shape() {
        let (out, notes) = build_output("db", "", &json!({}), 100).unwrap();
        assert!(notes.is_empty());
        assert_eq!(out["rows"], json!([]));
        assert_eq!(out["columns"], json!([]));
        assert_eq!(out["columnTypes"], json!([]));
        assert_eq!(out["rowCount"], json!(0));
        assert_eq!(out["truncated"], json!(false));
        assert_eq!(out["latencyMs"], json!(0));
        assert_eq!(out["database"], json!("db"));
    }

    /// Latency is a diagnostic: a value bbcli cannot read must not fail a
    /// query that succeeded.
    #[test]
    fn latency_parses_to_milliseconds_and_garbage_reads_as_zero() {
        assert_eq!(parse_latency_ms(Some("0.012s")), 12);
        assert_eq!(parse_latency_ms(Some("1.5s")), 1500);
        assert_eq!(parse_latency_ms(Some("2s")), 2000);
        assert_eq!(parse_latency_ms(Some("")), 0);
        assert_eq!(parse_latency_ms(Some("later")), 0);
        assert_eq!(parse_latency_ms(None), 0);
    }
}
