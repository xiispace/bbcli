//! `bbcli change propose` — sheet, plan and plan checks for a database
//! change, as one command.
//!
//! Follows the first half of upstream's `backend/api/mcp/tool_change.go`:
//! CreateSheet → CreatePlan → RunPlanChecks → poll GetPlanCheckRun, and stops
//! at the plan. This is the case a single-call wrapper cannot cover — each
//! step consumes the resource name the previous one minted, and the check
//! poll is what turns "the plan exists" into "the plan is fit to go further".
//!
//! Upstream goes on to CreateIssue and, when asked, CreateRollout. bbcli does
//! not: in practice the plan is where people pick the change up, and an issue
//! created on every proposal is one nobody asked for. Opening one is a single
//! `IssueService/CreateIssue` call on the plan, which is `bbcli api`'s job.
//!
//! It does not clean up: a failure names every resource created so far and
//! stops, because deleting a sheet someone may want to inspect is not a
//! decision a CLI should make.

use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::ApiClient;
use crate::resolve::{self, tool_error};

/// What the agent should do next. None of them is "approve" or "roll out":
/// past the plan, the change belongs to the review flow and its humans.
const CREATE_ISSUE: &str = "CREATE_ISSUE";
const WAIT_PLAN_CHECK: &str = "WAIT_PLAN_CHECK";
const FIX_SQL_AND_RETRY: &str = "FIX_SQL_AND_RETRY";

const CHECK_DONE: &str = "DONE";
const CHECK_RUNNING: &str = "RUNNING";
const CHECK_FAILED: &str = "FAILED";

/// How long to wait for plan checks before reporting them as still running.
/// A change is worth a few seconds of waiting — the check result decides
/// whether the plan is worth taking further — but not an unbounded block.
const POLL_BUDGET: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PlanCheckInfo {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<PlanCheckSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    results: Vec<PlanCheckResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_check_run: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
struct PlanCheckSummary {
    error: usize,
    warning: usize,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PlanCheckResult {
    r#type: &'static str,
    message: String,
}

impl PlanCheckInfo {
    fn running(check_run: &str) -> Self {
        Self {
            status: CHECK_RUNNING,
            summary: None,
            results: Vec::new(),
            plan_check_run: Some(check_run.to_string()),
        }
    }

    fn failed() -> Self {
        Self {
            status: CHECK_FAILED,
            summary: None,
            results: Vec::new(),
            plan_check_run: None,
        }
    }

    /// True when the checks are a reason not to take the plan further. A
    /// `FAILED` run is one too: nothing verified the statement, so proceeding
    /// would send unreviewed SQL on.
    fn blocking(&self) -> bool {
        self.status == CHECK_FAILED
            || (self.status == CHECK_DONE && self.summary.as_ref().is_some_and(|s| s.error > 0))
    }
}

/// Runs the whole flow and returns the output document.
pub async fn propose(
    client: &ApiClient,
    database: &str,
    sql: &str,
    title: &str,
    instance: Option<&str>,
    project: Option<&str>,
    reason: Option<&str>,
) -> Result<Value> {
    let resolved = resolve::resolve(client, database, instance, project).await?;
    // The project comes from the resolved database, not from --project: that
    // flag only narrowed the resolution, and the sheet and plan both have to
    // be parented to the project the database actually lives in.
    let project_name = resolved.project.clone();

    let sheet = create_named(
        client,
        "SheetService/CreateSheet",
        &json!({
            "parent": project_name,
            "sheet": {"content": sheet_content(sql)},
        }),
    )
    .await
    .map_err(|e| step_error("SHEET_CREATE_FAILED", &e, &[]))?;

    let mut plan = json!({
        "title": title,
        "specs": [{
            "id": "spec-1",
            "changeDatabaseConfig": {"targets": [resolved.name], "sheet": sheet},
        }],
    });
    if let Some(reason) = reason.filter(|r| !r.is_empty()) {
        plan["description"] = json!(reason);
    }
    let plan = create_named(
        client,
        "PlanService/CreatePlan",
        &json!({"parent": project_name, "plan": plan}),
    )
    .await
    .map_err(|e| step_error("PLAN_CREATE_FAILED", &e, &[("sheet", &sheet)]))?;

    let checks = run_plan_checks(client, &plan).await;
    let next_action = derive_next_action(&checks);

    Ok(json!({
        "database": resolved.name,
        "project": project_name,
        "sheet": sheet,
        "plan": plan,
        "planChecks": checks,
        "nextAction": next_action,
        "links": {"plan": format!("{}/{plan}", client.server())},
    }))
}

/// Calls a create method and returns the new resource's name.
async fn create_named(client: &ApiClient, method: &str, args: &Value) -> Result<String> {
    let resp = client.call_announced(method, args).await?;
    resource_name(&resp).with_context(|| format!("{method} returned no resource name"))
}

fn resource_name(resp: &Value) -> Option<String> {
    resp.get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The sheet carries the statement as standard base64 of its exact bytes.
/// Anything else (URL-safe, wrapped, re-encoded text) produces a sheet whose
/// content is not the SQL the user wrote.
fn sheet_content(sql: &str) -> String {
    STANDARD.encode(sql.as_bytes())
}

/// Triggers plan checks and waits out the budget for a verdict.
async fn run_plan_checks(client: &ApiClient, plan: &str) -> PlanCheckInfo {
    let check_run = format!("{plan}/planCheckRun");

    // Ignore the trigger's own failure: CreatePlan already starts plan checks
    // server-side, so the run may well exist regardless, and bailing here
    // would report RUNNING for checks that are already done.
    let _ = client
        .call_announced("PlanService/RunPlanChecks", &json!({"name": plan}))
        .await;

    // One attribution line for the whole poll, not one per tick: the method
    // and server are what an agent needs to reproduce it with `api`, and ten
    // identical lines would bury the rest of the trace.
    client.announce("PlanService/GetPlanCheckRun");
    eprintln!(
        "  polling for up to {}s until the plan checks finish",
        POLL_BUDGET.as_secs()
    );
    let deadline = tokio::time::Instant::now() + POLL_BUDGET;
    while tokio::time::Instant::now() < deadline {
        // A poll error is transient by assumption (the row is not visible
        // yet, a brief 500) and retried inside the budget: the run's real
        // status is what decides the next action.
        if let Ok(resp) = client
            .call("PlanService/GetPlanCheckRun", &json!({"name": check_run}))
            .await
        {
            match resp.get("status").and_then(Value::as_str).unwrap_or("") {
                CHECK_DONE => return build_plan_check_info(&resp, &check_run),
                CHECK_FAILED | "CANCELED" => return PlanCheckInfo::failed(),
                _ => {} // RUNNING or unknown: keep waiting
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    PlanCheckInfo::running(&check_run)
}

/// Summarises a completed run. SUCCESS entries are dropped: a list of things
/// that went right costs context and changes no decision.
fn build_plan_check_info(run: &Value, check_run: &str) -> PlanCheckInfo {
    let mut summary = PlanCheckSummary {
        error: 0,
        warning: 0,
    };
    let mut results = Vec::new();
    let entries = run
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for r in entries {
        // `title` is the one-line verdict; `content` is the fallback when a
        // check reports only prose.
        let message = ["title", "content"]
            .iter()
            .filter_map(|k| r.get(*k).and_then(Value::as_str))
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_string();
        let r#type = match r.get("status").and_then(Value::as_str).unwrap_or("") {
            "ERROR" => {
                summary.error += 1;
                "ERROR"
            }
            "WARNING" => {
                summary.warning += 1;
                "WARNING"
            }
            _ => continue,
        };
        results.push(PlanCheckResult { r#type, message });
    }
    PlanCheckInfo {
        status: CHECK_DONE,
        summary: Some(summary),
        results,
        plan_check_run: Some(check_run.to_string()),
    }
}

/// What to do with the plan, from its checks. Only a clean or warning-only
/// verdict sends the change on; checks still running are a wait, not a
/// refusal, so the agent is not sent to rewrite SQL that may be fine.
fn derive_next_action(checks: &PlanCheckInfo) -> &'static str {
    if checks.status == CHECK_RUNNING {
        WAIT_PLAN_CHECK
    } else if checks.blocking() {
        FIX_SQL_AND_RETRY
    } else {
        CREATE_ISSUE
    }
}

/// A step failure that names every resource already created.
///
/// Nothing is rolled back, so this list is the only record of what exists:
/// without it the next attempt either orphans a sheet or duplicates it. The
/// agent or a human decides which.
fn step_error(code: &str, err: &anyhow::Error, created: &[(&str, &str)]) -> anyhow::Error {
    let mut msg = format!("{err:#}");
    if !created.is_empty() {
        let refs: Vec<String> = created.iter().map(|(k, v)| format!("{k}={v}")).collect();
        msg.push_str(&format!("\n  created so far: {}", refs.join(", ")));
    }
    tool_error(code, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(error: usize, warning: usize) -> PlanCheckInfo {
        PlanCheckInfo {
            status: CHECK_DONE,
            summary: Some(PlanCheckSummary { error, warning }),
            results: Vec::new(),
            plan_check_run: Some("p/planCheckRun".to_string()),
        }
    }

    /// Warnings are advice, not a verdict: a plan with only warnings goes on
    /// to review like a clean one, or every index hint would stall a change.
    #[test]
    fn clean_or_warning_only_checks_send_the_plan_on_to_an_issue() {
        assert_eq!(derive_next_action(&done(0, 0)), CREATE_ISSUE);
        assert_eq!(derive_next_action(&done(0, 3)), CREATE_ISSUE);
    }

    /// Checks still running are not a refusal, so the caller is told to wait
    /// rather than to rewrite SQL that may well be fine.
    #[test]
    fn checks_still_running_ask_for_a_wait_not_a_fix() {
        let running = PlanCheckInfo::running("p/planCheckRun");
        assert_eq!(derive_next_action(&running), WAIT_PLAN_CHECK);
    }

    /// An error means the SQL is wrong, and a run that failed outright
    /// verified nothing — both send the agent back to the statement instead
    /// of on to review.
    #[test]
    fn check_errors_or_a_failed_run_send_the_agent_back_to_the_sql() {
        assert_eq!(derive_next_action(&done(1, 0)), FIX_SQL_AND_RETRY);
        assert_eq!(
            derive_next_action(&PlanCheckInfo::failed()),
            FIX_SQL_AND_RETRY
        );
    }

    /// Past the plan the change belongs to humans, so no next action may send
    /// the agent at an approve or a rollout call.
    #[test]
    fn no_next_action_approves_or_rolls_out() {
        for checks in [
            done(0, 0),
            done(1, 0),
            PlanCheckInfo::failed(),
            PlanCheckInfo::running("p"),
        ] {
            let next = derive_next_action(&checks);
            assert!(
                !next.contains("APPROVE") && !next.contains("ROLLOUT"),
                "{next}"
            );
        }
    }

    /// Only the entries that change a decision survive. A list of successful
    /// checks costs context and tells the agent nothing to act on.
    #[test]
    fn plan_checks_count_errors_and_warnings_and_drop_the_successes() {
        let run = json!({"status": "DONE", "results": [
            {"status": "SUCCESS", "title": "all good"},
            {"status": "WARNING", "title": "no index"},
            {"status": "ERROR", "title": "", "content": "column does not exist"},
            {"status": "ERROR", "title": "naming convention", "content": "ignored"},
        ]});
        let info = build_plan_check_info(&run, "p/planCheckRun");
        assert_eq!(info.status, CHECK_DONE);
        assert_eq!(
            info.summary,
            Some(PlanCheckSummary {
                error: 2,
                warning: 1
            })
        );
        assert_eq!(info.results.len(), 3, "{:?}", info.results);
        assert_eq!(info.results[0].r#type, "WARNING");
        assert_eq!(info.results[0].message, "no index");
        // An empty title falls back to content, so a check never reports a
        // blank message.
        assert_eq!(info.results[1].message, "column does not exist");
        // ...and a present title wins over content.
        assert_eq!(info.results[2].message, "naming convention");
        assert!(info.blocking(), "errors must stop the plan going further");
        assert_eq!(info.plan_check_run.as_deref(), Some("p/planCheckRun"));

        let clean = build_plan_check_info(&json!({"status": "DONE"}), "p/planCheckRun");
        assert!(clean.results.is_empty());
        assert!(!clean.blocking());
        assert_eq!(
            serde_json::to_value(&clean).unwrap(),
            json!({"status": "DONE", "summary": {"error": 0, "warning": 0},
                   "planCheckRun": "p/planCheckRun"}),
            "an empty results list is omitted, not printed as []"
        );
    }

    /// Nothing is cleaned up, so the error is the only record of what exists.
    /// Without these names the next attempt orphans or duplicates them.
    #[test]
    fn a_step_failure_names_every_resource_created_so_far() {
        let cause = anyhow::anyhow!("HTTP 403 [permission_denied]: nope");

        let sheet_failed = step_error("SHEET_CREATE_FAILED", &cause, &[]).to_string();
        assert!(
            sheet_failed.starts_with("[SHEET_CREATE_FAILED]"),
            "{sheet_failed}"
        );
        assert!(
            !sheet_failed.contains("created so far"),
            "nothing existed yet: {sheet_failed}"
        );

        let plan_failed = step_error(
            "PLAN_CREATE_FAILED",
            &cause,
            &[("sheet", "projects/hr/sheets/1")],
        )
        .to_string();
        assert!(
            plan_failed.contains("created so far: sheet=projects/hr/sheets/1"),
            "{plan_failed}"
        );
        // The server's own code survives inside bbcli's: it is what decides
        // whether to ask for access or fix the request.
        assert!(plan_failed.contains("[permission_denied]"), "{plan_failed}");
    }

    /// The sheet is the statement. Any other encoding stores something that is
    /// not the SQL the user wrote, and the change would apply that instead.
    #[test]
    fn sheet_content_is_standard_base64_of_the_exact_sql_bytes() {
        assert_eq!(
            sheet_content("ALTER TABLE t ADD c int"),
            "QUxURVIgVEFCTEUgdCBBREQgYyBpbnQ="
        );
        assert_eq!(
            STANDARD
                .decode(sheet_content("SELECT 'ü', \"x\";\n"))
                .unwrap(),
            "SELECT 'ü', \"x\";\n".as_bytes(),
            "multi-byte and quoted SQL must round-trip byte for byte"
        );
        // Standard alphabet, not URL-safe: the server decodes the standard one.
        assert_eq!(sheet_content("\u{fb}\u{ff}"), "w7vDvw==");
    }
}
