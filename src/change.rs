//! `bbcli change propose` — the five-call review flow for a database change,
//! as one command.
//!
//! Mirrors upstream's `backend/api/mcp/tool_change.go`: CreateSheet →
//! CreatePlan → RunPlanChecks → poll GetPlanCheckRun → CreateIssue, then
//! CreateRollout only when asked and only when the gates allow it. This is the
//! case a single-call wrapper cannot cover — every step consumes the resource
//! name the previous one minted, and getting the order or the parents wrong
//! leaves a half-built change behind.
//!
//! Two things it deliberately does not do. It does not clean up: a failure
//! names every resource created so far and stops, because deleting a sheet or
//! plan someone may want to inspect is not a decision a CLI should make. And
//! `nextAction` never names `ApproveIssue` — the agent hands the issue link to
//! a human instead of approving on their behalf.

use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::ApiClient;
use crate::resolve::{self, tool_error};

/// What the agent should do next. `AWAIT_HUMAN_APPROVAL` is a stop, not a
/// task: approving is the human's, so no value here names an approve call.
const AWAIT_HUMAN_APPROVAL: &str = "AWAIT_HUMAN_APPROVAL";
const CREATE_ROLLOUT: &str = "CREATE_ROLLOUT";
const MONITOR_ROLLOUT: &str = "MONITOR_ROLLOUT";
const WAIT_PLAN_CHECK: &str = "WAIT_PLAN_CHECK";
const FIX_SQL_AND_RETRY: &str = "FIX_SQL_AND_RETRY";

/// Why no rollout was created. Present whenever `rolloutCreated` is false, so
/// the caller never has to guess between "not asked for" and "refused".
const NOT_REQUESTED: &str = "NOT_REQUESTED";
const APPROVAL_PENDING: &str = "APPROVAL_PENDING";
const APPROVAL_REJECTED: &str = "APPROVAL_REJECTED";
const PLAN_CHECK_PENDING: &str = "PLAN_CHECK_PENDING";
const PLAN_CHECK_ERROR: &str = "PLAN_CHECK_ERROR";
const ROLLOUT_CREATE_FAILED: &str = "ROLLOUT_CREATE_FAILED";

const CHECK_DONE: &str = "DONE";
const CHECK_RUNNING: &str = "RUNNING";
const CHECK_FAILED: &str = "FAILED";

/// How long to wait for plan checks before reporting them as still running.
/// A change is worth a few seconds of waiting — the check result decides
/// whether a rollout may be created at all — but not an unbounded block.
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

    /// True when the checks are a reason not to roll out. A `FAILED` run is
    /// one too: nothing verified the statement, so proceeding would deploy
    /// unreviewed SQL.
    fn blocking(&self) -> bool {
        self.status == CHECK_FAILED
            || (self.status == CHECK_DONE && self.summary.as_ref().is_some_and(|s| s.error > 0))
    }
}

/// Runs the whole flow and returns the output document.
#[allow(clippy::too_many_arguments)]
pub async fn propose(
    client: &ApiClient,
    database: &str,
    sql: &str,
    title: &str,
    instance: Option<&str>,
    project: Option<&str>,
    rollout: bool,
    reason: Option<&str>,
) -> Result<Value> {
    let resolved = resolve::resolve(client, database, instance, project).await?;
    // The project comes from the resolved database, not from --project: that
    // flag only narrowed the resolution, and the sheet, plan and issue all
    // have to be parented to the project the database actually lives in.
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
    .map_err(|e| step_error("SHEET_CREATE_FAILED", &e, &[], None))?;

    let plan = create_named(
        client,
        "PlanService/CreatePlan",
        &json!({
            "parent": project_name,
            "plan": {
                "title": title,
                "specs": [{
                    "id": "spec-1",
                    "changeDatabaseConfig": {"targets": [resolved.name], "sheet": sheet},
                }],
            },
        }),
    )
    .await
    .map_err(|e| step_error("PLAN_CREATE_FAILED", &e, &[("sheet", &sheet)], None))?;

    let checks = run_plan_checks(client, &plan).await;

    let mut issue = json!({
        "title": title,
        "type": "DATABASE_CHANGE",
        "plan": plan,
    });
    if let Some(reason) = reason.filter(|r| !r.is_empty()) {
        issue["description"] = json!(reason);
    }
    let issue = client
        .call_announced(
            "IssueService/CreateIssue",
            &json!({"parent": project_name, "issue": issue}),
        )
        .await
        .map_err(|e| {
            // A failure here is very often the SQL review gate, which the plan
            // checks already reported. Say so, or the agent retries the same
            // statement against the same gate.
            let hint = checks.blocking().then_some(
                "plan checks must pass before an issue can be created; fix the SQL and retry",
            );
            step_error(
                "ISSUE_CREATE_FAILED",
                &e,
                &[("sheet", &sheet), ("plan", &plan)],
                hint,
            )
        })?;
    let approval = issue
        .get("approvalStatus")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let issue = resource_name(&issue).context("CreateIssue returned no resource name")?;

    let mut next_action = derive_next_action(&approval);
    let mut rollout_created = false;
    let mut rollout_name = None;
    let mut deferred = None;

    match rollout_decision(rollout, &checks, &approval) {
        Rollout::Deferred { reason, next } => {
            deferred = Some(reason);
            if let Some(next) = next {
                next_action = next;
            }
        }
        // The parent of a rollout is the plan, not the project — the catalog
        // says so, and the vendored guide's project-parent form is stale.
        Rollout::Attempt => match create_named(
            client,
            "RolloutService/CreateRollout",
            &json!({"parent": plan}),
        )
        .await
        {
            Ok(name) => {
                rollout_created = true;
                rollout_name = Some(name);
                next_action = MONITOR_ROLLOUT;
            }
            Err(e) => {
                // The change itself exists and is approved; only the rollout
                // failed. Warn and keep the approval-derived next action
                // rather than inventing one.
                eprintln!("warning: rollout creation failed: {e:#}");
                deferred = Some(ROLLOUT_CREATE_FAILED);
            }
        },
    }

    let server = client.server();
    let mut links = json!({
        "issue": format!("{server}/{issue}"),
        "plan": format!("{server}/{plan}"),
    });
    let mut output = json!({
        "database": resolved.name,
        "project": project_name,
        "sheet": sheet,
        "plan": plan,
        "planChecks": checks,
        "issue": issue,
        "rolloutCreated": rollout_created,
        "nextAction": next_action,
    });
    if let Some(rollout) = &rollout_name {
        links["rollout"] = json!(format!("{server}/{rollout}"));
        output["rollout"] = json!(rollout);
    }
    if let Some(deferred) = deferred {
        output["rolloutDeferredReason"] = json!(deferred);
    }
    output["links"] = links;
    Ok(output)
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
        // status is what decides whether a rollout is allowed.
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

/// What to do after the issue exists, from the approval the server assigned.
fn derive_next_action(approval: &str) -> &'static str {
    match approval {
        "APPROVED" | "SKIPPED" => CREATE_ROLLOUT,
        "REJECTED" => FIX_SQL_AND_RETRY,
        // PENDING, CHECKING, unset, or a status this binary does not know:
        // stop and let a human look. Guessing "go ahead" here would deploy a
        // change nobody approved.
        _ => AWAIT_HUMAN_APPROVAL,
    }
}

/// Whether to attempt the rollout, or why not.
#[derive(Debug, PartialEq)]
enum Rollout {
    Deferred {
        reason: &'static str,
        /// Set when the reason also changes what to do next.
        next: Option<&'static str>,
    },
    Attempt,
}

/// The gate order matters: the most specific blocker wins, so the reported
/// reason is the one a caller has to act on. Checks come before approval
/// because a failing check cannot be approved away.
fn rollout_decision(requested: bool, checks: &PlanCheckInfo, approval: &str) -> Rollout {
    if !requested {
        return Rollout::Deferred {
            reason: NOT_REQUESTED,
            next: None,
        };
    }
    if checks.status == CHECK_RUNNING {
        return Rollout::Deferred {
            reason: PLAN_CHECK_PENDING,
            next: Some(WAIT_PLAN_CHECK),
        };
    }
    if checks.blocking() {
        return Rollout::Deferred {
            reason: PLAN_CHECK_ERROR,
            next: Some(FIX_SQL_AND_RETRY),
        };
    }
    match approval {
        "PENDING" | "CHECKING" => Rollout::Deferred {
            reason: APPROVAL_PENDING,
            next: Some(AWAIT_HUMAN_APPROVAL),
        },
        "REJECTED" => Rollout::Deferred {
            reason: APPROVAL_REJECTED,
            next: Some(FIX_SQL_AND_RETRY),
        },
        _ => Rollout::Attempt,
    }
}

/// A step failure that names every resource already created.
///
/// Nothing is rolled back, so this list is the only record of what exists:
/// without it the next attempt either orphans a sheet and plan or duplicates
/// them. The agent or a human decides which.
fn step_error(
    code: &str,
    err: &anyhow::Error,
    created: &[(&str, &str)],
    hint: Option<&str>,
) -> anyhow::Error {
    let mut msg = format!("{err:#}");
    if !created.is_empty() {
        let refs: Vec<String> = created.iter().map(|(k, v)| format!("{k}={v}")).collect();
        msg.push_str(&format!("\n  created so far: {}", refs.join(", ")));
    }
    if let Some(hint) = hint {
        msg.push_str(&format!("\n  {hint}"));
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

    /// The agent must never approve on the user's behalf, so every status that
    /// is not already settled has to land on a stop. An unknown status is the
    /// dangerous case: treated as approval it would deploy unreviewed SQL.
    #[test]
    fn only_an_approved_or_skipped_issue_moves_on_without_a_human() {
        assert_eq!(derive_next_action("APPROVED"), CREATE_ROLLOUT);
        assert_eq!(derive_next_action("SKIPPED"), CREATE_ROLLOUT);
        assert_eq!(derive_next_action("REJECTED"), FIX_SQL_AND_RETRY);
        assert_eq!(derive_next_action("PENDING"), AWAIT_HUMAN_APPROVAL);
        assert_eq!(derive_next_action("CHECKING"), AWAIT_HUMAN_APPROVAL);
        assert_eq!(derive_next_action(""), AWAIT_HUMAN_APPROVAL);
        assert_eq!(derive_next_action("SOMETHING_NEW"), AWAIT_HUMAN_APPROVAL);
        // No next action may send the agent at an approve call.
        for status in ["APPROVED", "REJECTED", "PENDING", ""] {
            assert!(!derive_next_action(status).contains("APPROVE"));
        }
    }

    #[test]
    fn without_rollout_nothing_is_attempted_and_the_output_says_why() {
        assert_eq!(
            rollout_decision(false, &done(0, 0), "APPROVED"),
            Rollout::Deferred {
                reason: NOT_REQUESTED,
                next: None
            },
            "not asking for a rollout must not change the approval-derived next action"
        );
    }

    /// Checks still running are not a refusal, so the caller is told to wait
    /// rather than to fix anything.
    #[test]
    fn checks_still_running_defer_the_rollout_and_ask_for_a_wait() {
        let running = PlanCheckInfo::running("p/planCheckRun");
        assert_eq!(
            rollout_decision(true, &running, "APPROVED"),
            Rollout::Deferred {
                reason: PLAN_CHECK_PENDING,
                next: Some(WAIT_PLAN_CHECK)
            }
        );
    }

    /// A failing check cannot be approved away, so it outranks the approval
    /// status — otherwise an approved-but-broken change would roll out.
    #[test]
    fn check_errors_outrank_an_approval_and_send_the_agent_back_to_the_sql() {
        assert_eq!(
            rollout_decision(true, &done(1, 0), "APPROVED"),
            Rollout::Deferred {
                reason: PLAN_CHECK_ERROR,
                next: Some(FIX_SQL_AND_RETRY)
            }
        );
        // A run that failed outright verified nothing, which blocks too.
        assert_eq!(
            rollout_decision(true, &PlanCheckInfo::failed(), "APPROVED"),
            Rollout::Deferred {
                reason: PLAN_CHECK_ERROR,
                next: Some(FIX_SQL_AND_RETRY)
            }
        );
        // Warnings are not errors and must not block.
        assert_eq!(
            rollout_decision(true, &done(0, 3), "APPROVED"),
            Rollout::Attempt
        );
    }

    #[test]
    fn a_pending_approval_defers_the_rollout_to_the_human() {
        for status in ["PENDING", "CHECKING"] {
            assert_eq!(
                rollout_decision(true, &done(0, 0), status),
                Rollout::Deferred {
                    reason: APPROVAL_PENDING,
                    next: Some(AWAIT_HUMAN_APPROVAL)
                },
                "{status}"
            );
        }
    }

    #[test]
    fn a_rejected_approval_defers_the_rollout_and_names_the_rejection() {
        assert_eq!(
            rollout_decision(true, &done(0, 0), "REJECTED"),
            Rollout::Deferred {
                reason: APPROVAL_REJECTED,
                next: Some(FIX_SQL_AND_RETRY)
            }
        );
    }

    #[test]
    fn an_approved_change_with_clean_checks_is_eligible_for_a_rollout() {
        assert_eq!(
            rollout_decision(true, &done(0, 0), "APPROVED"),
            Rollout::Attempt
        );
        assert_eq!(
            rollout_decision(true, &done(0, 0), "SKIPPED"),
            Rollout::Attempt
        );
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
        assert!(info.blocking(), "errors must block a rollout");
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

        let sheet_failed = step_error("SHEET_CREATE_FAILED", &cause, &[], None).to_string();
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
            None,
        )
        .to_string();
        assert!(
            plan_failed.contains("created so far: sheet=projects/hr/sheets/1"),
            "{plan_failed}"
        );

        let issue_failed = step_error(
            "ISSUE_CREATE_FAILED",
            &cause,
            &[
                ("sheet", "projects/hr/sheets/1"),
                ("plan", "projects/hr/plans/1"),
            ],
            Some("plan checks must pass before an issue can be created; fix the SQL and retry"),
        )
        .to_string();
        assert!(
            issue_failed
                .contains("created so far: sheet=projects/hr/sheets/1, plan=projects/hr/plans/1"),
            "{issue_failed}"
        );
        assert!(
            issue_failed.contains("plan checks must pass"),
            "{issue_failed}"
        );
        // The server's own code survives inside bbcli's: it is what decides
        // whether to ask for access or fix the request.
        assert!(
            issue_failed.contains("[permission_denied]"),
            "{issue_failed}"
        );
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
