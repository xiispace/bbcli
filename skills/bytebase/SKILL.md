---
name: bytebase
description: Interact with a Bytebase server via the bbcli CLI — query databases, inspect schemas, call APIs, propose database changes, grant permissions. Use when the user mentions Bytebase, asks to run SQL against a Bytebase-managed database, review or create database changes, or manage database access.
---

# Bytebase via bbcli

`bbcli` calls the Bytebase v1 API directly (Connect protocol); OAuth2 tokens
and refresh are handled automatically. `search` and `skill` are offline and
need no login.

## Prerequisites

Check the setup before doing real work:

```bash
bbcli config check
```

It verifies connectivity and credentials and exits non-zero when unusable. If
it fails with "not logged in" (or credentials are missing), ask the user to
run once: `bbcli login --context <bytebase-url>` (add `--insecure` for
self-signed TLS). Do not attempt to handle OAuth yourself.

`login` is interactive and needs a person at a browser, so leave it to the
user. If this host has no browser, tell them `bbcli login` prints an
authorization URL they can open anywhere: the redirect fails to load and they
paste that failed address back into the prompt. No port forwarding.

`bbcli config view` shows the effective server and all logged-in ones; switch
the default with `bbcli config use <url>`.

## Typical flows

Three commands cover the common work and resolve the database themselves, so
you never have to look up `instances/{instance}/databases/{database}` first.
Pass the name the user says (`employee`), a substring of it, or the full
resource name if you already have one.

Inspect a schema, then read from it:

```bash
bbcli schema employee                  # tables, row counts, column counts
bbcli schema employee --table orders   # one table: columns, indexes, foreign keys
bbcli schema employee --include columns   # every table with its columns

bbcli query employee 'SELECT count(*) FROM orders'
bbcli query employee 'SELECT * FROM orders WHERE total > 100' --limit 500
```

`query` prints `{database, dataSourceId, columns, columnTypes, rows, rowCount,
truncated, latencyMs}`. `truncated: true` means there were more rows than
`--limit`; raise it or add a `WHERE`. Read `bbcli skill query` for the full
flow, including how masked values must be presented.

Propose a schema change — this creates a sheet, a plan, plan checks and an
issue in one command:

```bash
bbcli change propose employee \
  --sql 'ALTER TABLE orders ADD COLUMN note text' \
  --title 'Add orders.note' --reason 'TICKET-1234'
```

Read `nextAction` in the output and stop there:

| `nextAction` | What to do |
|---|---|
| `AWAIT_HUMAN_APPROVAL` | Stop. Give the user `links.issue` and let them approve. |
| `CREATE_ROLLOUT` | Approved already: re-run with `--rollout`. |
| `MONITOR_ROLLOUT` | The rollout exists; watch it with `bbcli api RolloutService/GetRollout`. |
| `WAIT_PLAN_CHECK` | Checks were still running; re-run in a moment. |
| `FIX_SQL_AND_RETRY` | A plan check failed or the issue was rejected — read `planChecks.results`. |

Narrow an ambiguous database name with `--instance <id>` or `--project <id>`;
both flags work on all three commands.

Anything else — instances, environments, users, policies, rollouts — goes
through `api`:

```bash
bbcli search --service InstanceService
bbcli api InstanceService/GetInstance --args '{"name": "instances/e1"}'
```

## Rules

- **One statement per `query` call.** Extra result sets are dropped with a
  note on stderr; send separate calls instead.
- **Never approve an issue on the user's behalf.** `AWAIT_HUMAN_APPROVAL`
  means stop and hand `links.issue` to the user — do not call `ApproveIssue`.
- **`created so far:` in an error is a list of real resources.** `change
  propose` rolls nothing back, so those sheets and plans still exist: reuse
  them or tell the user to clean them up, but do not assume a retry starts
  from nothing.
- **Never guess a resource name.** If a command cannot resolve one, list the
  collection with `api` rather than inventing a name.

## Discover APIs (offline, no server)

```bash
bbcli search                                 # all services
bbcli search --service SQLService            # methods of a service
bbcli search --operation-id SQLService/Query # request fields of a method
bbcli search --schema QueryRequest           # one message type
```

Always look up the request fields before calling — never guess field names.
Field names are camelCase. Read the indented continuation lines under a
field: that is where resource-name formats and constraints live
(`Format: instances/{instance}/databases/{databaseName}`). A field marked
`(optional)` is proto3 `optional`, not a different type.

The catalog is a snapshot of the Bytebase API at build time; `bbcli --version`
names the commit it came from.

## Call an API

```bash
bbcli api <Service/Method> --args '{"key": "value"}'
```

- `--args` must be a JSON object matching the method's request fields.
- Large payloads (e.g. base64 sheet content): `bbcli api <Service/Method>
  --args-file -` with the JSON on stdin.
- The response prints as JSON on stdout. Non-zero exit means the call failed —
  stderr carries the server's message.

## Task guides (offline)

```bash
bbcli skill query               # running SQL
bbcli skill database-change     # schema changes / migrations via review flow
bbcli skill grant-permission    # RBAC / access control
```

Read the relevant guide before attempting a multi-step task. Guides are
written in MCP tool syntax; `bbcli skill <name>` prints the MCP→bbcli command
translation at the top of every guide.

## Server selection

`--context <name-or-url>` (or env `BBCLI_SERVER`) for one command — names come
from `bbcli login --as <name>`; otherwise the nearest `.bbcli` file or
the global default applies. `bbcli config view` shows the effective server
and all contexts; `bbcli config use <name>` switches the default.

## Troubleshooting

A failed call prints the Connect code in brackets; the code determines the
next step, so read it rather than the prose:

| Code | What to do |
|---|---|
| `unauthenticated` | Ask the user to re-run `bbcli login`. Do not retry. |
| `permission_denied` | The account lacks the role — see `bbcli skill grant-permission`. Do not retry as-is. |
| `invalid_argument` | Re-check fields with `bbcli search --operation-id <Service/Method>`. |
| `not_found` | The resource name is wrong; list the parent collection to get a real one. |
| `unimplemented` | The server is older or newer than the embedded catalog (`bbcli --version`). |
| `unavailable`, `deadline_exceeded` | Transient; retrying may work. |

`query`, `schema` and `change propose` can also refuse before reaching the
server. Those codes are UPPER_SNAKE, so the case tells you who refused —
lowercase is Bytebase, uppercase is bbcli:

| Code | What to do |
|---|---|
| `AMBIGUOUS_TARGET` | Several databases match. Add `--instance`/`--project`, or pass a full resource name from the listed candidates. Never pick one at random. |
| `DATABASE_NOT_FOUND` | Nothing matched. List them: `bbcli api DatabaseService/ListDatabases --args '{"parent": "workspaces/-"}'`. |
| `TABLE_NOT_FOUND` | Re-run `bbcli schema <database>` without `--table` to see what exists; the error also lists near-miss candidates. |
| `AMBIGUOUS_TABLE` | That table name exists in several schemas — add `--schema <one of the listed>`. |
| `QUERY_ERROR` | The server ran the statement and it failed. Fix the SQL; do not retry unchanged. |
| `SHEET_CREATE_FAILED`, `PLAN_CREATE_FAILED`, `ISSUE_CREATE_FAILED` | Read the Connect code quoted inside the message — that is the real cause. Anything under `created so far:` already exists; do not recreate it. |

- `invalid_grant` on refresh: the 30-day refresh token expired or was revoked —
  the user must re-run `bbcli login`. `bbcli status` distinguishes an expired
  access token (self-healing) from an expired refresh token (needs re-login).
- Every call prints `Method -> server (source: ...)` on stderr — including
  each underlying call a friendly command makes, so you can see which methods
  to reach for with `api`. Check it when a multi-step task must stay on one
  environment; stdout is pure JSON on success and empty on failure.
- `--insecure` only helps with TLS failures, not auth ones.
- There is no request deadline by default, because queries and rollouts can
  run for minutes. Pass `--timeout <seconds>` to bound an unattended run — but
  a client timeout does not cancel server-side work, so query the resource's
  status before retrying a change.
