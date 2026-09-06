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

## Typical flows

Run a query. The database must be located first — resource names are
`instances/{instance}/databases/{database}` and cannot be guessed:

```bash
bbcli api DatabaseService/ListDatabases --args '{
  "parent": "workspaces/-",
  "filter": "name.contains(\"employee\")"
}'
# pick `name` from the response; take dataSourceId from
# instanceResource.dataSources, preferring type READ_ONLY over ADMIN

bbcli api DatabaseService/GetDatabaseMetadata --args '{
  "name": "instances/e1/databases/db/metadata"
}'                                    # inspect the schema before writing SQL

bbcli api SQLService/Query --args '{
  "name": "instances/e1/databases/db",
  "dataSourceId": "<id>",
  "statement": "SELECT 1"
}'
```

Read `bbcli skill query` for the full flow, including how masked values must
be presented.

Find and call any API:

```bash
bbcli search --service InstanceService
bbcli api InstanceService/GetInstance --args '{"name": "instances/e1"}'
```

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

- `invalid_grant` on refresh: the 30-day refresh token expired or was revoked —
  the user must re-run `bbcli login`. `bbcli status` distinguishes an expired
  access token (self-healing) from an expired refresh token (needs re-login).
- Every `api` call prints `Method -> server (source: ...)` on stderr. Check it
  when a multi-step task must stay on one environment; stdout is pure JSON.
- `--insecure` only helps with TLS failures, not auth ones.
- There is no request deadline by default, because queries and rollouts can
  run for minutes. Pass `--timeout <seconds>` to bound an unattended run — but
  a client timeout does not cancel server-side work, so query the resource's
  status before retrying a change.
