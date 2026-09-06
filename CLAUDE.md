# bbcli

A CLI for a Bytebase server, built to be driven by coding agents (Claude Code
and friends) through plain Bash. `bbcli api` speaks the [Connect JSON
protocol](https://connectrpc.com/docs/protocol) straight to Bytebase's v1 API;
`bbcli search` and `bbcli skill` serve a vendored API catalog and task guides
offline. The agent learns the surface from `skills/bytebase/SKILL.md`, which
`bbcli install-skill` writes into the agent's skills directory.

Layout: `src/main.rs` (clap dispatch) → `src/client.rs` (Connect calls, token
refresh) ← `src/oauth.rs` (registration, PKCE, token exchange) +
`src/store.rs` (locked credential/config files). `src/search.rs` reads the
embedded OpenAPI catalog; `src/agent_skill.rs` installs the embedded skill.
The friendly subcommands live one per file, each mirroring the upstream MCP
tool it stands in for: `src/resolve.rs` (database short name → resource name
+ data source; shared), `src/query.rs` (`query_database`), `src/schema.rs`
(`get_schema`), `src/change.rs` (`propose_database_change`). They compose
`client::ApiClient` calls and never speak HTTP themselves.

## Design constraints (do not revisit without discussion)

These are settled trade-offs, not gaps waiting to be filled.

- **No MCP layer.** Bytebase serves every v1 service as a Connect handler on
  its main HTTP port (`backend/server/grpc_routes.go`), and the connect auth
  interceptor accepts the same OAuth2 audience the `/mcp` endpoint does. So
  bbcli posts `/bytebase.v1.{Service}/{Method}` directly: no MCP session, no
  JSON-RPC envelope, one round trip per command. bbcli is also deliberately
  **not registered as an MCP server** with any agent host — a host that
  registers one loads every tool schema into the model's context on every
  turn. A skill loads lazily instead, and the agent shells out.

- **The catalog is vendored, not fetched.** `vendor/bytebase/` holds a
  verbatim copy of `backend/api/mcp/` (the OpenAPI catalog and the same task
  guides the MCP `search_api` / `get_skill` tools serve), embedded with
  `include_str!` at build time. The build therefore needs nothing but this
  repository, and API discovery costs no round trip. **Never hand-edit
  anything under `vendor/`** — it must stay diffable against upstream. Re-sync
  with `scripts/sync_vendor.sh /path/to/bytebase`, which also stamps the
  source commit into `vendor/bytebase/COMMIT` (compiled into
  `bbcli --version`) and `SOURCE.md`.

- **Credentials live in a locked file, not an OS keychain.** The problem worth
  solving here is not local secrecy — it is that Bytebase's refresh tokens are
  **single-use and rotated on every refresh**, so concurrent clients sharing
  one credential race the rotation into forced browser re-logins. A keychain
  does not solve that; an exclusive file lock does. See the invariant below.

- **No unattended machine-identity flow.** `login` needs a browser somewhere
  and a person at it. The browser does not have to be on this host (the
  redirect can be pasted back), but there is no client-credentials path.
  bbcli targets interactive agents, not CI.

- **Unary RPCs only.** Connect JSON streaming endpoints are out of scope;
  one-shot CLI commands rarely want them.

- **`install-skill` has no host table.** One default path
  (`~/.claude/skills/bytebase/SKILL.md`) plus `--dest` for everything else —
  project-level installs and other agent hosts included. Add a host enum only
  when a second host actually needs different skill *content*, not merely a
  different path.

- **Friendly subcommands must earn their place.** `bbcli api` reaches every
  method, so a dedicated subcommand has to prove it is not the same call with
  renamed flags. Add one only when at least one of these holds:
  (a) it chains two or more API calls and threads state between them
  (`change propose`: sheet → plan → plan checks → issue → rollout);
  (b) it reshapes a response the model cannot read economically (`query`
  flattens `RowValue` oneofs; `schema` summarises and truncates metadata);
  (c) it resolves a resource name the model would otherwise look up on every
  task (database short name → `instances/{i}/databases/{d}` + `dataSourceId`).
  A single-call wrapper fails all three — `list-databases`, `get-issue` and
  their kin are `bbcli api`. Two hard rules for the ones that qualify: their
  parameter names mirror the upstream MCP tool they stand in for
  (`query_database`, `get_schema`, `propose_database_change`), so the vendored
  guides read without translation; and every underlying call prints the same
  `Method -> server (source: ...)` line `api` does, so the escape hatch stays
  learnable and an agent can always fall back to it. Where upstream's MCP
  server found `call_api` sufficient, so does bbcli — `grant-permission` stays
  a guide. The burden of proof is on the new subcommand. There is also no
  second argument syntax (`--arg k=v`): request bodies nest
  (`plan.specs[].changeDatabaseConfig.targets`), and `--args` /
  `--args-file -` already take JSON.

## Non-obvious invariants

- **The refresh race.** `store::edit_tokens` holds the token file's exclusive
  lock across the whole read-refresh-write sequence, `.await`s included, and
  `client::refresh_locked` re-reads the file *inside* that critical section
  before deciding to refresh. That ordering is the whole mechanism: the loser
  of a race blocks, adopts the winner's rotated token, and skips its own
  network refresh instead of burning a dead single-use token. Lock order is
  always memory `Mutex` → file lock, matching `login`'s writer. Do not hoist
  the refresh out of the lock, and do not replace the in-place locked rewrite
  with an atomic rename — renaming moves the file out from under other
  processes' locks.

- **Refresh-token expiry is a local estimate.** The server issues 30-day
  refresh tokens (`backend/api/oauth2/oauth2.go: refreshTokenExpiry`) but does
  not return the lifetime in the token response, so `refresh_expires_at` is
  issue time + 30 days. `bbcli status` must keep distinguishing an expired
  *access* token (self-healing on next use) from an expired *refresh* token
  (needs a new browser login) — they are not the same event and must never
  share a message.

- **stdout is pure JSON.** Every diagnostic goes to stderr, including the
  `Method -> server (source: ...)` line every `api` call prints. That line is
  how a multi-step agent run confirms it hit the environment it meant to;
  keep it, and keep it on stderr.

- **SIGPIPE is reset to `SIG_DFL` in `main`.** Rust ignores it by default,
  which turns `bbcli ... | head` into a panic.

- **`--timeout` is unset by default, deliberately.** Queries and rollouts can
  legitimately run for minutes. A client-side deadline also does *not* cancel
  server-side work, so the timeout error must keep saying so — otherwise an
  agent retries a change that already took effect.

- **Connect errors keep `code` and `details`, not just `message`.** The code
  decides the next action (re-login / fix fields / request access / retry), so
  `client::recovery_hint` maps each code to the one action that resolves it.
  An agent should never have to infer intent from prose.

- **Two families of error codes, told apart by case.** Connect codes from the
  server stay lowercase (`[permission_denied]`) and pass through
  `client::call` unchanged. Codes the friendly subcommands raise themselves
  are UPPER_SNAKE and named after upstream's (`[AMBIGUOUS_TARGET]`,
  `[DATABASE_NOT_FOUND]`, `[TABLE_NOT_FOUND]`, `[AMBIGUOUS_TABLE]`,
  `[QUERY_ERROR]`, `[SHEET_CREATE_FAILED]`, `[PLAN_CREATE_FAILED]`,
  `[ISSUE_CREATE_FAILED]`). The case tells the agent who refused: bbcli's own
  resolution, or the server. Both go to stderr with exit 1; stdout stays
  JSON-on-success only.

- **The resolver never picks for the agent.** A full
  `instances/{i}/databases/{d}` name skips the listing (one `GetDatabase`);
  a short name is listed with `name.contains` and matched in tiers — exact,
  then case-insensitive, then substring. The listing parent is the concrete
  `workspaces/{id}`, fetched with one `GetWorkspace` on `workspaces/-`:
  `GetWorkspace` is the only method whose request documents that wildcard,
  and a real server answers `permission_denied: workspace mismatch` when
  `ListDatabases` is handed it — which reads to an agent like a missing role
  rather than a malformed parent. Every hint that prints a listing command
  spells the resolved id for the same reason. More than one survivor is
  `AMBIGUOUS_TARGET` with every candidate's full name, engine and project;
  bbcli does not choose, because a wrong guess runs SQL against a database
  nobody named. Data source preference is READ_ONLY over ADMIN, and the
  chosen id is part of the output so the agent can hand it to `api`.

- **`query` asks for `limit + 1` rows and trims to `limit`.** That is what
  makes `truncated` exact instead of "maybe", and it bounds the payload. Only
  the first result set is flattened — one statement per call is the
  contract; extra result sets are announced on stderr rather than silently
  dropped or allowed to change the output shape. `int64`/`uint64` arrive as
  protojson strings and become JSON numbers only when they fit (`serde_json`
  holds i64/u64 exactly); timestamps collapse to the UTC RFC 3339 string in
  `googleTimestamp`, dropping zone and offset because the instant is the
  unambiguous value. A `QueryResult.error` inside a 200 response is a
  failure (`QUERY_ERROR`), not a result.

- **`schema` picks detail client-side and truncates server-side.**
  `--include` defaults to `summary`, or `details` when `--table` is given. In
  `columns`/`details` bulk modes it asks the server for 201 tables per schema
  and trims to 200, so `truncated` is exact (the `query` trick again);
  `summary` is uncapped because the per-table payload is tiny and a silent
  cap would hide tables. The multi-schema engine list is client-side and
  copied from upstream: on MySQL-family engines `--schema` is dropped with a
  stderr note, because the server applies `schema == "x"` as an exact match
  and would return zero tables. Primary-key columns come from the index with
  `primary: true`; `ColumnMetadata` has no such flag.

- **`change propose` leaves what it created.** The sequence is CreateSheet →
  CreatePlan → RunPlanChecks (its failure is ignored: CreatePlan already
  starts checks server-side) → poll `GetPlanCheckRun` for at most 10 s (announced once, not per tick:
  ten identical attribution lines would bury the trace) →
  CreateIssue → CreateRollout only with `--rollout` and only when checks and
  approval allow it. A failure at any step names every resource created so
  far (`created so far: sheet=..., plan=...`) and cleans up nothing — the
  agent or a human decides. `nextAction` is one of `AWAIT_HUMAN_APPROVAL`,
  `CREATE_ROLLOUT`, `MONITOR_ROLLOUT`, `WAIT_PLAN_CHECK`, `FIX_SQL_AND_RETRY`
  and never names `ApproveIssue`: the agent does not approve on the user's
  behalf. There is no change-type flag: the server detects MIGRATE vs SDL
  from the sheet content, and upstream's `changeType` parameter is echoed
  but unused.

- **Field descriptions print with their continuation lines.** proto3 has no
  `required`, so the resource-name formats and constraints an agent must not
  guess (`Format: instances/{instance}/databases/{databaseName}`) live in
  those indented lines. Truncating them is how agents start guessing.

- **`skills/bytebase/SKILL.md` is embedded into the binary** via
  `include_str!` in `src/agent_skill.rs`, so the repo file stays the
  reviewable source of truth and an installed copy can never describe a
  different bbcli than the one that wrote it. Its frontmatter `name:` must
  stay `bytebase` — that is also the install directory name — and
  `description:` is what the model matches on when deciding to load the
  skill. A test asserts both; if you change the skill, keep them intact.

- **`bbcli skill` and `bbcli install-skill` are different things.** The first
  prints a vendored *task guide* (`query`, `database-change`,
  `grant-permission`) for the agent to read mid-task. The second installs the
  *agent skill* that teaches the agent bbcli exists. Don't merge them.

- **No dev-dependencies.** Tests build scratch paths from
  `std::env::temp_dir()` + `process::id()` + `line!()` and clean up with a
  `Drop` guard. Justify any new `[dependencies]` entry; prefer std.

- **`store` tests mutate process-global env** (`BBCLI_TOKEN_FILE`,
  `BBCLI_CONFIG`), so they serialize on a module-level `FILE_LOCK` and take
  that lock *before* touching the env var. Follow the pattern or they race.

## Working on this

- **Simplicity first.** Minimum code that solves the problem; no abstraction
  for a single caller, no config key without a concrete need. The design
  constraints above exist because things were left out on purpose.
- **Surgical changes.** Touch what the task requires. Don't reformat, rename,
  or "improve" adjacent code in the same change.
- **Tests encode intent.** A test should fail when the *reason* for the
  behavior is broken, not merely when a string changes. The tests in
  `src/agent_skill.rs` are the shape to copy: each name states a decision
  ("reinstalling an identical copy is a no-op"), so the test cannot survive
  that decision being reversed.
- **Comment the why.** The code says what it does; comments carry the reason
  it is that way — especially anything the next reader would otherwise
  "simplify" back into a bug.
- **Never log or print tokens**, and keep them out of error messages.
- **Agent-facing output is an interface.** Error text, the Connect code hints,
  and `SKILL.md` are read by models. Changing their wording is a behavior
  change; update the skill in the same commit as the command it describes.

## Before committing

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings    # must pass clean
cargo test
cargo build && python3 scripts/e2e_test.py   # full lifecycle against a mock server
```

The E2E script needs `os.mkfifo`, so it is Unix-only; CI runs it on Linux and
macOS and the unit tests everywhere.

## Versioning and releases

**Calendar versioning: `YYYY.M.D`.** bbcli wraps a moving upstream and exposes
no library API, so the question a version can usefully answer is "how stale is
this binary", not "is this source-compatible". `2026.9.6` answers it at a
glance; `0.4.2` does not. Cargo requires semver syntax, which **rejects leading
zeros** — `version = "2026.09.06"` fails the build with `invalid leading zero
in minor version number`, so write `2026.9.6`.

**Two axes of identity.** `bbcli --version` prints its own calver *and* the
Bytebase commit the vendored catalog came from:

```
bbcli 2026.9.6 (API catalog: bytebase c19b6bf4b46ab9f333bc2790bd8ed7992f9805ea)
```

Re-syncing `vendor/bytebase/` is therefore a release-worthy change even when no
bbcli code moved — the binary now describes a different API surface, and the
only way a user can tell is for the version to change.

**Cutting a release.** The git tag mirrors the Cargo version, prefixed with
`v`:

1. Make sure CI is green on `main`. `release.yml` builds and publishes; it does
   not re-run the test suite.
2. Bump `Cargo.toml` to today's `YYYY.M.D`, run a build so `Cargo.lock` picks
   it up, and commit both — `release: v2026.9.6`.
3. `git tag v2026.9.6 && git push origin v2026.9.6`.

The workflow's first job refuses to build unless the tag equals
`v$(cargo version)`. That gate exists because the failure it prevents is
silent: binaries reporting a version that exists nowhere on GitHub, which is
precisely what a version is for.

**Release archives carry the vendored notice.** The binary embeds
`vendor/bytebase/` (MIT Expat) via `include_str!`, so every archive ships
`vendor/bytebase/LICENSE` and `SOURCE.md` alongside the binary. Keep that step
in `release.yml` — dropping it makes the distribution non-compliant, not merely
untidy.

**Windows is not in the release matrix.** Four Unix triples are built
(`x86_64`/`aarch64` × linux-gnu/darwin). Nothing has yet proven the crate
builds for `x86_64-pc-windows-msvc`, and a target that fails to build blocks
the release job for every other platform. Add it once the CI test job has been
green on `windows-latest`.

## Conventions

- **Commit messages**: `<scope>: <imperative summary>` — e.g.
  `login: accept the redirect by paste when the browser is elsewhere`. Not
  conventional-commit type prefixes. The body explains *why* the change is
  right, not what the diff shows; it is the durable record of a trade-off.
  No `Co-Authored-By` trailer and no "Generated with Claude Code" footer, in
  commits or PR descriptions.
- **Docs that must move together**: a new or changed command touches
  `src/main.rs`, the README `Commands` table, and `skills/bytebase/SKILL.md`.
  A stale skill is worse than a missing one — the agent follows it either way.
